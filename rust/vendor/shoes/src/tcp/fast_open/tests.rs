use super::*;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket};

fn deferred_socket() -> TcpSocket {
    let socket = crate::socket_util::new_tcp_socket_with_options(
        None,
        false,
        &crate::dial_options::DialOptions {
            tcp_fast_open: true,
            ..Default::default()
        },
    )
    .unwrap();
    let enabled: libc::c_int = 1;
    // SAFETY: this test-only option produces the cached-cookie deferred path
    // deterministically without changing host sysctls or the shared TFO cache.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_FASTOPEN_NO_COOKIE,
            std::ptr::from_ref(&enabled).cast(),
            std::mem::size_of_val(&enabled) as libc::socklen_t,
        )
    };
    assert_eq!(result, 0, "{}", io::Error::last_os_error());
    socket
}

async fn deferred_stream(address: SocketAddr, deadline: Instant) -> FastOpenStream {
    let stream = deferred_socket().connect(address).await.unwrap();
    assert!(
        !is_established(&stream).unwrap(),
        "fixture must exercise deferred SYN"
    );
    FastOpenStream::new(stream, deadline).unwrap()
}

#[tokio::test]
async fn read_first_triggers_syn_and_receives_server_banner() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut stream = deferred_stream(
            listener.local_addr().unwrap(),
            Instant::now() + Duration::from_secs(2),
        )
        .await;
        assert!(
            tokio::time::timeout(Duration::from_millis(10), listener.accept())
                .await
                .is_err()
        );
        #[cfg(target_os = "linux")]
        assert!(
            stream.plain_tcp().is_none(),
            "raw relay must not bypass pending TFO"
        );
        let peer = async {
            let (mut peer, _) = listener.accept().await.unwrap();
            peer.write_all(b"server banner").await.unwrap();
        };
        let client = async {
            let mut banner = [0; 13];
            stream.read_exact(&mut banner).await.unwrap();
            assert_eq!(&banner, b"server banner");
            assert!(stream.deadline.is_none());
        };
        tokio::join!(peer, client);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn deferred_connection_keeps_deadline_and_closes_on_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut stream = deferred_stream(
        listener.local_addr().unwrap(),
        Instant::now() + Duration::from_millis(20),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(
        stream.write_all(b"too late").await.unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert!(
        stream.stream.is_none(),
        "expiry must release the socket immediately"
    );
    assert_eq!(
        stream.flush().await.unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(10), listener.accept())
            .await
            .is_err(),
        "expiry must not send late SYN/data"
    );
}

#[tokio::test]
async fn deferred_candidate_cannot_win_before_real_connection() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bad_address = closed.local_addr().unwrap();
        drop(closed);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let good_address = listener.local_addr().unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut stream = crate::tcp::socket_connector_impl::connect_tcp_candidates(
            vec![bad_address, good_address],
            |address| {
                let socket = deferred_socket();
                Ok(async move {
                    let stream = socket.connect(address).await?;
                    let mut stream = FastOpenStream::new(stream, deadline)?;
                    stream.establish_without_data().await?;
                    Ok(stream)
                })
            },
        )
        .await
        .unwrap();
        assert_eq!(stream.peer_addr(), Some(good_address));
        assert!(stream.deadline.is_none());
        let (mut peer, _) = listener.accept().await.unwrap();
        stream.write_u8(41).await.unwrap();
        assert_eq!(peer.read_u8().await.unwrap(), 41);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn established_connection_does_not_expire_while_caller_is_idle() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut stream = deferred_stream(
            listener.local_addr().unwrap(),
            Instant::now() + Duration::from_millis(100),
        )
        .await;
        stream.write_u8(51).await.unwrap();
        let (mut peer, _) = listener.accept().await.unwrap();
        assert_eq!(peer.read_u8().await.unwrap(), 51);
        tokio::time::sleep(Duration::from_millis(110)).await;
        stream.write_u8(52).await.unwrap();
        stream.flush().await.unwrap();
        assert_eq!(peer.read_u8().await.unwrap(), 52);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn first_tls_client_hello_drives_deferred_fast_open() {
    use crate::crypto::{CryptoTlsStream, TlsConnection, TlsReadMode};
    tokio::time::timeout(Duration::from_secs(5), async {
        let certificate =
            rcgen::generate_simple_self_signed(vec!["tfo.aerobox-test.example".into()]).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate.cert.der().clone()).unwrap();
        let server = rustls::ServerConfig::builder_with_provider(aerobox_crypto::shared_provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![certificate.cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(
                    certificate.signing_key.serialize_der(),
                )
                .into(),
            )
            .unwrap();
        let client = rustls::ClientConfig::builder_with_provider(aerobox_crypto::shared_provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let stream = deferred_stream(
            listener.local_addr().unwrap(),
            Instant::now() + Duration::from_secs(2),
        )
        .await;
        let peer = async {
            let (peer, _) = listener.accept().await.unwrap();
            let mut peer = CryptoTlsStream::handshake(
                peer,
                TlsConnection::new(rustls::ServerConnection::new(Arc::new(server)).unwrap()),
                TlsReadMode::Stream,
                &[],
            )
            .await
            .unwrap();
            assert_eq!(peer.read_u8().await.unwrap(), 91);
            peer.write_u8(92).await.unwrap();
            peer.flush().await.unwrap();
        };
        let client = async {
            let mut stream = CryptoTlsStream::handshake(
                stream,
                TlsConnection::new(
                    rustls::ClientConnection::new(
                        Arc::new(client),
                        "tfo.aerobox-test.example".try_into().unwrap(),
                    )
                    .unwrap(),
                ),
                TlsReadMode::Stream,
                &[],
            )
            .await
            .unwrap();
            stream.write_u8(91).await.unwrap();
            stream.flush().await.unwrap();
            assert_eq!(stream.read_u8().await.unwrap(), 92);
        };
        tokio::join!(peer, client);
    })
    .await
    .unwrap();
}
