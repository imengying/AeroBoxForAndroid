use super::*;
use std::future::poll_fn;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn hello() -> Vec<u8> {
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(aerobox_crypto::provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    let mut connection =
        rustls::ClientConnection::new(Arc::new(config), "fragment.example.com".try_into().unwrap())
            .unwrap();
    let mut bytes = Vec::new();
    connection.write_tls(&mut bytes).unwrap();
    assert_eq!(
        5 + usize::from(u16::from_be_bytes([bytes[3], bytes[4]])),
        bytes.len()
    );
    bytes
}

fn options(packet: bool, record: bool) -> TlsFragmentOptions {
    TlsFragmentOptions {
        fragment: packet,
        record_fragment: record,
        fragment_fallback_delay: packet.then_some(DialDuration(Duration::from_millis(35))),
    }
}

#[test]
fn fragment_duration_and_unknown_options_fail_before_io() {
    for value in [
        serde_json::json!({"fragment":true,"fragment_fallback_delay":"-1ms"}),
        serde_json::json!({"record_fragment":true,"fragment_fallback_delay":"invalid"}),
        serde_json::json!({"fragment":true,"fragment_fallback_delay":1}),
        serde_json::json!({"fragement":true}),
    ] {
        assert!(serde_json::from_value::<TlsFragmentOptions>(value).is_err());
    }
    let options: TlsFragmentOptions = serde_json::from_value(serde_json::json!({
        "record_fragment":true,"fragment_fallback_delay":"1ms"
    }))
    .unwrap();
    assert_eq!(
        options.validate().unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    for zero in ["0", "+0s", "0.0s", "0h0m0s"] {
        let options: TlsFragmentOptions = serde_json::from_value(serde_json::json!({
            "record_fragment":true,"fragment_fallback_delay":zero
        }))
        .unwrap();
        options.validate().unwrap();
        assert_eq!(options.fallback_delay(), Duration::from_millis(500));
    }
}

#[test]
fn real_client_hello_sni_is_bounded_and_record_split_preserves_transcript() {
    let bytes = hello();
    let name = server_name_range(&bytes).unwrap();
    assert_eq!(&bytes[name.clone()], b"fragment.example.com");
    for end in 0..bytes.len() {
        assert!(server_name_range(&bytes[..end]).is_none(), "prefix={end}");
    }
    for split in name.start + 1..name.end {
        let output = split_record(&bytes, split);
        assert_eq!(output.len(), bytes.len() + 5);
        assert_eq!(&output[..3], &bytes[..3]);
        assert_eq!(
            usize::from(u16::from_be_bytes([output[3], output[4]])),
            split - 5
        );
        assert_eq!(&output[split..split + 3], &bytes[..3]);
        let mut transcript = output[5..split].to_vec();
        transcript.extend_from_slice(&output[split + 5..]);
        assert_eq!(transcript, bytes[5..]);
    }
    // Corrupt each 16-bit length around the SNI extension, without indexing
    // or allocating from unvalidated lengths.
    for index in name.start - 9..name.start {
        let mut malformed = bytes.clone();
        malformed[index] = 255;
        let _ = server_name_range(&malformed);
    }
}

#[derive(Default)]
struct Output {
    bytes: Vec<u8>,
    writes: Vec<(Instant, usize)>,
}

struct Capture {
    state: Arc<Mutex<Output>>,
    quota: usize,
    stall: bool,
}

impl AsyncRead for Capture {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}
impl AsyncWrite for Capture {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.stall {
            self.stall = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        self.stall = true;
        let count = self.quota.min(bytes.len());
        let mut state = self.state.lock().unwrap();
        state.bytes.extend_from_slice(&bytes[..count]);
        state.writes.push((Instant::now(), count));
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
impl AsyncPing for Capture {
    fn supports_ping(&self) -> bool {
        false
    }
    fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}
impl AsyncStream for Capture {}

#[tokio::test]
async fn cancelled_flush_preserves_each_byte_and_fallback_delay() {
    for (packet, record) in [(false, true), (true, false), (true, true)] {
        let state = Arc::new(Mutex::new(Output::default()));
        let capture = Capture {
            state: state.clone(),
            quota: 7,
            stall: false,
        };
        let mut stream = FragmentStream::new(Box::new(capture), options(packet, record));
        let hello = hello();
        // A caller may split even the TLS record header across writes.
        for fragment in hello.chunks(3) {
            stream.write_all(fragment).await.unwrap();
        }
        {
            let flush = stream.flush();
            tokio::pin!(flush);
            assert!(futures::poll!(flush.as_mut()).is_pending());
        }
        tokio::time::timeout(Duration::from_secs(3), stream.flush())
            .await
            .unwrap()
            .unwrap();
        stream.write_all(b"tail").await.unwrap();
        stream.flush().await.unwrap();
        let output = state.lock().unwrap();
        assert_eq!(&output.bytes[output.bytes.len() - 4..], b"tail");
        if record {
            let split = 5 + usize::from(u16::from_be_bytes([output.bytes[3], output.bytes[4]]));
            let mut payload = output.bytes[5..split].to_vec();
            payload.extend_from_slice(&output.bytes[split + 5..output.bytes.len() - 4]);
            assert_eq!(payload, hello[5..]);
        } else {
            assert_eq!(&output.bytes[..output.bytes.len() - 4], hello);
        }
        if packet {
            assert!(
                output
                    .writes
                    .windows(2)
                    .any(|pair| pair[1].0 - pair[0].0 >= Duration::from_millis(35))
            );
        }
    }
}

#[tokio::test]
async fn cancellation_during_wait_does_not_restart_delay_or_resend_prefix() {
    let state = Arc::new(Mutex::new(Output::default()));
    let capture = Capture {
        state: state.clone(),
        quota: usize::MAX,
        stall: false,
    };
    let mut stream = FragmentStream::new(Box::new(capture), options(true, true));
    let hello = hello();
    stream.write_all(&hello).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(5), stream.flush())
            .await
            .is_err()
    );
    let prefix_length = state.lock().unwrap().bytes.len();
    assert!(prefix_length > 5 && prefix_length < hello.len());
    stream.flush().await.unwrap();
    let output = state.lock().unwrap();
    assert_eq!(output.writes.len(), 2);
    assert_eq!(output.bytes.len(), hello.len() + 5);
    assert_eq!(output.writes[0].1, prefix_length);
}

#[tokio::test]
async fn flushing_truncated_or_non_tls_input_preserves_bytes_without_waiting() {
    for input in [hello()[..4].to_vec(), b"a plaintext protocol".to_vec()] {
        let (wire, mut peer) = tokio::io::duplex(4096);
        let mut stream = FragmentStream::new(Box::new(wire), options(true, true));
        stream.write_all(&input).await.unwrap();
        tokio::time::timeout(Duration::from_millis(100), stream.flush())
            .await
            .unwrap()
            .unwrap();
        let mut received = vec![0; input.len()];
        peer.read_exact(&mut received).await.unwrap();
        assert_eq!(received, input);
    }
}

struct Broken;
impl AsyncRead for Broken {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}
impl AsyncWrite for Broken {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
impl AsyncPing for Broken {
    fn supports_ping(&self) -> bool {
        false
    }
    fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}
impl AsyncStream for Broken {}

#[tokio::test]
async fn failed_first_flight_never_retries_or_exposes_raw_socket() {
    let mut stream = FragmentStream::new(Box::new(Broken), options(true, true));
    stream.write_all(&hello()).await.unwrap();
    for _ in 0..2 {
        assert_eq!(
            stream.flush().await.unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        assert_eq!(
            stream.write(b"retry").await.unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        assert_eq!(
            poll_fn(|cx| Pin::new(&mut stream).poll_read(cx, &mut ReadBuf::new(&mut [0; 1])))
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::BrokenPipe
        );
    }
}

async fn read_hello(peer: &mut tokio::net::TcpStream) -> (Vec<u8>, Vec<u8>, usize) {
    let mut records = Vec::new();
    let mut body = Vec::new();
    let mut count = 0;
    loop {
        let mut header = [0; 5];
        peer.read_exact(&mut header).await.unwrap();
        assert_eq!(&header[..2], &[22, 3]);
        let size = usize::from(u16::from_be_bytes([header[3], header[4]]));
        assert!(size > 0);
        let mut part = vec![0; size];
        peer.read_exact(&mut part).await.unwrap();
        records.extend_from_slice(&header);
        records.extend_from_slice(&part);
        body.extend_from_slice(&part);
        count += 1;
        if body.len() >= 4 {
            assert_eq!(body[0], 1);
            let length =
                usize::from(body[1]) << 16 | usize::from(body[2]) << 8 | usize::from(body[3]);
            if body.len() >= length + 4 {
                assert_eq!(body.len(), length + 4);
                break;
            }
        }
    }
    let mut hello = records[..3].to_vec();
    hello.extend_from_slice(&(body.len() as u16).to_be_bytes());
    hello.extend_from_slice(&body);
    assert_eq!(
        &hello[server_name_range(&hello).unwrap()],
        b"fragment.example.com"
    );
    (records, hello, count)
}

async fn echo(stream: crate::crypto::CryptoTlsStream<Box<dyn AsyncStream>>, vision: bool) {
    use crate::address::NetLocation;
    use crate::tcp::tcp_handler::TcpServerSetupResult;
    let mut stream: Box<dyn AsyncStream> = if vision {
        let resolver: Arc<dyn crate::resolver::Resolver> =
            Arc::new(crate::resolver::NativeResolver::new());
        let result =
            crate::vless::vless_server_handler::setup_custom_tls_vision_vless_server_stream(
                stream,
                &[1, 1, 1, 1, 1, 1, 0x41, 1, 0x81, 1, 1, 1, 1, 1, 1, 1],
                true,
                Arc::new(crate::client_proxy_selector::ClientProxySelector::new(
                    vec![],
                )),
                &resolver,
                None,
            )
            .await
            .unwrap();
        let TcpServerSetupResult::TcpForward {
            remote_location,
            stream,
            ..
        } = result
        else {
            panic!("expected Vision TCP stream");
        };
        assert_eq!(
            remote_location,
            NetLocation::from_str("192.0.2.1:443", None).unwrap()
        );
        stream
    } else {
        Box::new(stream)
    };
    let mut payload = [0; 4097];
    stream.read_exact(&mut payload).await.unwrap();
    assert_eq!(payload, [42; 4097]);
    stream.write_all(&payload).await.unwrap();
    stream.flush().await.unwrap();
}

async fn handshake_matrix(reality: bool) {
    use crate::address::NetLocation;
    use crate::crypto::{CryptoTlsStream, TlsConnection, TlsReadMode};
    use base64::Engine;
    use serde_json::json;

    let cert = rcgen::generate_simple_self_signed(vec!["fragment.example.com".into()]).unwrap();
    let server_config = Arc::new(
        rustls::ServerConfig::builder_with_provider(aerobox_crypto::shared_provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())
                    .into(),
            )
            .unwrap(),
    );
    let private = aerobox_primitives::agreement::PrivateKey::from_private_key(
        &aerobox_primitives::agreement::X25519,
        &[42; 32],
    )
    .unwrap();
    let public = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(private.compute_public_key().unwrap());

    for vision in [false, true] {
        for (packet, record) in [(true, false), (false, true), (true, true)] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = listener.local_addr().unwrap();
            let config = server_config.clone();
            let server_task = tokio::spawn(async move {
                let (mut peer, _) = listener.accept().await.unwrap();
                let (wire, hello, records) = read_hello(&mut peer).await;
                assert_eq!(records, if record { 2 } else { 1 });
                let mode = if vision {
                    TlsReadMode::PreserveRecords
                } else {
                    TlsReadMode::Stream
                };
                let (connection, preread) = if reality {
                    let server = crate::reality::RealityServerConfig {
                        mldsa65_key: None,
                        private_key: [42; 32],
                        short_ids: vec![[1; 8]],
                        dest: NetLocation::from_str("fragment.example.com:443", None).unwrap(),
                        max_time_diff: None,
                        min_client_version: None,
                        max_client_version: None,
                        cipher_suites: vec![crate::reality::CipherSuite::AES_128_GCM_SHA256],
                    };
                    let target = crate::reality::default_target_records(&hello[44..76]);
                    (
                        server
                            .authenticate_client_hello(&hello)
                            .unwrap()
                            .into_connection(&target)
                            .unwrap(),
                        vec![],
                    )
                } else {
                    (
                        TlsConnection::new(rustls::ServerConnection::new(config).unwrap()),
                        wire,
                    )
                };
                let peer: Box<dyn AsyncStream> = Box::new(peer);
                let stream = CryptoTlsStream::handshake(peer, connection, mode, &preread)
                    .await
                    .unwrap();
                echo(stream, vision).await;
            });
            let mut native = json!({
                "type":if reality { "reality" } else { "tls" },
                "sni_hostname":"fragment.example.com",
                "vision":vision,
                "fragmentation":options(packet,record),
                "protocol":if vision {
                    json!({"type":"vless","user_id":"01010101-0101-4101-8101-010101010101"})
                } else { json!({"type":"noop"}) }
            });
            if reality {
                native["public_key"] = public.clone().into();
                native["short_id"] = "0101010101010101".into();
            } else {
                native["verify"] = true.into();
                native["options"] = json!({"root_certificates":[cert.cert.pem()]});
            }
            let handler = crate::tcp::tcp_client_handler_factory::create_tcp_client_handler(
                crate::config::test_support::from_json(native).unwrap(),
                &NetLocation::from_str("fragment.example.com:443", None).unwrap(),
                Arc::new(crate::resolver::NativeResolver::new()),
            )
            .unwrap();
            let wire = tokio::net::TcpStream::connect(endpoint).await.unwrap();
            let mut client = handler
                .setup_client_tcp_stream(
                    Box::new(wire),
                    NetLocation::from_str("192.0.2.1:443", None).unwrap().into(),
                )
                .await
                .unwrap()
                .client_stream;
            client.write_all(&[42; 4097]).await.unwrap();
            client.flush().await.unwrap();
            let mut received = [0; 4097];
            client.read_exact(&mut received).await.unwrap();
            assert_eq!(received, [42; 4097]);
            server_task.await.unwrap();
        }
    }
}

#[tokio::test]
async fn ordinary_tls_and_vision_handshakes_preserve_authentication_and_payload() {
    tokio::time::timeout(Duration::from_secs(10), handshake_matrix(false))
        .await
        .unwrap();
}

#[tokio::test]
async fn reality_and_vision_authenticate_the_original_client_hello_transcript() {
    tokio::time::timeout(Duration::from_secs(10), handshake_matrix(true))
        .await
        .unwrap();
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
async fn packet_fragment_restores_caller_nodelay_setting() {
    tokio::time::timeout(Duration::from_secs(3), async {
        for original in [false, true] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let wire = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let (mut peer, _) = listener.accept().await.unwrap();
            wire.set_nodelay(original).unwrap();
            let mut stream = FragmentStream::new(Box::new(wire), options(true, true));
            stream.write_all(&hello()).await.unwrap();
            assert!(stream.inner.plain_tcp().unwrap().nodelay().unwrap());
            assert!(stream.plain_tcp().is_none());
            let server = tokio::spawn(async move {
                let (_, _, count) = read_hello(&mut peer).await;
                assert_eq!(count, 2);
            });
            stream.flush().await.unwrap();
            assert_eq!(stream.plain_tcp().unwrap().nodelay().unwrap(), original);
            server.await.unwrap();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires AEROBOX_TLS_FRAGMENT_PEER built from tests/fixtures/tls-fragment-peer"]
async fn tls12_and_tls13_fragments_interoperate_with_independent_go_server() {
    use crate::address::NetLocation;
    use std::process::Stdio;
    use tokio::io::{AsyncBufReadExt, BufReader};

    let mut child = tokio::process::Command::new(
        std::env::var_os("AEROBOX_TLS_FRAGMENT_PEER").expect("set AEROBOX_TLS_FRAGMENT_PEER"),
    )
    .stdout(Stdio::piped())
    .stderr(Stdio::inherit())
    .kill_on_drop(true)
    .spawn()
    .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let info: serde_json::Value = serde_json::from_str(
        &tokio::time::timeout(Duration::from_secs(5), lines.next_line())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        for version in ["1.2", "1.3"] {
            for (packet, record) in [(true, false), (false, true), (true, true)] {
                let handler = crate::tcp::tcp_client_handler_factory::create_tcp_client_handler(
                    crate::config::test_support::from_json(serde_json::json!({
                        "type":"tls","sni_hostname":"fragment.example.com","verify":true,
                        "fragmentation":options(packet,record),"protocol":{"type":"noop"},
                        "options":{"root_certificates":[info["certificate"]],
                            "min_version":version,"max_version":version}
                    }))
                    .unwrap(),
                    &NetLocation::from_str("fragment.example.com:443", None).unwrap(),
                    Arc::new(crate::resolver::NativeResolver::new()),
                )
                .unwrap();
                let wire = tokio::net::TcpStream::connect((
                    "127.0.0.1",
                    info["port"].as_u64().unwrap() as u16,
                ))
                .await
                .unwrap();
                let mut stream = handler
                    .setup_client_tcp_stream(
                        Box::new(wire),
                        NetLocation::from_str("192.0.2.1:443", None).unwrap().into(),
                    )
                    .await
                    .unwrap()
                    .client_stream;
                let expected = vec![42; 65_537];
                stream.write_all(&expected).await.unwrap();
                stream.flush().await.unwrap();
                let mut received = vec![0; expected.len()];
                stream.read_exact(&mut received).await.unwrap();
                assert_eq!(
                    received, expected,
                    "TLS {version} packet={packet} record={record}"
                );
                stream.shutdown().await.unwrap();
            }
        }
    })
    .await
    .unwrap();
    child.kill().await.unwrap();
    child.wait().await.unwrap();
}
