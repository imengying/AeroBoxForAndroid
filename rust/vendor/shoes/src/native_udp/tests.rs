use super::*;
use crate::{
    option_util::OneOrSome,
    resolver::{NativeResolver, Resolver},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn send(stream: &mut dyn AsyncMessageStream, payload: &[u8]) -> io::Result<()> {
    futures::future::poll_fn(|cx| Pin::new(&mut *stream).poll_write_message(cx, payload)).await
}
async fn receive(stream: &mut dyn AsyncMessageStream) -> io::Result<Vec<u8>> {
    let mut bytes = vec![0; 65_535];
    let mut output = ReadBuf::new(&mut bytes);
    futures::future::poll_fn(|cx| Pin::new(&mut *stream).poll_read_message(cx, &mut output))
        .await?;
    Ok(output.filled().to_vec())
}
fn chain(configs: Vec<serde_json::Value>) -> crate::client_proxy_chain::ClientProxyChain {
    let hops = configs
        .into_iter()
        .map(|value| {
            crate::config::resolved::ResolvedClientHop::Single(
                crate::config::test_support::from_json(value).unwrap(),
            )
        })
        .collect();
    crate::tcp::chain_builder::try_build_client_proxy_chain(
        OneOrSome::Some(hops),
        Arc::new(NativeResolver::new()),
    )
    .unwrap()
}
fn resolver() -> Arc<dyn Resolver> {
    Arc::new(NativeResolver::new())
}

#[tokio::test]
async fn socks_associate_authentication_filters_packets_and_tracks_control_lifetime() {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let (finish, done) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut control, _) = listener.accept().await.unwrap();
            let mut hello = [0; 3]; control.read_exact(&mut hello).await.unwrap(); assert_eq!(hello, [5,1,2]);
            control.write_all(&[5,2]).await.unwrap();
            let mut auth = [0; 5]; control.read_exact(&mut auth).await.unwrap(); assert_eq!(auth, [1,1,b'u',1,b'p']);
            control.write_all(&[1,0]).await.unwrap();
            let mut request = [0; 3]; control.read_exact(&mut request).await.unwrap(); assert_eq!(request, [5,3,0]);
            crate::socks_handler::read_location_direct(&mut control).await.unwrap();
            let mut reply = vec![5,0,0,1,0,0,0,0]; reply.extend_from_slice(&relay.local_addr().unwrap().port().to_be_bytes());
            control.write_all(&reply).await.unwrap();
            let mut packet = [0; 65_535];
            for expected in [Vec::new(), vec![42; 4096]] {
                let (length, peer) = relay.recv_from(&mut packet).await.unwrap();
                let (target, payload) = crate::socks5_udp_relay::parse_socks5_udp_packet(&packet[..length]).unwrap();
                assert_eq!(target, NetLocation::from_str("1.2.3.4:443", None).unwrap()); assert_eq!(payload, expected);
                // A packet from an unrelated source must never reach the decoder.
                let intruder = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let mut fake = Vec::new(); crate::socks5_udp_relay::encode_socks5_udp_packet(&target, b"injected", &mut fake);
                intruder.send_to(&fake, peer).await.unwrap();
                let mut fragmented = packet[..length].to_vec(); fragmented[2] = 1;
                relay.send_to(&fragmented, peer).await.unwrap();
                relay.send_to(&packet[..length], peer).await.unwrap();
            }
            done.await.unwrap();
        });
        let chain = chain(vec![serde_json::json!({"address":endpoint.to_string(),"protocol":{"type":"socks","username":"u","password":"p"}})]);
        assert!(chain.supports_udp());
        let mut udp = chain.connect_udp_bidirectional(&resolver(), NetLocation::from_str("1.2.3.4:443", None).unwrap().into()).await.unwrap();
        for payload in [Vec::new(), vec![42; 4096]] { send(&mut *udp, &payload).await.unwrap(); assert_eq!(receive(&mut *udp).await.unwrap(), payload); }
        finish.send(()).unwrap(); server.await.unwrap();
        assert!(receive(&mut *udp).await.is_err());
    }).await.unwrap();
}

#[tokio::test]
async fn two_socks_hops_relay_native_udp_through_the_selected_prefix() {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let vacant = || { let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap(); listener.local_addr().unwrap() };
        let first = vacant(); let second = vacant();
        let core = crate::embedding::EmbeddedCore::start_json(&serde_json::json!([
            {"address":first.to_string(),"protocol":{"type":"socks"}},
            {"address":second.to_string(),"protocol":{"type":"socks"}}
        ]).to_string(), None).await.unwrap();
        let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = echo.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut bytes = vec![0; 65_535];
            for _ in 0..3 { let (length, source) = echo.recv_from(&mut bytes).await.unwrap(); echo.send_to(&bytes[..length], source).await.unwrap(); }
        });
        let chain = chain([first,second].iter().map(|address| serde_json::json!({"address":address.to_string(),"protocol":{"type":"socks"}})).collect());
        let mut udp = chain.connect_udp_bidirectional(&resolver(), NetLocation::from_ip_addr(target.ip(), target.port()).into()).await.unwrap();
        for payload in [vec![1], Vec::new(), vec![2; 4096]] { send(&mut *udp, &payload).await.unwrap(); assert_eq!(receive(&mut *udp).await.unwrap(), payload); }
        server.await.unwrap();
        drop(udp);
        core.shutdown().await.unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn tcp_only_prefix_cannot_leak_native_udp_to_the_underlay() {
    let chain = chain(vec![
        serde_json::json!({"address":"127.0.0.1:9","protocol":{"type":"http"}}),
        serde_json::json!({"address":"127.0.0.1:10","protocol":{"type":"shadowsocks","cipher":"aes-128-gcm","password":"password"}}),
    ]);
    let result = chain
        .connect_udp_bidirectional(
            &resolver(),
            NetLocation::from_str("1.2.3.4:443", None).unwrap().into(),
        )
        .await;
    assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::Unsupported));
}

#[test]
fn explicit_stream_wrappers_keep_their_transport_semantics() {
    for (protocol, native) in [
        (serde_json::json!({"type":"socks"}), true),
        (
            serde_json::json!({"type":"shadowsocks","cipher":"aes-128-gcm","password":"password"}),
            true,
        ),
        (
            serde_json::json!({"type":"shadowsocks","cipher":"aes-128-gcm","password":"password","udp_enabled":false}),
            false,
        ),
        (
            serde_json::json!({"type":"tls","verify":false,"protocol":{"type":"socks"}}),
            false,
        ),
    ] {
        let config = crate::config::test_support::from_json(
            serde_json::json!({"address":"127.0.0.1:443","protocol":protocol}),
        )
        .unwrap();
        assert_eq!(Client::from_config(&config).unwrap().is_some(), native);
    }
}
