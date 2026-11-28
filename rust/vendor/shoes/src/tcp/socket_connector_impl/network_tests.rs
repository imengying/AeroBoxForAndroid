use super::*;
use crate::async_stream::{AsyncReadMessage, AsyncWriteMessage};
use crate::network_dial::{NetworkPolicy, tests::make_host};
use crate::resolver::NativeResolver;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn fallback_config() -> ResolvedClientConfig {
    crate::config::test_support::from_yaml("protocol: {type: direct}\ndial_options: {network_strategy: fallback, fallback_network_type: [cellular], connect_timeout: 2s}").unwrap()
}

#[tokio::test]
async fn selected_tcp_and_udp_carriers_exchange_data_after_binding_failure() {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let host = make_host(vec![1]);
        let config = fallback_config();
        let mut connector = SocketConnectorImpl::from_config(&config, None).unwrap();
        connector.network = NetworkPolicy::with_platform(&config.dial_options, host.clone());
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = ResolvedLocation::new(
            NetLocation::from_str(&tcp.local_addr().unwrap().to_string(), None).unwrap(),
        );
        let mut client = connector.connect(&resolver, &target).await.unwrap();
        let (mut server, _) = tcp.accept().await.unwrap();
        client.write_all(b"one application write").await.unwrap();
        let mut bytes = [0; 21];
        server.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"one application write");
        assert_eq!(*host.bound.lock(), [1, 2]);
        drop((client, server));

        for proxy in [false, true] {
            host.bound.lock().clear();
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let target = ResolvedLocation::new(
                NetLocation::from_str(&udp.local_addr().unwrap().to_string(), None).unwrap(),
            );
            let mut client = if proxy {
                connector
                    .connect_proxy_datagram(&resolver, target)
                    .await
                    .unwrap()
            } else {
                connector
                    .connect_udp_bidirectional(&resolver, target)
                    .await
                    .unwrap()
            };
            futures::future::poll_fn(|cx| {
                Pin::new(&mut client).poll_write_message(cx, b"single datagram")
            })
            .await
            .unwrap();
            let mut bytes = [0; 64];
            let (len, address) = udp.recv_from(&mut bytes).await.unwrap();
            assert_eq!(&bytes[..len], b"single datagram");
            udp.send_to(&bytes[..len], address).await.unwrap();
            let mut read = ReadBuf::new(&mut bytes);
            futures::future::poll_fn(|cx| Pin::new(&mut client).poll_read_message(cx, &mut read))
                .await
                .unwrap();
            assert_eq!(read.filled(), b"single datagram");
            assert_eq!(*host.bound.lock(), [1, 2]);
            assert!(
                tokio::time::timeout(
                    std::time::Duration::from_millis(15),
                    udp.recv_from(&mut bytes)
                )
                .await
                .is_err()
            );
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn denied_selected_networks_cannot_reach_a_tcp_or_udp_peer() {
    let host = make_host(vec![1, 2, 3]);
    let config = fallback_config();
    let mut connector = SocketConnectorImpl::from_config(&config, None).unwrap();
    connector.network = NetworkPolicy::with_platform(&config.dial_options, host.clone());
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = ResolvedLocation::new(
        NetLocation::from_str(&tcp.local_addr().unwrap().to_string(), None).unwrap(),
    );
    assert_eq!(
        connector
            .connect(&resolver, &target)
            .await
            .err()
            .unwrap()
            .kind(),
        std::io::ErrorKind::PermissionDenied
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), tcp.accept())
            .await
            .is_err()
    );
    assert_eq!(
        connector
            .connect_proxy_datagram(&resolver, target)
            .await
            .err()
            .unwrap()
            .kind(),
        std::io::ErrorKind::PermissionDenied
    );
}

#[tokio::test]
async fn quic_network_endpoints_reuse_sockets_and_retire_on_generation_change() {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(aerobox_crypto::provider()))
            .with_safe_default_protocol_versions().unwrap().with_no_client_auth()
            .with_single_cert(vec![certificate.cert.der().clone()], rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.signing_key.serialize_der()).into()).unwrap();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let server = quinn::Endpoint::server(quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap()
        )), "127.0.0.1:0".parse().unwrap()).unwrap();
        let config: ResolvedClientConfig = crate::config::test_support::from_json(serde_json::json!({
            "protocol":{"type":"hysteria2","password":"test"},
            "address":server.local_addr().unwrap().to_string(), "transport":"quic",
            "dial_options":{"network_strategy":"fallback","fallback_network_type":["cellular"]},
            "quic_settings":{"sni_hostname":"localhost","alpn_protocols":["h3"],"options":{"root_certificates":[certificate.cert.pem()]}}
        })).unwrap();
        let host = make_host(vec![1]);
        let mut connector = SocketConnectorImpl::from_config(&config, Some(&config.address)).unwrap();
        connector.network = NetworkPolicy::with_platform(&config.dial_options, host.clone());
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let target = ResolvedLocation::new(config.address.clone());
        let mut clients = Vec::new();
        let mut peers = Vec::new();
        let mut port = None;
        for round in 0..3 {
            if round == 2 { host.snapshot.lock().generation += 1; }
            let (client, peer) = tokio::join!(connector.connect_quic(&resolver, &target), async { server.accept().await.unwrap().await.unwrap() });
            let client = client.unwrap();
            if round == 1 { assert_eq!(port, Some(peer.remote_address().port())); }
            else { port = Some(peer.remote_address().port()); }
            let (written, received) = tokio::join!(async {
                let (mut send, recv) = client.connection.open_bi().await.unwrap();
                send.write_all(b"QUIC uses one selected network").await.unwrap(); send.finish().unwrap();
                (send, recv)
            }, async {
                let (send, mut recv) = peer.accept_bi().await.unwrap();
                let bytes = recv.read_to_end(128).await.unwrap();
                (send, bytes)
            });
            assert_eq!(received.1, b"QUIC uses one selected network");
            drop((written, received));
            clients.push(client); peers.push(peer);
        }
        // Binding 1 fails on every selection. Binding 2 creates only one socket
        // per generation, and cached sockets retain their source port.
        assert_eq!(*host.bound.lock(), [1, 2, 1, 1, 2]);
        assert!(clients[0].connection.close_reason().is_some());
        assert!(clients[1].connection.close_reason().is_some());
        assert!(clients[2].connection.close_reason().is_none());
        for client in clients { client.connection.close(0_u32.into(), b"done"); }
        server.close(0_u32.into(), b"done");
    }).await.unwrap();
}

#[tokio::test]
async fn delayed_old_host_lookup_cannot_close_or_replace_new_quic_endpoints() {
    let options = fallback_config().dial_options;
    let old_policy = NetworkPolicy::with_platform(&options, make_host(vec![]));
    let old = old_policy
        .udp(|binding| Ok(binding.unwrap().clone()))
        .unwrap();
    let new_policy = NetworkPolicy::with_platform(&options, make_host(vec![]));
    let current = new_policy
        .udp(|binding| Ok(binding.unwrap().clone()))
        .unwrap();
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.set_nonblocking(true).unwrap();
    let endpoint = Arc::new(QuicEndpoint::new(None, socket, 1).unwrap());
    let mut cache = NetworkEndpointCache::default();
    assert!(cache.lookup(current.key(), false).unwrap().is_none());
    cache.entries.push((current.key(), false, endpoint.clone()));
    assert_eq!(
        cache.lookup(old.key(), false).unwrap_err().kind(),
        std::io::ErrorKind::NotConnected
    );
    assert_eq!(cache.snapshot, Some(current.key()));
    assert!(Arc::ptr_eq(
        &cache.lookup(current.key(), false).unwrap().unwrap(),
        &endpoint
    ));
}
