use super::*;
use crate::{
    address::ResolvedLocation,
    config::ResolvedClientConfig,
    network_dial::{NetworkPolicy, tests::make_host},
    resolver::{NativeResolver, Resolver},
    tcp::{socket_connector::SocketConnector, socket_connector_impl::SocketConnectorImpl},
};
use serde_json::json;
use std::{collections::HashSet, time::Duration};

fn fixture(network: bool) -> (quinn::Endpoint, ResolvedClientConfig) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(aerobox_crypto::provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )
        .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let server = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap(),
        )),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let mut value = json!({
        "address":server.local_addr().unwrap().to_string(), "transport":"quic",
        "quic_settings":{"sni_hostname":"localhost", "options":{"root_certificates":[cert.cert.pem()]}},
        "protocol":{"type":"naiveproxy", "username":"user", "password":"pass",
            "settings":{"quic":true,"stream_receive_window":65536,"session_receive_window":262144}}
    });
    if network {
        value["dial_options"] =
            json!({"network_strategy":"fallback", "fallback_network_type":["cellular"]});
    }
    (
        server,
        crate::config::test_support::from_json(value).unwrap(),
    )
}

async fn echo(client: &quinn::Connection, peer: &quinn::Connection, data: &[u8]) {
    let (client, server) = tokio::join!(
        async {
            let (mut send, mut recv) = client.open_bi().await.unwrap();
            send.write_all(data).await.unwrap();
            send.finish().unwrap();
            recv.read_to_end(data.len()).await.unwrap()
        },
        async {
            let (mut send, mut recv) = peer.accept_bi().await.unwrap();
            let bytes = recv.read_to_end(data.len()).await.unwrap();
            send.write_all(&bytes).await.unwrap();
            send.finish().unwrap();
            bytes
        }
    );
    assert_eq!(client, data);
    assert_eq!(server, data);
}

#[tokio::test]
async fn naive_zero_cid_connections_have_separate_sockets_and_survive_replacement() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for network in [false, true] {
            let (server, config) = fixture(network);
            let host = make_host(vec![1]);
            let mut connector =
                SocketConnectorImpl::from_config(&config, Some(&config.address)).unwrap();
            if network {
                connector.network =
                    NetworkPolicy::with_platform(&config.dial_options, host.clone());
            }
            let target = ResolvedLocation::new(config.address);
            let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
            let mut carriers = Vec::new();
            let mut peers = Vec::new();
            let mut ports = HashSet::new();
            let mut ongoing = None;
            for round in 0..3 {
                let (carrier, peer) =
                    tokio::join!(connector.connect_quic(&resolver, &target), async {
                        server.accept().await.unwrap().await.unwrap()
                    });
                let carrier = carrier.unwrap();
                assert!(ports.insert(peer.remote_address().port()));
                carriers.push(carrier);
                peers.push(peer);
                if round == 0 {
                    let (mut send, recv) = carriers[0].connection.open_bi().await.unwrap();
                    send.write_all(b"before replacement").await.unwrap();
                    let (peer_send, mut peer_recv) = peers[0].accept_bi().await.unwrap();
                    let mut prefix = [0; 18];
                    peer_recv.read_exact(&mut prefix).await.unwrap();
                    assert_eq!(&prefix, b"before replacement");
                    ongoing = Some((send, recv, peer_send, peer_recv));
                }
                // A later connection must not replace the old endpoint's
                // zero-CID routing entry, including while the old stream lives.
                for (carrier, peer) in carriers.iter().zip(&peers) {
                    echo(
                        &carrier.connection,
                        peer,
                        b"old and new Naive connections stay usable",
                    )
                    .await;
                    assert!(carrier.connection.close_reason().is_none());
                }
            }
            let (mut send, mut recv, mut peer_send, mut peer_recv) = ongoing.unwrap();
            send.write_all(b"after replacement").await.unwrap();
            send.finish().unwrap();
            let suffix = peer_recv.read_to_end(32).await.unwrap();
            assert_eq!(suffix, b"after replacement");
            peer_send.write_all(&suffix).await.unwrap();
            peer_send.finish().unwrap();
            assert_eq!(recv.read_to_end(32).await.unwrap(), suffix);
            if network {
                assert_eq!(*host.bound.lock(), [1, 2, 1, 2, 1, 2]);
                host.snapshot.lock().generation += 1;
                let (current, peer) =
                    tokio::join!(connector.connect_quic(&resolver, &target), async {
                        server.accept().await.unwrap().await.unwrap()
                    });
                let current = current.unwrap();
                assert!(
                    carriers
                        .iter()
                        .all(|old| old.connection.close_reason().is_some())
                );
                echo(&current.connection, &peer, b"new physical network").await;
                current.connection.close(0_u32.into(), b"test complete");
            }
            for carrier in carriers {
                carrier.connection.close(0_u32.into(), b"test complete");
            }
            server.close(0_u32.into(), b"test complete");
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn naive_network_registry_rejects_stale_bindings_and_does_not_retain_endpoints() {
    let (_, config) = fixture(true);
    let old_policy = NetworkPolicy::with_platform(&config.dial_options, make_host(vec![]));
    let old = old_policy
        .udp(|binding| Ok(binding.unwrap().clone()))
        .unwrap();
    let current_policy = NetworkPolicy::with_platform(&config.dial_options, make_host(vec![]));
    let current = current_policy
        .udp(|binding| Ok(binding.unwrap().clone()))
        .unwrap();
    let connector = SocketConnectorImpl::from_config(&config, Some(&config.address)).unwrap();
    let super::super::TransportConfig::Quic {
        naive: Some(endpoints),
        ..
    } = &connector.transport
    else {
        panic!("missing Naive endpoint configuration");
    };
    let address = "127.0.0.1:443".parse().unwrap();
    let endpoint = endpoints.open(address, None, Some(&current)).unwrap();
    assert_eq!(endpoints.network.lock().active.len(), 1);
    assert_eq!(
        endpoints
            .open(address, None, Some(&old))
            .unwrap_err()
            .kind(),
        io::ErrorKind::NotConnected
    );
    assert_eq!(endpoints.network.lock().snapshot, Some(current.key()));
    let weak = Arc::downgrade(&endpoint);
    drop(endpoint);
    assert!(weak.upgrade().is_none());
    endpoints.network.lock().select(current.key()).unwrap();
    assert!(endpoints.network.lock().active.is_empty());
}
