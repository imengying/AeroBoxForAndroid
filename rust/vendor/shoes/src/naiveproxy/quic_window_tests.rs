use std::{process::Stdio, sync::Arc, time::Duration};

use serde_json::json;
use tokio::io::{AsyncBufReadExt, BufReader};

use crate::{
    address::NetLocation,
    config::ResolvedClientConfig,
    resolver::{NativeResolver, Resolver},
    tcp::{socket_connector::SocketConnector, socket_connector_impl::SocketConnectorImpl},
};

#[tokio::test]
#[ignore = "requires AEROBOX_NAIVE_PEER built from tests/fixtures/naive-peer"]
async fn naive_http3_advertises_independent_windows_to_go_peer() {
    tokio::time::timeout(Duration::from_secs(20), async {
        for (stream, connection) in [(6 * 1024 * 1024, 15 * 1024 * 1024), (512 * 1024, 16384), (16384, 65536)] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("parameters.jsonl");
            let mut peer = tokio::process::Command::new(std::env::var_os("AEROBOX_NAIVE_PEER").unwrap())
                .env("AEROBOX_NAIVE_PARAMETERS", &path)
                .stdout(Stdio::piped()).stderr(Stdio::inherit()).kill_on_drop(true)
                .spawn().unwrap();
            let mut ready = String::new();
            BufReader::new(peer.stdout.take().unwrap()).read_line(&mut ready).await.unwrap();
            let ready: serde_json::Value = serde_json::from_str(&ready).unwrap();
            let root = format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", ready["certificate"].as_str().unwrap());
            let target = NetLocation::from_str(&format!("127.0.0.1:{}", ready["h3"]), None).unwrap();
            let config: ResolvedClientConfig = crate::config::test_support::from_json(json!({
                "address":target.to_string(),"transport":"quic",
                "quic_settings":{"verify":true,"sni_hostname":"localhost","alpn_protocols":["h3"],"options":{"root_certificates":[root]}},
                "protocol":{"type":"naiveproxy","username":"user","password":"pass", "settings":{
                    "quic":true,"stream_receive_window":stream,"session_receive_window":connection
                }}
            })).unwrap();
            let connector = SocketConnectorImpl::from_config(&config, Some(&target)).unwrap();
            let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
            let carrier = connector.connect_quic(&resolver, &target.into()).await.unwrap();
            let values = tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    if let Ok(bytes) = std::fs::read(&path)
                        && let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                        break value;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }).await.expect("Go did not decode client transport parameters");
            assert_eq!(values["connection"], connection);
            assert_eq!(values["bidi_local"], stream);
            assert_eq!(values["bidi_remote"], stream);
            assert_eq!(values["uni"], stream);
            assert_eq!(values["bidi_streams"], 100);
            assert_eq!(values["uni_streams"], 103);
            assert_eq!(values["source_cid_bytes"], 0);
            assert_eq!(values["active_cid_limit"], 2);
            carrier.connection.close(0u32.into(), b"window test complete");
            peer.kill().await.unwrap();
            peer.wait().await.unwrap();
        }
    }).await.unwrap();
}

#[tokio::test]
#[ignore = "requires AEROBOX_NAIVE_PEER built from tests/fixtures/naive-peer"]
async fn naive_bbr2_factory_and_padded_tunnels_interoperate_with_go_peer() {
    use crate::tcp::{
        carrier_dialer::{CarrierDialer, QuicCarrier, RouteKey},
        proxy_connector::ProxyConnector,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct ConnectedRoute {
        carrier: QuicCarrier,
        key: RouteKey,
    }
    impl std::fmt::Debug for ConnectedRoute {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ConnectedRoute").finish_non_exhaustive()
        }
    }
    #[async_trait::async_trait]
    impl CarrierDialer for ConnectedRoute {
        fn route_key(&self) -> &RouteKey {
            &self.key
        }
        async fn open_stream(&self) -> std::io::Result<Box<dyn crate::async_stream::AsyncStream>> {
            unreachable!("Naive QUIC requires a datagram carrier")
        }
        async fn open_quic(&self) -> std::io::Result<QuicCarrier> {
            Ok(self.carrier.clone())
        }
    }

    tokio::time::timeout(Duration::from_secs(30), async {
        let mut peer = tokio::process::Command::new(std::env::var_os("AEROBOX_NAIVE_PEER").unwrap())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut ready = String::new();
        BufReader::new(peer.stdout.take().unwrap()).read_line(&mut ready).await.unwrap();
        let ready: serde_json::Value = serde_json::from_str(&ready).unwrap();
        let root = format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", ready["certificate"].as_str().unwrap());
        let target = NetLocation::from_str(&format!("127.0.0.1:{}", ready["h3"]), None).unwrap();
        for padding in [false, true] {
            let config: ResolvedClientConfig = crate::config::test_support::from_json(json!({
                "address":target.to_string(), "transport":"quic",
                "quic_settings":{"verify":true,"sni_hostname":"localhost","alpn_protocols":["h3"],"options":{"root_certificates":[root]}},
                "protocol":{"type":"naiveproxy","username":"user","password":"pass", "padding":padding,
                    "settings":{"quic":true,"quic_congestion_control":"bbr2","stream_receive_window":65536,"session_receive_window":262144}}
            })).unwrap();
            let connector = SocketConnectorImpl::from_config(&config, Some(&target)).unwrap();
            let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
            let carrier = connector.connect_quic(&resolver, &target.clone().into()).await.unwrap();
            assert!(carrier.connection.congestion_state().into_any().is::<quinn::congestion::Bbr2>());
            let route = Arc::new(ConnectedRoute { carrier: carrier.clone(), key: RouteKey(vec![2233]) });
            let client = super::quic::Client::new(config).unwrap();
            for round in 0..2 {
                let stream = client.connect_tcp_with_dialer(route.clone(), &NetLocation::from_str("echo.test:443", None).unwrap().into()).await.unwrap().client_stream;
                let data: Vec<u8> = (0..131_073).map(|index| ((index + round) % 251) as u8).collect();
                let (mut reader, mut writer) = tokio::io::split(stream);
                let ((), received) = tokio::join!(async {
                    writer.write_all(&data).await.unwrap();
                    writer.flush().await.unwrap();
                    writer.shutdown().await.unwrap();
                }, async {
                    let mut bytes = Vec::new();
                    reader.read_to_end(&mut bytes).await.unwrap();
                    bytes
                });
                assert_eq!(received, data, "padding={padding} round={round}");
            }
            let model = carrier.connection.congestion_state().into_any().downcast::<quinn::congestion::Bbr2>().unwrap();
            assert!(model.state().bandwidth_hi > 0);
            assert!(model.state().tracked_packets < 4096);
            carrier.connection.close(0u32.into(), b"BBRv2 integration complete");
        }
        peer.kill().await.unwrap();
        peer.wait().await.unwrap();
    }).await.unwrap();
}
