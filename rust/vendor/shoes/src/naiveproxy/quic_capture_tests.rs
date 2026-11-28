//! Production Naive QUIC against an independent Go H3/QPACK observer.
use std::{
    io,
    path::PathBuf,
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

use crate::{
    address::{NetLocation, ResolvedLocation},
    async_stream::AsyncStream,
    config::ResolvedClientConfig,
    resolver::{NativeResolver, Resolver},
    tcp::{
        carrier_dialer::{CarrierDialer, QuicCarrier, RouteKey},
        proxy_connector::ProxyConnector,
        socket_connector::SocketConnector,
        socket_connector_impl::SocketConnectorImpl,
    },
};

fn config(address: &NetLocation, root: &str, server_name: &str) -> ResolvedClientConfig {
    crate::config::test_support::from_json(json!({
        "address":address.to_string(), "transport":"quic",
        "quic_settings":{
            "verify":true, "sni_hostname":server_name,
            "options":{"root_certificates":[root]}
        },
        "protocol":{
            "type":"naiveproxy", "username":"user", "password":"pass", "padding":true,
            "settings":{
                "quic":true, "stream_receive_window":6 * 1024 * 1024,
                "session_receive_window":15 * 1024 * 1024
            }
        }
    }))
    .unwrap()
}

#[derive(Debug)]
struct ProductionRoute {
    connector: SocketConnectorImpl,
    resolver: Arc<dyn Resolver>,
    address: ResolvedLocation,
    opens: AtomicUsize,
    key: RouteKey,
}

#[async_trait]
impl CarrierDialer for ProductionRoute {
    fn route_key(&self) -> &RouteKey {
        &self.key
    }
    async fn open_stream(&self) -> io::Result<Box<dyn AsyncStream>> {
        unreachable!()
    }
    async fn open_quic(&self) -> io::Result<QuicCarrier> {
        self.opens.fetch_add(1, Ordering::Relaxed);
        self.connector
            .connect_quic(&self.resolver, &self.address)
            .await
    }
}

#[tokio::test]
#[ignore = "requires AEROBOX_NAIVE_PEER and a fresh absolute AEROBOX_NAIVE_CAPTURE directory"]
async fn production_naive_h3_with_independent_reference_observer() {
    run_observer(false, false).await;
}

#[tokio::test]
#[ignore = "requires AEROBOX_NAIVE_PEER and a fresh absolute AEROBOX_NAIVE_CAPTURE directory"]
async fn production_naive_h3_decodes_independent_dynamic_qpack() {
    run_observer(true, false).await;
}

#[tokio::test]
#[ignore = "requires AEROBOX_NAIVE_PEER and a fresh absolute AEROBOX_NAIVE_CAPTURE directory"]
async fn production_naive_h3_waits_for_final_response_after_informational_heads() {
    run_observer(true, true).await;
}

async fn run_observer(dynamic: bool, informational: bool) {
    let peer = std::env::var_os("AEROBOX_NAIVE_PEER").expect("set AEROBOX_NAIVE_PEER");
    let output = PathBuf::from(
        std::env::var_os("AEROBOX_NAIVE_CAPTURE").expect("set AEROBOX_NAIVE_CAPTURE"),
    );
    assert!(output.is_absolute(), "capture directory must be absolute");
    assert!(
        !output.exists(),
        "observer requires a new capture directory"
    );
    tokio::time::timeout(Duration::from_secs(60), async {
        let mut child = tokio::process::Command::new(peer)
            .env("AEROBOX_NAIVE_CAPTURE", &output)
            .env(
                "AEROBOX_NAIVE_DYNAMIC_QPACK",
                if dynamic { "1" } else { "0" },
            )
            .env(
                "AEROBOX_NAIVE_INFORMATIONAL",
                if informational { "1" } else { "0" },
            )
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let mut ready_line = String::new();
        assert_ne!(stdout.read_line(&mut ready_line).await.unwrap(), 0);
        let ready: serde_json::Value = serde_json::from_str(&ready_line).unwrap();
        assert_eq!(ready["phase"], "ready");
        assert_eq!(ready["server_name"], "naive.test");
        let ca = PathBuf::from(ready["ca_pem"].as_str().unwrap());
        assert_eq!(ca, output.join("ca.pem"));
        std::fs::write(output.join("ready.json"), ready_line).unwrap();

        let port = u16::try_from(ready["port"].as_u64().unwrap()).unwrap();
        let address = NetLocation::from_str(&format!("127.0.0.1:{port}"), None).unwrap();
        let config = config(
            &address,
            &std::fs::read_to_string(ca).unwrap(),
            ready["server_name"].as_str().unwrap(),
        );
        let route = Arc::new(ProductionRoute {
            connector: SocketConnectorImpl::from_config(&config, Some(&address)).unwrap(),
            resolver: Arc::new(NativeResolver::new()),
            address: address.into(),
            opens: AtomicUsize::new(0),
            key: RouteKey(vec![2513]),
        });
        let client = super::quic::Client::new(config).unwrap();
        let target = NetLocation::from_str("capture.invalid:443", None)
            .unwrap()
            .into();
        let payload: Vec<u8> = (0..65537)
            .map(|index| ((index * 17 + 3) % 251) as u8)
            .collect();
        for _ in 0..2 {
            let stream = client
                .connect_tcp_with_dialer(route.clone(), &target)
                .await
                .unwrap()
                .client_stream;
            let (read, mut write) = tokio::io::split(stream);
            let mut read = read.take(payload.len() as u64 + 1);
            let mut received = Vec::with_capacity(payload.len());
            let upload = async {
                write.write_all(&payload).await?;
                write.shutdown().await
            };
            tokio::try_join!(upload, read.read_to_end(&mut received)).unwrap();
            assert_eq!(received, payload);
        }
        assert_eq!(
            route.opens.load(Ordering::Relaxed),
            1,
            "both tunnels must share one production QUIC carrier"
        );
        drop(client);

        let mut ending = String::new();
        let (status, _) =
            tokio::try_join!(child.wait(), stdout.read_to_string(&mut ending)).unwrap();
        std::fs::write(output.join("server-ending.json"), &ending).unwrap();
        assert!(status.success(), "observer failed: {ending}");
        let completed: serde_json::Value = serde_json::from_str(&ending).unwrap();
        let capture: serde_json::Value =
            serde_json::from_slice(&std::fs::read(output.join("capture.json")).unwrap()).unwrap();
        assert_eq!(completed, capture);
        assert_eq!(capture["phase"], "complete");
        assert_eq!(capture["requests"], 2);
        assert_eq!(capture["dynamic_qpack"], dynamic);
        assert_eq!(capture["informational_responses"], informational);
        if dynamic {
            let feedback = capture["decoder_feedback"].as_array().unwrap();
            assert!(feedback.iter().any(|entry| entry == "ack:0"));
            assert!(feedback.iter().any(|entry| entry == "ack:4"));
        }
        assert!(
            !std::fs::read(output.join("client-hello.bin"))
                .unwrap()
                .is_empty()
        );

        let requests: Vec<_> = capture["streams"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|stream| stream["Type"] == 1 && stream["Headers"].is_array())
            .collect();
        assert_eq!(requests.len(), 2);
        for (index, request) in requests.into_iter().enumerate() {
            assert_eq!(request["ID"], index * 4);
            assert_eq!(
                request["End"], "fin",
                "observer must receive a clean request FIN"
            );
            assert!(request["Bytes"].as_u64().unwrap() >= payload.len() as u64);
            let fields = request["Headers"].as_array().unwrap();
            assert_eq!(fields.len(), 5);
            for (name, expected) in [
                (":method", "CONNECT"),
                (":authority", "capture.invalid:443"),
                ("proxy-authorization", "Basic dXNlcjpwYXNz"),
                ("user-agent", ""),
            ] {
                let matching: Vec<_> = fields
                    .iter()
                    .filter(|field| field["Name"] == name)
                    .collect();
                assert_eq!(matching.len(), 1, "duplicate/missing {name}");
                assert_eq!(matching[0]["Value"], expected);
            }
            assert!(
                fields
                    .iter()
                    .all(|field| field["Name"] != "padding-type-request")
            );
            let padding = fields
                .iter()
                .find(|field| field["Name"] == "padding")
                .unwrap()["Value"]
                .as_str()
                .unwrap()
                .as_bytes();
            assert!((30..=61).contains(&padding.len()));
            assert!(
                padding[..16]
                    .iter()
                    .all(|byte| b"!#$()+<>?@[]^`{}".contains(byte))
            );
            assert!(padding[16..].iter().all(|byte| *byte == b'~'));
        }
    })
    .await
    .expect("production Naive H3 observer timed out");
}

#[tokio::test]
#[ignore = "requires AEROBOX_NAIVE_PEER"]
async fn production_naive_h3_rejects_wrong_root_and_hostname() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let mut child =
            tokio::process::Command::new(std::env::var_os("AEROBOX_NAIVE_PEER").unwrap())
                .env_remove("AEROBOX_NAIVE_CAPTURE")
                .env_remove("AEROBOX_NAIVE_PARAMETERS")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .kill_on_drop(true)
                .spawn()
                .unwrap();
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let mut ready = String::new();
        assert_ne!(stdout.read_line(&mut ready).await.unwrap(), 0);
        let ready: serde_json::Value = serde_json::from_str(&ready).unwrap();
        let root = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            ready["certificate"].as_str().unwrap()
        );
        let wrong_root = rcgen::generate_simple_self_signed(vec!["naive.test".into()])
            .unwrap()
            .cert
            .pem();
        let port = u16::try_from(ready["h3"].as_u64().unwrap()).unwrap();
        let address = NetLocation::from_str(&format!("127.0.0.1:{port}"), None).unwrap();
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        for (root, name, valid) in [
            (root.as_str(), "naive.test", true),
            (wrong_root.as_str(), "naive.test", false),
            (root.as_str(), "wrong.invalid", false),
        ] {
            let config = config(&address, root, name);
            let connector = SocketConnectorImpl::from_config(&config, Some(&address)).unwrap();
            match connector
                .connect_quic(&resolver, &address.clone().into())
                .await
            {
                Ok(carrier) => {
                    carrier
                        .connection
                        .close(0u32.into(), b"certificate test complete");
                    assert!(valid, "invalid root/hostname was accepted: {name}");
                }
                Err(error) => {
                    assert!(!valid, "trusted fixture rejected: {error}");
                    assert!(
                        error.to_string().to_lowercase().contains("certificate"),
                        "expected certificate rejection, got {error}"
                    );
                }
            }
        }
        child.kill().await.unwrap();
        child.wait().await.unwrap();
    })
    .await
    .expect("production Naive QUIC certificate checks timed out");
}
