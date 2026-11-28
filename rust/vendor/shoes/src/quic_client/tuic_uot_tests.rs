//! TUIC's SagerNet UoT addon is a CONNECT stream, not COMMAND_PACKET.
use crate::{
    address::NetLocation,
    async_stream::{AsyncMessageStream, AsyncReadMessage, AsyncShutdownMessageExt},
    config::{
        ResolvedClientChain,
        quic_client::{TuicClientConfig, TuicUdpMode},
    },
    resolver::{NativeResolver, Resolver},
    tcp::chain_builder::try_build_client_proxy_chain,
};
use serde_json::{Value, json};
use std::{future::poll_fn, pin::Pin, process::Stdio, sync::Arc, time::Duration};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, ReadBuf};

const UUID: &str = "d9ad4eab-f118-492b-a99b-e0e27332b4b2";

#[test]
fn tuic_uot_preserves_native_defaults_and_rejects_incompatible_native_mode() {
    let mut value = json!({"uuid":UUID,"password":"test-password"});
    let config: TuicClientConfig = serde_json::from_value(value.clone()).unwrap();
    assert!(!config.udp_over_stream);
    assert_eq!(config.udp_relay_mode, TuicUdpMode::Native);
    config.validate().unwrap();
    value["udp_over_stream"] = true.into();
    let config: TuicClientConfig = serde_json::from_value(value.clone()).unwrap();
    assert!(config.udp_over_stream);
    config.validate().unwrap();
    value["udp_relay_mode"] = "quic".into();
    let config: TuicClientConfig = serde_json::from_value(value).unwrap();
    assert_eq!(
        config.validate().unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput
    );
}

async fn exchange(stream: &mut dyn AsyncMessageStream, data: &[u8]) {
    poll_fn(|cx| Pin::new(&mut *stream).poll_write_message(cx, data))
        .await
        .unwrap();
    poll_fn(|cx| Pin::new(&mut *stream).poll_flush_message(cx))
        .await
        .unwrap();
    let mut buffer = vec![0; 65535];
    let mut received = ReadBuf::new(&mut buffer);
    poll_fn(|cx| Pin::new(&mut *stream).poll_read_message(cx, &mut received))
        .await
        .unwrap();
    assert_eq!(received.filled(), data);
    if data.is_empty() {
        assert!(
            !stream.read_message_eof_on_empty(),
            "empty UDP payload became EOF"
        );
    }
}

fn events(path: &std::path::Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[tokio::test]
#[ignore = "requires AEROBOX_TUIC_PEER built from the pinned TUIC/UoT Go peer"]
async fn tuic_uot_magic_tcp_udp_empty_maximum_and_cancellation_with_go() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let directory = tempfile::tempdir().unwrap();
        let mut process = tokio::process::Command::new(std::env::var_os("AEROBOX_TUIC_PEER").unwrap())
            .args(["accept", "uot-only"])
            .env("AEROBOX_PEER_CERT_DIR", directory.path())
            .stdout(Stdio::piped()).stderr(Stdio::inherit()).kill_on_drop(true)
            .spawn().unwrap();
        let port: u16 = BufReader::new(process.stdout.take().unwrap()).lines()
            .next_line().await.unwrap().unwrap().parse().unwrap();
        let root = std::fs::read_to_string(directory.path().join("ca.pem")).unwrap();
        let config: ResolvedClientChain = crate::config::test_support::from_json(json!({"chain":[{
            "address":format!("127.0.0.1:{port}"),"transport":"quic",
            "quic_settings":{"verify":true,"sni_hostname":"localhost","alpn_protocols":["h3"],"options":{"root_certificates":[root]}},
            "protocol":{"type":"tuic","uuid":UUID,"password":"test-password","udp_over_stream":true}
        }]})).unwrap();
        let network = crate::network_tasks::NetworkLifetime::default();
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let chain = network.scope(async {
            try_build_client_proxy_chain(config.hops, resolver.clone()).unwrap()
        }).await;
        assert!(chain.supports_udp());

        // A cancelled foreground waiter cannot cancel shared QUIC setup. It
        // has not received the generation, so it has sent no UoT CONNECT yet.
        let cancelled_target = NetLocation::from_str("cancelled.test:53", None).unwrap().into();
        let mut cancelled = Box::pin(network.scope(chain.connect_udp_bidirectional(&resolver, cancelled_target)));
        assert!(futures::poll!(&mut cancelled).is_pending());
        tokio::task::yield_now().await;
        drop(cancelled);

        let mut held = None;
        for destination in ["192.0.2.8:5353", "[2001:db8::8]:5353", "packet.test:5353"] {
            let target = NetLocation::from_str(destination, None).unwrap().into();
            let mut packets = network.scope(chain.connect_udp_bidirectional(&resolver, target)).await.unwrap();
            for size in [0usize, 3, 16384, 65535] {
                let payload: Vec<_> = (0..size).map(|n| (n % 251) as u8).collect();
                exchange(&mut *packets, &payload).await;
            }
            // Cancelling an empty read must preserve the stream's framing.
            {
                let mut bytes = [0; 32];
                let mut read = ReadBuf::new(&mut bytes);
                let mut pending = Box::pin(poll_fn(|cx| Pin::new(&mut *packets).poll_read_message(cx, &mut read)));
                assert!(futures::poll!(&mut pending).is_pending());
            }
            exchange(&mut *packets, b"after cancelled read").await;
            if destination == "packet.test:5353" { held = Some(packets); }
            else { packets.shutdown_message().await.unwrap(); }
        }

        let target = NetLocation::from_str("tcp.test:443", None).unwrap().into();
        let result = network.scope(chain.connect_tcp(target, &resolver)).await.unwrap();
        assert!(result.early_data.is_none());
        let (mut read, mut write) = tokio::io::split(result.client_stream);
        let payload: Vec<_> = (0..65537).map(|n| (n % 247) as u8).collect();
        let mut received = vec![0; payload.len()];
        let (written, echoed) = tokio::join!(async { write.write_all(&payload).await?; write.flush().await }, read.read_exact(&mut received));
        written.unwrap(); echoed.unwrap(); assert_eq!(payload, received);
        write.shutdown().await.unwrap();
        drop((read, write));

        let rows = events(&directory.path().join("events.jsonl"));
        assert_eq!(rows.iter().filter(|r| r["event"] == "offer").count(), 1, "TCP/UDP must share one session");
        assert_eq!(rows.iter().filter(|r| r["event"] == "uot_open").count(), 3);
        assert_eq!(rows.iter().filter(|r| r["event"] == "uot_packet").count(), 15);
        assert_eq!(rows.iter().filter(|r| r["event"] == "tcp_open").count(), 1);
        assert!(rows.iter().all(|r| r["event"] != "unexpected_native_udp" && r["event"] != "native_udp_open" && r["event"] != "native_udp_packet"));
        for destination in ["192.0.2.8:5353", "[2001:db8::8]:5353", "packet.test:5353"] {
            let opens: Vec<_> = rows.iter().filter(|r| r["event"] == "uot_open" && r["destination"] == destination).collect();
            assert_eq!(opens.len(), 1); assert_eq!(opens[0]["connect"], true);
            let sizes: Vec<_> = rows.iter().filter(|r| r["event"] == "uot_packet" && r["destination"] == destination)
                .map(|r| r["bytes"].as_u64().unwrap()).collect();
            assert_eq!(sizes, [0, 3, 16384, 65535, 20]);
        }

        // Network retirement must invalidate already returned UoT wrappers.
        network.cancel(); network.wait().await;
        let mut packets = held.unwrap();
        let mut bytes = [0; 1]; let mut read = ReadBuf::new(&mut bytes);
        let result = poll_fn(|cx| Pin::new(&mut *packets).poll_read_message(cx, &mut read)).await;
        assert!(result.is_err() || (read.filled().is_empty() && packets.read_message_eof_on_empty()));
        drop((packets, chain));
        process.kill().await.unwrap(); process.wait().await.unwrap();
    }).await.unwrap();
}
