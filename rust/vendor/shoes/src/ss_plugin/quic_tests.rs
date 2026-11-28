use crate::{
    address::NetLocation,
    async_stream::AsyncStream,
    config::{ResolvedClientConfig, ResolvedClientHop},
    option_util::OneOrSome,
    resolver::{NativeResolver, Resolver},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::{io, pin::Pin, process::Stdio, sync::Arc, time::Duration};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, ReadBuf};

fn configuration(port: u16, cipher: &str, roots: Vec<String>, name: &str) -> Value {
    let password = if cipher.starts_with("2022-") {
        STANDARD.encode([42; 32])
    } else {
        "aerobox-reference".into()
    };
    json!({"address":format!("127.0.0.1:{port}"), "protocol":{
        "type":"shadowsocks", "cipher":cipher, "password":password, "plugin":{
            "type":"v2ray-plugin", "mode":"quic", "tls":true,
            "sni_hostname":name, "root_certificates":roots,
            // QUIC streams never use WebSocket path or Xray mux framing.
            "path":"/unused", "mux":8
        }
    }})
}
fn chain(value: Value) -> io::Result<crate::client_proxy_chain::ClientProxyChain> {
    let config: ResolvedClientConfig = crate::config::test_support::from_json(value)?;
    crate::tcp::chain_builder::try_build_client_proxy_chain(
        OneOrSome::One(ResolvedClientHop::Single(config)),
        Arc::new(NativeResolver::new()),
    )
}
fn resolver() -> Arc<dyn Resolver> {
    Arc::new(NativeResolver::new())
}
fn target() -> crate::address::ResolvedLocation {
    NetLocation::from_str("destination.example:443", None)
        .unwrap()
        .into()
}
async fn echo(stream: Box<dyn AsyncStream>, size: usize, marker: u8) {
    let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8 ^ marker).collect();
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut output = vec![0; data.len()];
    let (sent, received) = tokio::join!(
        async {
            writer.write_all(&data).await?;
            writer.flush().await
        },
        reader.read_exact(&mut output)
    );
    sent.unwrap();
    received.unwrap();
    assert_eq!(output, data);
    writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn quic_plugin_requires_its_own_tls_and_first_hop_transport() {
    let value = configuration(443, "aes-128-gcm", vec![], "localhost");
    let config: ResolvedClientConfig =
        crate::config::test_support::from_json(value.clone()).unwrap();
    assert_eq!(config.transport, crate::config::Transport::Quic);
    assert!(crate::ss_plugin::quic::validate_resolved(&config, false).is_err());
    for (field, bad) in [
        ("transport", json!("tcp")),
        ("quic_settings", json!({"verify":false})),
        ("tcp_settings", json!({})),
    ] {
        let mut invalid = value.clone();
        invalid[field] = bad;
        assert!(chain(invalid).is_err(), "{field}");
    }
    let mut invalid = value;
    invalid["protocol"]["plugin"]["tls"] = false.into();
    assert!(chain(invalid).is_err());
}

#[tokio::test]
#[ignore = "requires AEROBOX_OBFS_PEER built from tests/fixtures/obfs-peer"]
async fn v2ray_quic_reuses_sessions_reconnects_and_checks_certificates_with_go_peer() {
    for cipher in ["aes-128-gcm", "2022-blake3-chacha20-poly1305"] {
        tokio::time::timeout(Duration::from_secs(40), async {
            let certificates = tempfile::tempdir().unwrap();
            let mut child =
                tokio::process::Command::new(std::env::var_os("AEROBOX_OBFS_PEER").unwrap())
                    .arg("quic")
                    .arg(cipher)
                    .env("AEROBOX_PEER_CERT_DIR", certificates.path())
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::inherit())
                    .kill_on_drop(true)
                    .spawn()
                    .unwrap();
            let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
            let port: u16 = lines.next_line().await.unwrap().unwrap().parse().unwrap();
            let roots = vec![std::fs::read_to_string(certificates.path().join("ca.pem")).unwrap()];
            let client =
                Arc::new(chain(configuration(port, cipher, roots.clone(), "localhost")).unwrap());
            let mut jobs = tokio::task::JoinSet::new();
            for marker in 0..4 {
                let client = client.clone();
                jobs.spawn(async move {
                    let stream = client
                        .connect_tcp(target(), &resolver())
                        .await
                        .unwrap()
                        .client_stream;
                    echo(stream, 512 * 1024, marker).await;
                });
            }
            while let Some(result) = jobs.join_next().await {
                result.unwrap();
            }
            assert_eq!(
                std::fs::read_to_string(certificates.path().join("connections")).unwrap(),
                "1",
                "parallel SS connections must share QUIC"
            );
            let mut live = client
                .connect_tcp(target(), &resolver())
                .await
                .unwrap()
                .client_stream;
            live.write_all(b"live").await.unwrap();
            live.flush().await.unwrap();
            let mut bytes = [0; 4];
            live.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"live");
            child
                .stdin
                .as_mut()
                .unwrap()
                .write_all(b"close\n")
                .await
                .unwrap();
            assert_eq!(lines.next_line().await.unwrap().unwrap(), "closed");
            assert!(live.read(&mut bytes).await.is_err());
            drop(live);
            echo(
                client
                    .connect_tcp(target(), &resolver())
                    .await
                    .unwrap()
                    .client_stream,
                65536,
                42,
            )
            .await;
            assert_eq!(
                std::fs::read_to_string(certificates.path().join("connections")).unwrap(),
                "2"
            );
            for (roots, name) in [(roots, "wrong.example"), (vec![], "localhost")] {
                let rejected = chain(configuration(port, cipher, roots, name)).unwrap();
                assert!(
                    rejected.connect_tcp(target(), &resolver()).await.is_err(),
                    "untrusted plugin TLS must be rejected"
                );
            }
            child.kill().await.unwrap();
            child.wait().await.unwrap();
        })
        .await
        .unwrap_or_else(|err| panic!("{cipher}: {err}"));
    }
}

#[tokio::test]
#[ignore = "requires AEROBOX_OBFS_PEER built from tests/fixtures/obfs-peer"]
async fn plugin_quic_preserves_native_ss_udp_without_starting_quic() {
    for cipher in ["aes-128-gcm", "2022-blake3-chacha20-poly1305"] {
        tokio::time::timeout(Duration::from_secs(15), async {
            let mut child =
                tokio::process::Command::new(std::env::var_os("AEROBOX_OBFS_PEER").unwrap())
                    .arg("udp")
                    .arg(cipher)
                    .stdout(Stdio::piped())
                    .stderr(Stdio::inherit())
                    .kill_on_drop(true)
                    .spawn()
                    .unwrap();
            let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
            let port: u16 = lines.next_line().await.unwrap().unwrap().parse().unwrap();
            // There is deliberately no QUIC listener or trusted certificate.
            let client = chain(configuration(
                port,
                cipher,
                vec![],
                "no-quic-listener.example",
            ))
            .unwrap();
            assert!(client.supports_udp());
            let mut stream = client
                .connect_udp_bidirectional(&resolver(), target())
                .await
                .unwrap();
            for data in [vec![], vec![42; 16 * 1024], vec![1, 2, 3]] {
                futures::future::poll_fn(|cx| Pin::new(&mut *stream).poll_write_message(cx, &data))
                    .await
                    .unwrap();
                let mut output = vec![0; 65535];
                let mut read = ReadBuf::new(&mut output);
                futures::future::poll_fn(|cx| {
                    Pin::new(&mut *stream).poll_read_message(cx, &mut read)
                })
                .await
                .unwrap();
                assert_eq!(read.filled().len(), data.len(), "{cipher}: UDP length changed");
                assert!(read.filled() == data, "{cipher}: UDP contents changed");
            }
            child.kill().await.unwrap();
            child.wait().await.unwrap();
        })
        .await
        .unwrap_or_else(|err| panic!("{cipher}: {err}"));
    }
}
