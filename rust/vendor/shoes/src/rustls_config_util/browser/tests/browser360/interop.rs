use super::*;
use crate::crypto::{CryptoTlsStream, TlsConnection, TlsReadMode};
use std::{
    io::{BufRead, BufReader},
    process::{Child, Command, Stdio},
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const FIXTURES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../crates/aerobox-crypto/tests/fixtures"
);
struct Peer(Child);
impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
#[derive(Debug)]
struct FixedTime;
impl rustls::time_provider::TimeProvider for FixedTime {
    fn current_time(&self) -> Option<rustls::pki_types::UnixTime> {
        Some(rustls::pki_types::UnixTime::since_unix_epoch(
            Duration::from_secs(1893456000),
        ))
    }
}
fn pem(kind: &str, data: &[u8]) -> String {
    format!(
        "-----BEGIN {kind}-----\n{}\n-----END {kind}-----\n",
        STANDARD.encode(data)
    )
}
fn hash(data: &[u8]) -> String {
    aerobox_primitives::digest::digest(&aerobox_primitives::digest::SHA256, data)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[tokio::test]
#[ignore = "requires AEROBOX_360_TLS_PEER"]
async fn browser360_production_async_non_ems_records_and_close() {
    // Every record primitive through the actual native policy builder and
    // asynchronous stream. Include preserved-record reads and small fragments.
    for version in ["1.0", "1.1", "1.2"] {
        for suite in [
            0xc007u16, 0xc011, 0x0005, 0xc013, 0x002f, 0x000a, 0xc023, 0xc027, 0x003c,
        ] {
            if version != "1.2" && matches!(suite, 0xc023 | 0xc027 | 0x003c) {
                continue;
            }
            for framed in [false, true] {
                tokio::time::timeout(Duration::from_secs(40), async {
                    let mut peer = Peer(
                        Command::new(std::env::var_os("AEROBOX_360_TLS_PEER").unwrap())
                            .args([
                                "--fixtures",
                                FIXTURES,
                                "--version",
                                version,
                                "--suite",
                                &format!("0x{suite:04x}"),
                                "--bytes",
                                "65537",
                            ])
                            .stdout(Stdio::piped())
                            .stderr(Stdio::inherit())
                            .spawn()
                            .unwrap(),
                    );
                    let mut output = BufReader::new(peer.0.stdout.take().unwrap());
                    let mut line = String::new();
                    output.read_line(&mut line).unwrap();
                    let ready: serde_json::Value = serde_json::from_str(&line).unwrap();
                    assert_eq!(ready["phase"], "ready");
                    let kind = if matches!(suite, 0xc007 | 0xc023) {
                        "ecdsa"
                    } else {
                        "rsa"
                    };
                    let cert = std::fs::read(format!("{FIXTURES}/{kind}-cert.der")).unwrap();
                    let (_, parsed) = x509_parser::parse_x509_certificate(&cert).unwrap();
                    let pin = STANDARD.encode(aerobox_primitives::digest::digest(
                        &aerobox_primitives::digest::SHA256,
                        parsed.public_key().raw,
                    ));
                    let options = TlsClientOptions {
                        root_certificates: vec![pem("CERTIFICATE", &cert)],
                        certificate_public_key_sha256: vec![pin],
                        ..policy()
                    };
                    let mut config = client(&options, false).unwrap();
                    config.time_provider = Arc::new(FixedTime);
                    config.max_fragment_size = Some(1024);
                    let connection = rustls::ClientConnection::new(
                        Arc::new(config),
                        "localhost".try_into().unwrap(),
                    )
                    .unwrap();
                    let socket = tokio::net::TcpStream::connect((
                        "127.0.0.1",
                        ready["port"].as_u64().unwrap() as u16,
                    ))
                    .await
                    .unwrap();
                    let mut stream = CryptoTlsStream::handshake(
                        socket,
                        TlsConnection::new(connection),
                        if framed {
                            TlsReadMode::PreserveRecords
                        } else {
                            TlsReadMode::Stream
                        },
                        &[],
                    )
                    .await
                    .unwrap();
                    assert_eq!(stream.alpn_protocol(), Some(b"http/1.1".as_slice()));
                    let sent: Vec<_> = (0..65537).map(|i| ((i * 17 + 3) % 251) as u8).collect();
                    stream.write_all(&sent).await.unwrap();
                    stream.flush().await.unwrap();
                    let mut received = vec![0; 65541];
                    stream.read_exact(&mut received).await.unwrap();
                    assert_eq!(&received[..4], b"B360");
                    for (i, b) in received[4..].iter().enumerate() {
                        assert_eq!(*b, ((i * 29 + 7) % 251) as u8);
                    }
                    stream.shutdown().await.unwrap();
                    assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
                    line.clear();
                    output.read_line(&mut line).unwrap();
                    let report: serde_json::Value = serde_json::from_str(&line).unwrap();
                    assert_eq!(report["phase"], "complete");
                    assert_eq!(report["cipher"], suite);
                    assert_eq!(report["ems"], false);
                    assert_eq!(report["exporter_rejected"], true);
                    assert_eq!(report["close_notify_received"], true);
                    assert_eq!(report["client_sha256"], hash(&sent));
                    assert_eq!(report["server_sha256"], hash(&received[4..]));
                    assert!(peer.0.wait().unwrap().success());
                })
                .await
                .unwrap();
            }
        }
    }
}
