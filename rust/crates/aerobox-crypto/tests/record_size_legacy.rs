//! RFC8449 receive limits across independent Go TLS1.0/1.1/1.2 key epochs.
#[path = "support/edge_qq.rs"]
mod support;
use rustls::{ClientConnection, ProtocolVersion, client::ClientHelloLayout};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
    process::{Child, ChildStdout, Command, Stdio},
    sync::Arc,
    time::Duration,
};
struct Peer {
    child: Child,
    stdout: BufReader<ChildStdout>,
    hellos: std::path::PathBuf,
}
impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.hellos);
    }
}
fn peer(
    mode: &str,
    version: &str,
    suite: u16,
    mutual: bool,
    first: i32,
    second: i32,
    advertised: u16,
) -> (Peer, TcpStream) {
    let mut cmd = Command::new(std::env::var_os("AEROBOX_RECORD_SIZE_LEGACY_PEER").unwrap());
    cmd.args([
        "--fixtures",
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures"),
        "--mode",
        mode,
        "--version",
        version,
        "--suite",
        &suite.to_string(),
    ]);
    cmd.args([
        "--record-first",
        &first.to_string(),
        "--record-second",
        &second.to_string(),
        "--record-advertised",
        &advertised.to_string(),
    ]);
    if mutual {
        cmd.arg("--mutual");
    }
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let hellos = std::env::temp_dir().join(format!(
        "aerobox-legacy-reneg-{}-{}.json",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let mut child = cmd
        .arg("--hellos")
        .arg(&hellos)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let ready: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(ready["phase"], "ready");
    let socket = TcpStream::connect(("127.0.0.1", ready["port"].as_u64().unwrap() as u16)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    (
        Peer {
            child,
            stdout,
            hellos,
        },
        socket,
    )
}
fn client(mutual: bool, tls12_only: bool) -> ClientConnection {
    let mut cfg = support::config(ClientHelloLayout::Edge85, mutual);
    if tls12_only {
        // The legacy opt-in deliberately requires TLS1.0/1.1. Construct an
        // ordinary TLS1.2-only policy instead of bypassing that guard.
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(include_bytes!("fixtures/rsa-cert.der").as_slice().into())
            .unwrap();
        let mut tls12 = rustls::ClientConfig::builder_with_provider(cfg.crypto_provider().clone())
            .with_protocol_versions(&[&rustls::version::TLS12])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls12.client_auth_cert_resolver = cfg.client_auth_cert_resolver;
        tls12.time_provider = cfg.time_provider;
        tls12.alpn_protocols = cfg.alpn_protocols;
        tls12.enable_tls12_renegotiation = true;
        tls12.resumption = rustls::client::Resumption::disabled();
        cfg = tls12;
    }
    cfg.client_hello_layout = None;
    cfg.cert_decompressors.clear();
    cfg.advertise_record_size_limit = true;
    cfg.max_fragment_size = None;
    ClientConnection::new(Arc::new(cfg), "localhost".try_into().unwrap()).unwrap()
}
fn marker(
    stream: &mut rustls::StreamOwned<ClientConnection, TcpStream>,
    name: &str,
) -> std::io::Result<Vec<u8>> {
    let mut out = vec![0; name.len() + 32];
    stream.read_exact(&mut out)?;
    assert_eq!(&out[..name.len()], name.as_bytes());
    let key = out[name.len()..].to_vec();
    match stream
        .conn
        .export_keying_material(vec![0; 32], b"aerobox-renegotiation", None)
    {
        Ok(actual) => assert_eq!(actual, key),
        Err(error) => assert!(
            error.to_string().contains("require extended master secret"),
            "{error}"
        ),
    }
    if name == "initial" {
        stream.write_all(b"ack")?;
        stream.flush()?;
    }
    Ok(key)
}

fn terminal(peer: &mut Peer) -> serde_json::Value {
    let mut line = String::new();
    peer.stdout.read_line(&mut line).unwrap();
    assert!(peer.child.wait().unwrap().success());
    serde_json::from_str(&line).unwrap()
}

#[test]
#[ignore = "requires independent AEROBOX_RECORD_SIZE_LEGACY_PEER"]
fn legacy_record_limits_follow_authenticated_key_epochs_and_negotiate_again() {
    for (version, protocol, suites) in [
        ("1.0", ProtocolVersion::TLSv1_0, vec![0xc013]),
        ("1.1", ProtocolVersion::TLSv1_1, vec![0xc013]),
        ("1.2", ProtocolVersion::TLSv1_2, vec![0xc013, 0xc02f]),
    ] {
        for suite in suites {
            for (first, second) in [(64, -1), (64, 512), (512, 64), (-1, 64)] {
                eprintln!("TLS{version} suite={suite:04x} {first}->{second}");
                let (mut peer, socket) = peer(
                    "inflight-fragment",
                    version,
                    suite,
                    true,
                    first,
                    second,
                    16385,
                );
                let mut stream = rustls::StreamOwned::new(client(true, false), socket);
                let old = marker(&mut stream, "initial").unwrap();
                let mut old_data = [0; 8];
                stream.read_exact(&mut old_data).unwrap();
                assert_eq!(&old_data, b"old-data");
                let new = marker(&mut stream, "renewed").unwrap();
                assert_ne!(old, new);
                assert_eq!(stream.conn.protocol_version(), Some(protocol));
                assert_eq!(
                    u16::from(stream.conn.negotiated_cipher_suite().unwrap().suite()),
                    suite
                );
                let sent: Vec<_> = (0..65537).map(|n| (n % 251) as u8).collect();
                stream.write_all(&sent).unwrap();
                stream.flush().unwrap();
                let mut received = vec![0; sent.len()];
                stream.read_exact(&mut received).unwrap();
                assert_eq!(sent, received);
                stream.conn.send_close_notify();
                stream.flush().unwrap();
                assert_eq!(stream.read(&mut [0]).unwrap(), 0);
                let result = terminal(&mut peer);
                assert_eq!(result["phase"], "complete", "{result}");
                assert_eq!(result["completed_handshakes"], 2);
                assert_eq!(result["client_certificates"], 1);
                assert_eq!(result["echoed_bytes"], sent.len());
                let first_limit = if first < 0 { 16384 } else { first as u64 };
                let second_limit = if second < 0 { 16384 } else { second as u64 };
                assert!(result["record_maximum"][1].as_u64().unwrap() <= first_limit);
                assert_eq!(result["record_maximum"][2], second_limit);
                assert!(result["record_counts"][1].as_u64().unwrap() > 1);
            }
        }
    }
}

#[test]
#[ignore = "requires independent AEROBOX_RECORD_SIZE_LEGACY_PEER"]
fn legacy_invalid_initial_and_renegotiated_limits_fail_before_application_data() {
    for invalid in [0, 63, 16385, 65535] {
        for renegotiated in [false, true] {
            let (first, second) = if renegotiated {
                (64, invalid)
            } else {
                (invalid, 64)
            };
            let (mut peer, socket) = peer("valid", "1.2", 0xc02f, true, first, second, 16385);
            let mut stream = rustls::StreamOwned::new(client(true, false), socket);
            if renegotiated {
                marker(&mut stream, "initial").unwrap();
            }
            assert!(
                marker(
                    &mut stream,
                    if renegotiated { "renewed" } else { "initial" }
                )
                .is_err()
            );
            let error = stream.conn.process_new_packets().unwrap_err();
            assert!(
                error.to_string().contains("invalid peer record_size_limit"),
                "{error:?}"
            );
            assert_eq!(stream.conn.process_new_packets().unwrap_err(), error);
            drop(stream);
            let result = terminal(&mut peer);
            assert_eq!(result["phase"], "error", "{result}");
            assert_eq!(result["echoed_bytes"], 0);
        }
    }
}

#[test]
#[ignore = "requires independent AEROBOX_RECORD_SIZE_LEGACY_PEER"]
fn tls12_only_advertises_16384_and_accepts_a_missing_reply() {
    let (mut peer, socket) = peer("valid", "1.2", 0xc02f, false, -1, -1, 16384);
    let mut stream = rustls::StreamOwned::new(client(false, true), socket);
    let old = marker(&mut stream, "initial").unwrap();
    let new = marker(&mut stream, "renewed").unwrap();
    assert_ne!(old, new);
    stream.write_all(b"record-size").unwrap();
    stream.flush().unwrap();
    let mut data = [0; 11];
    stream.read_exact(&mut data).unwrap();
    assert_eq!(&data, b"record-size");
    stream.conn.send_close_notify();
    stream.flush().unwrap();
    assert_eq!(stream.read(&mut [0]).unwrap(), 0);
    assert_eq!(terminal(&mut peer)["phase"], "complete");
}
