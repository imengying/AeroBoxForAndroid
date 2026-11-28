//! Production factory plus private test-only observation of the real rustls
//! exporter. This module adds no public seed/configuration or runtime API.
use super::*;
use crate::config::tls::TlsClientFingerprint;
use crate::reality::{CipherSuite, RealityClientConfig};
use std::{
    io::{BufRead, BufReader},
    net::TcpStream,
    process::{Child, Command, Stdio},
    sync::mpsc::{self, Receiver},
    thread::JoinHandle,
    time::Duration,
};

const LABEL: &[u8] = b"aerobox randomized reality exporter";
const CONTEXT: &[u8] = b"\0randomized\0reality\0";
const FIXTURES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../crates/aerobox-crypto/tests/fixtures"
);
struct Peer(Child, Option<JoinHandle<()>>);
impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        if let Some(reader) = self.1.take() {
            reader.join().expect("peer evidence reader panicked");
        }
    }
}
type Evidence = Receiver<io::Result<String>>;
fn report(out: &Evidence) -> serde_json::Value {
    // A blocked stdout pipe must not bypass the async test's timeout forever.
    // Drop kills the child and joins its bounded two-line evidence reader.
    let line = out
        .recv_timeout(Duration::from_secs(30))
        .expect("peer evidence timeout or disconnected reader")
        .expect("read bounded peer evidence");
    serde_json::from_str(&line).unwrap()
}
fn start(
    plan: &aerobox_fingerprint::randomized::Plan,
    suite: u16,
    group: u16,
    mode: &str,
    bad_finished: bool,
) -> (Peer, Evidence, u16) {
    let ext = plan.extensions();
    let mut args = vec![
        "-fixtures".into(),
        FIXTURES.into(),
        "-reality-profile=randomized".into(),
        "-reality-browser".into(),
        format!("-reality={mode}"),
        "-brotli=false".into(),
        format!("-reality-suite={suite}"),
        format!("-group={group}"),
        "-randomized-reality-exchange".into(),
        format!("-alps={}", if ext.contains(&17513) { 17513 } else { 0 }),
        format!(
            "-expect-shares={}",
            plan.shares()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")
        ),
    ];
    if !ext.contains(&16) {
        args.extend(["-allow-no-alpn".into(), "-omit-alpn".into()]);
    }
    if bad_finished {
        args.push("-bad-finished".into());
    }
    let mut peer = Peer(
        Command::new(
            std::env::var_os("AEROBOX_TLS_PROFILE_PEER")
                .expect("independent three-suite Go REALITY peer"),
        )
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap(),
        None,
    );
    let mut stdout = BufReader::new(peer.0.stdout.take().unwrap());
    let (sender, out) = mpsc::sync_channel(2);
    peer.1 = Some(std::thread::spawn(move || {
        for _ in 0..2 {
            let mut line = String::new();
            let evidence = stdout
                .by_ref()
                .take(65537)
                .read_line(&mut line)
                .and_then(|_| {
                    if line.is_empty() || line.len() > 65536 || !line.ends_with('\n') {
                        Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid peer evidence framing",
                        ))
                    } else {
                        Ok(line)
                    }
                });
            let failed = evidence.is_err();
            if sender.send(evidence).is_err() || failed {
                break;
            }
        }
    }));
    let ready = report(&out);
    assert_eq!(ready["phase"], "ready");
    let port = u16::try_from(ready["port"].as_u64().unwrap()).unwrap();
    (peer, out, port)
}
fn socket(port: u16) -> TcpStream {
    let s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    s.set_write_timeout(Some(Duration::from_secs(30))).unwrap();
    s
}
fn configuration(plan: &aerobox_fingerprint::randomized::Plan) -> RealityClientConfig {
    let public = aerobox_primitives::agreement::PrivateKey::from_private_key(
        &aerobox_primitives::agreement::X25519,
        &[42; 32],
    )
    .unwrap()
    .compute_public_key()
    .unwrap();
    let suites = plan
        .suites()
        .iter()
        .filter_map(|id| match id {
            0x1301 => Some(CipherSuite::AES_128_GCM_SHA256),
            0x1302 => Some(CipherSuite::AES_256_GCM_SHA384),
            0x1303 => Some(CipherSuite::CHACHA20_POLY1305_SHA256),
            _ => None,
        })
        .collect();
    RealityClientConfig {
        public_key: public.as_ref().try_into().unwrap(),
        short_id: [1; 8],
        mldsa65_verify: None,
        server_name: "cover.test".try_into().unwrap(),
        cipher_suites: suites,
    }
}
fn connection(plan: &aerobox_fingerprint::randomized::Plan) -> TlsConnection {
    configuration(plan)
        .create_connection_with_profile(vec![], Some(TlsClientFingerprint::Randomized))
        .unwrap()
}
fn drain(c: &mut TlsConnection, s: &mut TcpStream) -> io::Result<()> {
    while c.wants_write() {
        c.write_tls(s)?;
    }
    s.flush()
}
fn handshake(c: &mut TlsConnection, s: &mut TcpStream) -> io::Result<()> {
    while c.is_handshaking() {
        drain(c, s)?;
        if c.read_tls(s)? == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        };
        c.process_new_packets()?;
    }
    drain(c, s)
}
fn receive(c: &mut TlsConnection, s: &mut TcpStream, mut out: &mut [u8]) {
    while !out.is_empty() {
        match c.reader().read(out) {
            Ok(0) => panic!("premature plaintext EOF"),
            Ok(n) => {
                out = &mut out[n..];
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                assert!(c.read_tls(s).unwrap() > 0);
                c.process_new_packets().unwrap();
            }
            Err(e) => panic!("plaintext read: {e}"),
        }
    }
}
fn hex(v: &[u8]) -> String {
    v.iter().map(|b| format!("{b:02x}")).collect()
}
fn digest(v: &[u8]) -> String {
    hex(aerobox_primitives::digest::digest(&aerobox_primitives::digest::SHA256, v).as_ref())
}
fn fixed_plan() -> Option<aerobox_fingerprint::randomized::Plan> {
    let original = aerobox_fingerprint::randomized::process_plan().unwrap();
    match original.for_stream(true) {
        Ok(plan) => Some(plan),
        Err(expected) => {
            // A mathematically possible TLS1.2-only generator outcome must keep its
            // fixed error. No seed retry/1301 filtering is ever allowed in this test.
            for _ in 0..3 {
                let actual =
                    crate::rustls_config_util::browser::randomized::provider(true).unwrap_err();
                assert_eq!(actual.to_string(), expected.to_string());
                assert!(std::ptr::eq(
                    original,
                    aerobox_fingerprint::randomized::process_plan().unwrap()
                ));
            }
            eprintln!("process randomized REALITY policy rejects its fixed structure: {expected}");
            None
        }
    }
}
#[test]
#[ignore = "requires AEROBOX_TLS_PROFILE_PEER randomized REALITY three-suite exchange"]
fn randomized_production_reality_all_offered_suites_groups_exporter_and_close() {
    let Some(plan) = fixed_plan() else { return };
    assert!(!plan.groups().contains(&4588) && !plan.shares().contains(&4588));
    let original = aerobox_fingerprint::randomized::process_plan().unwrap();
    let suites: Vec<_> = plan
        .suites()
        .iter()
        .copied()
        .filter(|s| (0x1301..=0x1303).contains(s))
        .collect();
    assert!(!suites.is_empty());
    let mut connections = 0;
    for suite in suites {
        for &group in plan.shares() {
            let (mut peer, out, port) = start(&plan, suite, group, "valid", false);
            let mut socket = socket(port);
            let mut client = connection(&plan);
            assert!(client.is_reality());
            assert_eq!(
                client.reader().read(&mut [0]).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
            assert_eq!(
                client
                    .writer()
                    .write(b"pre-auth forbidden")
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::WouldBlock
            );
            handshake(&mut client, &mut socket).unwrap();
            let raw = client.inner.as_ref().unwrap();
            assert_eq!(
                raw.protocol_version(),
                Some(rustls::ProtocolVersion::TLSv1_3)
            );
            assert_eq!(
                u16::from(raw.negotiated_cipher_suite().unwrap().suite()),
                suite
            );
            assert_eq!(
                raw.alpn_protocol(),
                plan.extensions().contains(&16).then_some(b"h2".as_slice())
            );
            let rustls::Connection::Client(raw) = raw else {
                panic!("expected client")
            };
            assert_eq!(
                raw.peer_application_settings(),
                plan.extensions().contains(&17513).then_some([].as_slice())
            );
            let exporter = raw
                .export_keying_material([0; 32], LABEL, Some(CONTEXT))
                .unwrap();
            assert_eq!(
                client.negotiated_group(),
                Some(rustls::NamedGroup::from(group))
            );
            let sent: Vec<_> = (0..65537).map(|i| ((i * 17 + 3) % 251) as u8).collect();
            for chunk in sent.chunks(8192) {
                client.writer().write_all(chunk).unwrap();
                drain(&mut client, &mut socket).unwrap();
            }
            let mut response = vec![0; 36 + 65537];
            receive(&mut client, &mut socket, &mut response);
            assert_eq!(&response[..4], b"RR13");
            assert_eq!(&response[4..36], exporter);
            assert!(
                response[36..]
                    .iter()
                    .enumerate()
                    .all(|(i, b)| *b == ((i * 29 + 7) % 251) as u8)
            );
            client.send_close_notify();
            drain(&mut client, &mut socket).unwrap();
            loop {
                match client.reader().read(&mut [0]) {
                    Ok(0) => break,
                    Ok(_) => panic!("unexpected trailing data"),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        assert!(client.read_tls(&mut socket).unwrap() > 0);
                        client.process_new_packets().unwrap();
                    }
                    Err(e) => panic!("close: {e}"),
                }
            }
            assert!(
                client
                    .inner
                    .as_mut()
                    .unwrap()
                    .process_new_packets()
                    .unwrap()
                    .peer_has_closed()
            );
            let result = report(&out);
            assert_eq!(result["phase"], "complete", "{result}");
            let result = &result["result"];
            assert_eq!(result["reality_authenticated"], true);
            assert_eq!(result["suite"], suite);
            assert_eq!(result["group"], group);
            assert_eq!(result["hello_retry"], false);
            assert_eq!(
                result["alps"],
                if plan.extensions().contains(&17513) {
                    17513
                } else {
                    0
                }
            );
            assert_eq!(result["exporter"], hex(&exporter));
            assert_eq!(result["client_sha256"], digest(&sent));
            assert_eq!(result["server_sha256"], digest(&response[36..]));
            assert_eq!(result["bytes"], 65537);
            assert_eq!(result["close_notify"], true);
            assert!(peer.0.wait().unwrap().success());
            assert!(std::ptr::eq(
                original,
                aerobox_fingerprint::randomized::process_plan().unwrap()
            ));
            connections += 1;
        }
    }
    eprintln!(
        "authenticated {connections} production REALITY connections using every actual suite/initial share; no seed filtering"
    );
}
#[test]
#[ignore = "requires AEROBOX_TLS_PROFILE_PEER randomized REALITY three-suite exchange"]
fn randomized_reality_authentication_failures_deliver_no_plaintext_or_alerts() {
    let Some(plan) = fixed_plan() else { return };
    for &suite in plan
        .suites()
        .iter()
        .filter(|s| (0x1301..=0x1303).contains(*s))
    {
        for (mode, bad_finished) in [
            ("bad-hmac", false),
            ("bad-signature", false),
            ("bad-short-id", false),
            ("valid", true),
        ] {
            let (mut peer, out, port) = start(&plan, suite, 29, mode, bad_finished);
            let mut socket = socket(port);
            let mut client = connection(&plan);
            let error = handshake(&mut client, &mut socket).unwrap_err();
            if mode == "bad-short-id" {
                assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
                // The peer closes before a TLS response; this is a transport EOF,
                // not a received TLS fatal error. Plaintext remains unauthenticated.
                assert!(client.inner.is_some() && client.is_handshaking());
                assert_eq!(
                    client.reader().read(&mut [0]).unwrap_err().kind(),
                    io::ErrorKind::WouldBlock
                );
                assert_eq!(
                    client.writer().write(b"forbidden").unwrap_err().kind(),
                    io::ErrorKind::WouldBlock
                );
                let mut leaked = vec![];
                assert_eq!(client.write_tls(&mut leaked).unwrap(), 0);
                assert!(leaked.is_empty());
            } else {
                let tls = error
                    .get_ref()
                    .and_then(|e| e.downcast_ref::<rustls::Error>())
                    .expect("structured TLS authentication error");
                if bad_finished {
                    assert!(matches!(tls, rustls::Error::DecryptError), "{tls:?}");
                    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
                } else {
                    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
                    assert!(
                        matches!(
                            tls,
                            rustls::Error::InvalidCertificate(
                                rustls::CertificateError::ApplicationVerificationFailure
                            )
                        ),
                        "{tls:?}"
                    );
                }
                assert_failed_gates(&mut client, error.kind());
            }
            let _ = socket.shutdown(std::net::Shutdown::Both);
            let result = report(&out);
            assert_eq!(result["phase"], "error");
            if mode == "bad-short-id" {
                assert!(
                    result["error"]
                        .as_str()
                        .unwrap()
                        .contains("invalid authenticated REALITY metadata")
                );
            }
            assert_eq!(result["result"]["bytes"], 0);
            assert!(!peer.0.wait().unwrap().success());
        }
    }
}
fn assert_failed_gates(client: &mut TlsConnection, kind: io::ErrorKind) {
    assert!(client.inner.is_none());
    assert!(!client.wants_read() && !client.wants_write());
    assert_eq!(client.process_new_packets().unwrap_err().kind(), kind);
    assert_eq!(client.read_tls(&mut io::empty()).unwrap_err().kind(), kind);
    assert_eq!(client.feed(&[22, 3, 3, 0, 0]).unwrap_err().kind(), kind);
    assert_eq!(client.reader().read(&mut [0]).unwrap_err().kind(), kind);
    assert_eq!(client.reader().read(&mut []).unwrap_err().kind(), kind);
    assert_eq!(client.reader().fill_buf().unwrap_err().kind(), kind);
    assert_eq!(
        client.writer().write(b"forbidden").unwrap_err().kind(),
        kind
    );
    assert_eq!(client.writer().write(&[]).unwrap_err().kind(), kind);
    assert_eq!(
        client
            .writer()
            .write_vectored(&[io::IoSlice::new(b"forbidden")])
            .unwrap_err()
            .kind(),
        kind
    );
    assert_eq!(client.writer().flush().unwrap_err().kind(), kind);
    client.send_close_notify();
    let mut leaked = vec![];
    assert_eq!(client.write_tls(&mut leaked).unwrap(), 0);
    assert!(leaked.is_empty());
    assert!(!client.wants_write());
}
#[test]
#[ignore = "requires AEROBOX_TLS_PROFILE_PEER randomized REALITY three-suite exchange"]
fn randomized_reality_retry_for_noninitial_groups_is_explicitly_rejected() {
    let Some(plan) = fixed_plan() else { return };
    let groups: Vec<_> = plan
        .groups()
        .iter()
        .copied()
        .filter(|g| !plan.shares().contains(g))
        .collect();
    // Every TLS1.3 randomized plan advertises P-384 without an initial P-384 share.
    assert!(groups.contains(&24));
    for &suite in plan
        .suites()
        .iter()
        .filter(|s| (0x1301..=0x1303).contains(*s))
    {
        for &group in &groups {
            let (mut peer, out, port) = start(&plan, suite, group, "valid", false);
            let mut socket = socket(port);
            let mut client = connection(&plan);
            let error = handshake(&mut client, &mut socket).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::Unsupported);
            let tls = error
                .get_ref()
                .and_then(|e| e.downcast_ref::<rustls::Error>())
                .expect("structured REALITY retry rejection");
            assert!(
                matches!(
                    tls,
                    rustls::Error::PeerIncompatible(rustls::PeerIncompatible::RealityUnsupported)
                ),
                "{tls:?}"
            );
            assert_failed_gates(&mut client, error.kind());
            let _ = socket.shutdown(std::net::Shutdown::Both);
            let result = report(&out);
            assert_eq!(result["phase"], "error");
            assert_eq!(result["result"]["reality_authenticated"], true);
            assert_eq!(result["result"]["suite"], suite);
            assert_eq!(result["result"]["group"], group);
            assert_eq!(result["result"]["bytes"], 0);
            assert!(result["result"].get("close_notify").is_none());
            assert_eq!(result["error"], "EOF");
            assert!(!peer.0.wait().unwrap().success());
        }
    }
}
#[tokio::test]
#[ignore = "requires AEROBOX_TLS_PROFILE_PEER randomized REALITY three-suite exchange"]
async fn randomized_reality_actual_async_stream_uses_the_same_plan() {
    use crate::crypto::{CryptoTlsStream, TlsReadMode};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let Some(plan) = fixed_plan() else { return };
    for &suite in plan
        .suites()
        .iter()
        .filter(|s| (0x1301..=0x1303).contains(*s))
    {
        tokio::time::timeout(Duration::from_secs(30), async {
            let (mut peer, out, port) = start(&plan, suite, 29, "valid", false);
            let socket = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            let mut stream =
                CryptoTlsStream::handshake(socket, connection(&plan), TlsReadMode::Stream, &[])
                    .await
                    .unwrap();
            assert!(stream.is_reality());
            assert_eq!(stream.negotiated_group(), Some(rustls::NamedGroup::X25519));
            let sent: Vec<_> = (0..65537).map(|i| ((i * 17 + 3) % 251) as u8).collect();
            stream.write_all(&sent).await.unwrap();
            stream.flush().await.unwrap();
            let mut response = vec![0; 36 + 65537];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(&response[..4], b"RR13");
            assert!(
                response[36..]
                    .iter()
                    .enumerate()
                    .all(|(i, b)| *b == ((i * 29 + 7) % 251) as u8)
            );
            stream.shutdown().await.unwrap();
            assert_eq!(stream.read(&mut [0]).await.unwrap(), 0);
            let result = report(&out);
            assert_eq!(result["phase"], "complete");
            let result = &result["result"];
            assert_eq!(result["suite"], suite);
            assert_eq!(result["reality_authenticated"], true);
            assert_eq!(result["exporter"], hex(&response[4..36]));
            assert_eq!(result["client_sha256"], digest(&sent));
            assert_eq!(result["server_sha256"], digest(&response[36..]));
            assert_eq!(result["close_notify"], true);
            assert!(peer.0.wait().unwrap().success());
        })
        .await
        .unwrap();
    }
}
