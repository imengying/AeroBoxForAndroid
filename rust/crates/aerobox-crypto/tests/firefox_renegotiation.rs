//! Firefox120 TLS1.2 renegotiation against an independent RFC5746 peer.
#[path = "support/firefox.rs"]
mod support;
use rustls::{ClientConnection, ProtocolVersion, client::ClientHelloLayout};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
    process::{Child, ChildStdout, Command, Stdio},
    sync::Arc,
    time::Duration,
};
const PROFILES: [ClientHelloLayout; 1] = [ClientHelloLayout::Firefox120];
const VERSIONS: [(&str, ProtocolVersion); 1] = [("1.2", ProtocolVersion::TLSv1_2)];
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
fn peer(mode: &str, version: &str, suite: u16, mutual: bool) -> (Peer, TcpStream) {
    let mut cmd = Command::new(std::env::var_os("AEROBOX_LEGACY_RENEGOTIATION_PEER").unwrap());
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
fn client(profile: ClientHelloLayout, mutual: bool) -> ClientConnection {
    assert_eq!(profile, ClientHelloLayout::Firefox120);
    let mut cfg = support::config(mutual, false);
    cfg.max_fragment_size = Some(137);
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

fn assert_cached_layout(path: &std::path::Path) {
    let hellos: Vec<String> = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(hellos.len(), 2);
    fn parse(s: &str) -> (Vec<u8>, Vec<(u16, Vec<u8>)>) {
        let bytes: Vec<u8> = s
            .as_bytes()
            .chunks_exact(2)
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect();
        let mut i = 38;
        i += 1 + bytes[i] as usize;
        let n = u16::from_be_bytes(bytes[i..i + 2].try_into().unwrap()) as usize;
        assert!(
            !bytes[i + 2..i + 2 + n]
                .chunks_exact(2)
                .any(|id| id == [0, 255])
        );
        i += 2 + n;
        i += 1 + bytes[i] as usize;
        let prefix = bytes[4..i].to_vec();
        let total = u16::from_be_bytes(bytes[i..i + 2].try_into().unwrap()) as usize;
        i += 2;
        assert_eq!(i + total, bytes.len());
        let mut exts = vec![];
        while i < bytes.len() {
            let t = u16::from_be_bytes(bytes[i..i + 2].try_into().unwrap());
            let n = u16::from_be_bytes(bytes[i + 2..i + 4].try_into().unwrap()) as usize;
            i += 4;
            exts.push((t, bytes[i..i + n].to_vec()));
            i += n;
        }
        let padding = exts
            .iter()
            .find(|(t, _)| *t == 21)
            .map(|(_, p)| {
                assert!(p.iter().all(|b| *b == 0));
                p.len() + 4
            })
            .unwrap_or(0);
        assert_eq!(padding, 0, "Firefox has no padding extension");
        assert_eq!(exts.iter().find(|(t, _)| *t == 28).unwrap().1, [0x40, 1]);
        assert_eq!(
            exts.iter().find(|(t, _)| *t == 34).unwrap().1,
            [0, 8, 4, 3, 5, 3, 6, 3, 2, 3]
        );
        (prefix, exts)
    }
    let (a, mut ax) = parse(&hellos[0]);
    let (b, mut bx) = parse(&hellos[1]);
    assert_eq!(a, b, "cached public random/session/ciphers");
    assert_eq!(ax.iter().find(|(t, _)| *t == 65281).unwrap().1, [0]);
    let binding = &bx.iter().find(|(t, _)| *t == 65281).unwrap().1;
    assert_eq!(binding.len(), 13);
    assert_eq!(binding[0], 12);
    ax.retain(|(t, _)| ![65281, 21].contains(t));
    bx.retain(|(t, _)| ![65281, 21].contains(t));
    assert_eq!(
        ax, bx,
        "fixed order, DC/RSL, ECH and real public shares are retained"
    );
}
fn exercise(
    profile: ClientHelloLayout,
    version: &str,
    expected_version: ProtocolVersion,
    suite: u16,
    mutual: bool,
    mode: &str,
) {
    eprintln!("{profile:?} TLS{version} {suite:04x} mutual={mutual} {mode}");
    let (mut peer, socket) = peer(mode, version, suite, mutual);
    let mut stream = rustls::StreamOwned::new(client(profile, mutual), socket);
    let old = marker(&mut stream, "initial").unwrap();
    if mode.starts_with("inflight") {
        let mut data = [0; 8];
        stream.read_exact(&mut data).unwrap();
        assert_eq!(&data, b"old-data");
    }
    let new = marker(&mut stream, "renewed").unwrap();
    assert_ne!(old, new);
    assert!(!stream.conn.is_handshaking());
    assert_eq!(stream.conn.protocol_version(), Some(expected_version));
    assert_eq!(
        u16::from(stream.conn.negotiated_cipher_suite().unwrap().suite()),
        suite
    );
    assert!(stream.conn.peer_application_settings().is_none());
    let sent: Vec<_> = (0..65537).map(|n| (n % 251) as u8).collect();
    stream.write_all(&sent).unwrap();
    stream.flush().unwrap();
    let mut received = vec![0; sent.len()];
    stream.read_exact(&mut received).unwrap();
    assert_eq!(sent, received);
    stream.conn.send_close_notify();
    stream.flush().unwrap();
    assert_eq!(stream.read(&mut [0]).unwrap(), 0);
    let mut line = String::new();
    peer.stdout.read_line(&mut line).unwrap();
    let terminal: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(terminal["phase"], "complete", "{terminal}");
    assert!(peer.child.wait().unwrap().success());
    assert_cached_layout(&peer.hellos);
}
#[test]
#[ignore = "requires independent AEROBOX_LEGACY_RENEGOTIATION_PEER"]
fn firefox_tls12_renegotiation_changes_keys_and_authenticates_both_peers() {
    for profile in PROFILES {
        for (version, protocol) in VERSIONS {
            for mutual in [false, true] {
                for suite in [0xc013, 0xc014, 0x002f, 0x0035] {
                    exercise(profile, version, protocol, suite, mutual, "valid");
                }
                if protocol == ProtocolVersion::TLSv1_2 {
                    for suite in [0xc02f, 0xc030, 0x009c, 0x009d, 0xcca8] {
                        exercise(profile, version, protocol, suite, mutual, "valid");
                    }
                }
            }
        }
    }
}
#[test]
#[ignore = "requires independent AEROBOX_LEGACY_RENEGOTIATION_PEER"]
fn firefox_tls12_fragmentation_old_epoch_data_and_consistent_no_ems() {
    for profile in PROFILES {
        for (version, protocol) in VERSIONS {
            for mode in ["inflight", "fragment", "inflight-fragment", "no-ems"] {
                exercise(profile, version, protocol, 0xc013, true, mode);
            }
        }
    }
}
#[test]
#[ignore = "requires independent AEROBOX_LEGACY_RENEGOTIATION_PEER"]
fn firefox_tls12_rejects_unauthenticated_and_changed_renegotiation_permanently() {
    for profile in PROFILES {
        for (version, _) in VERSIONS {
            for mode in [
                "bad-binding",
                "bad-server-binding",
                "short-binding",
                "omit-binding",
                "initial-nonempty",
                "initial-no-binding",
                "changed-certificate",
                "changed-alpn",
                "changed-version",
                "ems-downgrade",
                "bad-finished",
                "early-data",
                "repeat",
            ] {
                eprintln!("{profile:?} TLS{version} reject {mode}");
                let (mut peer, socket) = peer(mode, version, 0xc013, false);
                let mut stream = rustls::StreamOwned::new(client(profile, false), socket);
                let result = (|| {
                    marker(&mut stream, "initial")?;
                    marker(&mut stream, "renewed")?;
                    if mode == "repeat" {
                        stream.read_exact(&mut [0])?;
                    }
                    Ok::<_, std::io::Error>(())
                })();
                let error = result.expect_err(mode);
                assert!(
                    !matches!(
                        error.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                    ),
                    "timeout does not prove rejection: {mode}: {error}"
                );
                if matches!(mode, "initial-no-binding" | "repeat") {
                    // RFC5746 permits refusing HelloRequest with a warning.
                    // The peer must observe that alert; EOF alone is no proof.
                    let mut line = String::new();
                    peer.stdout.read_line(&mut line).unwrap();
                    let terminal: serde_json::Value = serde_json::from_str(&line).unwrap();
                    assert_eq!(terminal["phase"], "error");
                    assert!(
                        terminal["error"]
                            .as_str()
                            .unwrap()
                            .contains("no renegotiation"),
                        "{terminal}"
                    );
                    assert_eq!(
                        terminal["completed_handshakes"],
                        if mode == "repeat" { 2 } else { 1 }
                    );
                    let hellos: Vec<String> =
                        serde_json::from_slice(&std::fs::read(&peer.hellos).unwrap()).unwrap();
                    assert_eq!(hellos.len(), if mode == "repeat" { 2 } else { 1 });
                    assert!(stream.conn.process_new_packets().is_ok());
                    continue;
                }
                let expected = match mode {
                    "changed-certificate" => "certificate changed",
                    "changed-alpn" => "changed ALPN",
                    "changed-version" => "cannot change protocol version",
                    "initial-nonempty" => "must be empty",
                    "bad-finished" => "decrypt",
                    "early-data" => "ApplicationData",
                    _ => "previous Finished binding",
                };
                assert!(error.to_string().contains(expected), "{mode}: {error}");
                let failure = stream.conn.process_new_packets().unwrap_err();
                assert_eq!(stream.conn.process_new_packets().unwrap_err(), failure);
                assert!(stream.conn.reader().read(&mut [0]).is_err());
            }
        }
    }
}
