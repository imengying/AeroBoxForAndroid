//! Independent TLS 1.2 epoch change, RFC5746 binding and client-authentication tests.
use rustls::{
    ClientConfig, ClientConnection, RootCertStore,
    client::{ApplicationSettings, ApplicationSettingsCodepoint, ClientHelloLayout},
    pki_types::UnixTime,
    time_provider::TimeProvider,
};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
    process::{Child, Command, Stdio},
    sync::Arc,
    time::Duration,
};
#[path = "../../../vendor/shoes/src/crypto/rustcrypto_kx.rs"]
mod production_hybrid;
#[derive(Debug)]
struct FixedTime;
impl TimeProvider for FixedTime {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(Duration::from_secs(1893456000)))
    }
}
struct Peer {
    child: Child,
    hellos: std::path::PathBuf,
}
impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.hellos);
    }
}
fn peer(mode: &str, suite: u16, mutual: bool) -> (Peer, TcpStream) {
    let mut cmd = Command::new(
        std::env::var_os("AEROBOX_TLS12_RENEGOTIATION_PEER")
            .expect("AEROBOX_TLS12_RENEGOTIATION_PEER"),
    );
    cmd.args([
        "-fixtures",
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures"),
        "-mode",
        mode,
        "-suite",
        &suite.to_string(),
    ]);
    if mutual {
        cmd.arg("-mutual");
    }
    if mode == "resumed" {
        cmd.arg("-resume-first");
    }
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let hellos = std::env::temp_dir().join(format!(
        "aerobox-reneg-{}-{}.json",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    cmd.arg("-hellos").arg(&hellos);
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let ready: serde_json::Value = serde_json::from_str(&line).unwrap();
    let socket = TcpStream::connect(("127.0.0.1", ready["port"].as_u64().unwrap() as u16)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    (Peer { child, hellos }, socket)
}
fn config(enabled: bool, chrome: bool, mutual: bool) -> ClientConfig {
    let mut roots = RootCertStore::empty();
    roots
        .add(include_bytes!("fixtures/rsa-cert.der").as_slice().into())
        .unwrap();
    let mut provider = aerobox_crypto::provider();
    provider
        .cipher_suites
        .extend(aerobox_crypto::legacy_cbc::suites());
    provider
        .cipher_suites
        .extend(aerobox_crypto::legacy_rsa::suites());
    provider.kx_groups.insert(
        0,
        production_hybrid::group(rustls::NamedGroup::X25519MLKEM768),
    );
    let builder = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots);
    let mut config = if mutual {
        builder
            .with_client_auth_cert(
                vec![include_bytes!("fixtures/rsa-cert.der").as_slice().into()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(
                    include_bytes!("fixtures/rsa-key.der").to_vec(),
                )
                .into(),
            )
            .unwrap()
    } else {
        builder.with_no_client_auth()
    };
    config.time_provider = Arc::new(FixedTime);
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config.enable_tls12_renegotiation = enabled;
    config.max_fragment_size = Some(137);
    if chrome {
        config.application_settings = Some(
            ApplicationSettings::new(
                ApplicationSettingsCodepoint::Chrome,
                vec![(b"h2".to_vec(), vec![])],
            )
            .unwrap(),
        );
        config.initial_key_share_groups = vec![
            rustls::NamedGroup::X25519MLKEM768,
            rustls::NamedGroup::X25519,
        ];
        config.client_hello_layout = Some(ClientHelloLayout::Chrome133);
    }
    config
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
#[test]
#[ignore = "requires independent AEROBOX_TLS12_RENEGOTIATION_PEER"]
fn authenticated_tls12_renegotiation_changes_keys_and_supports_client_auth() {
    for chrome in [false, true] {
        for mutual in [false, true] {
            for suite in [0xc02f, 0xc013, 0x009c, 0x002f, 0xcca8] {
                let (mut peer, socket) = peer("valid", suite, mutual);
                let client = ClientConnection::new(
                    Arc::new(config(true, chrome, mutual)),
                    "localhost".try_into().unwrap(),
                )
                .unwrap();
                let mut stream = rustls::StreamOwned::new(client, socket);
                let old = marker(&mut stream, "initial").unwrap();
                let new = marker(&mut stream, "renewed").unwrap();
                assert_ne!(old, new);
                assert!(!stream.conn.is_handshaking());
                assert_eq!(
                    stream.conn.protocol_version(),
                    Some(rustls::ProtocolVersion::TLSv1_2)
                );
                assert!(stream.conn.peer_application_settings().is_none());
                for size in [1, 16384, 65537] {
                    let sent: Vec<_> = (0..size).map(|n| (n % 251) as u8).collect();
                    stream.write_all(&sent).unwrap();
                    stream.flush().unwrap();
                    let mut received = vec![0; size];
                    stream.read_exact(&mut received).unwrap();
                    assert_eq!(sent, received);
                }
                stream.conn.send_close_notify();
                stream.flush().unwrap();
                assert_eq!(stream.read(&mut [0]).unwrap(), 0);
                assert!(peer.child.wait().unwrap().success());
                if chrome {
                    assert_cached_layout(&peer.hellos);
                }
            }
        }
    }
}
#[test]
#[ignore = "requires independent AEROBOX_TLS12_RENEGOTIATION_PEER"]
fn tls12_renegotiation_refuses_changed_binding_certificate_and_alpn() {
    for chrome in [false, true] {
        for mode in [
            "bad-binding",
            "short-binding",
            "omit-binding",
            "initial-nonempty",
            "changed-certificate",
            "changed-alpn",
            "ems-downgrade",
            "bad-finished",
            "early-data",
        ] {
            let (_peer, socket) = peer(mode, 0xc02f, false);
            let client = ClientConnection::new(
                Arc::new(config(true, chrome, false)),
                "localhost".try_into().unwrap(),
            )
            .unwrap();
            let mut stream = rustls::StreamOwned::new(client, socket);
            let result = (|| {
                marker(&mut stream, "initial")?;
                marker(&mut stream, "renewed")?;
                Ok::<_, std::io::Error>(())
            })();
            let error = result.expect_err(mode);
            let error = error.to_string();
            let expected = match mode {
                "changed-certificate" => "certificate changed",
                "changed-alpn" => "changed ALPN",
                "initial-nonempty" => "must be empty",
                "bad-finished" => "decrypt",
                "early-data" => "ApplicationData",
                _ => "previous Finished binding",
            };
            assert!(error.contains(expected), "mode={mode} error={error}");
            assert!(stream.conn.process_new_packets().is_err());
            assert!(stream.conn.reader().read(&mut [0]).is_err());
        }
    }
}
#[test]
#[ignore = "requires independent AEROBOX_TLS12_RENEGOTIATION_PEER"]
fn tls12_renegotiation_is_opt_in_secure_and_limited_to_once() {
    for (enabled, mode, finish_one) in [
        (false, "valid", false),
        (true, "initial-no-binding", false),
        (true, "repeat", true),
    ] {
        let (_peer, socket) = peer(mode, 0xc02f, false);
        let client = ClientConnection::new(
            Arc::new(config(enabled, true, false)),
            "localhost".try_into().unwrap(),
        )
        .unwrap();
        let mut stream = rustls::StreamOwned::new(client, socket);
        marker(&mut stream, "initial").unwrap();
        if finish_one {
            marker(&mut stream, "renewed").unwrap();
        }
        let mut out = [0];
        assert!(stream.read(&mut out).is_err());
        assert_eq!(out, [0]);
    }
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
        i += 2 + n;
        i += 1 + bytes[i] as usize;
        let prefix = bytes[4..i].to_vec();
        let total = u16::from_be_bytes(bytes[i..i + 2].try_into().unwrap()) as usize;
        i += 2;
        assert_eq!(i + total, bytes.len());
        let mut extensions = vec![];
        while i < bytes.len() {
            let t = u16::from_be_bytes(bytes[i..i + 2].try_into().unwrap());
            let n = u16::from_be_bytes(bytes[i + 2..i + 4].try_into().unwrap()) as usize;
            i += 4;
            extensions.push((t, bytes[i..i + n].to_vec()));
            i += n;
        }
        (prefix, extensions)
    }
    let (a, mut ax) = parse(&hellos[0]);
    let (b, mut bx) = parse(&hellos[1]);
    assert_eq!(
        a, b,
        "pinned Chrome keeps the public random/session ID/cipher list"
    );
    let x = ax.iter().find(|(t, _)| *t == 65281).unwrap();
    assert_eq!(x.1, [0]);
    let y = bx.iter().find(|(t, _)| *t == 65281).unwrap();
    assert_eq!(y.1.len(), 13);
    assert_eq!(y.1[0], 12);
    ax.retain(|(t, _)| *t != 65281);
    bx.retain(|(t, _)| *t != 65281);
    assert_eq!(
        ax, bx,
        "extension order, GREASE and public key shares remain stable"
    );
}
#[test]
#[ignore = "requires independent AEROBOX_TLS12_RENEGOTIATION_PEER"]
fn renegotiation_accepts_old_epoch_data_and_fragmented_records() {
    for chrome in [false, true] {
        for mode in ["inflight", "fragment", "no-ems"] {
            let (_peer, socket) = peer(mode, 0xc013, true);
            let client = ClientConnection::new(
                Arc::new(config(true, chrome, true)),
                "localhost".try_into().unwrap(),
            )
            .unwrap();
            let mut stream = rustls::StreamOwned::new(client, socket);
            let old = marker(&mut stream, "initial").unwrap();
            if mode == "inflight" {
                let mut old_data = [0; 8];
                stream.read_exact(&mut old_data).unwrap();
                assert_eq!(&old_data, b"old-data");
            }
            let new = marker(&mut stream, "renewed").unwrap();
            assert_ne!(old, new);
            if mode == "no-ems" {
                assert!(
                    stream
                        .conn
                        .export_keying_material(vec![0; 32], b"test", None)
                        .is_err()
                );
            }
            let sent = vec![42; 65537];
            stream.write_all(&sent).unwrap();
            stream.flush().unwrap();
            let mut out = vec![0; sent.len()];
            stream.read_exact(&mut out).unwrap();
            assert_eq!(out, sent);
            stream.conn.send_close_notify();
            stream.flush().unwrap();
            assert_eq!(stream.read(&mut [0]).unwrap(), 0);
        }
    }
}
#[test]
#[ignore = "requires independent AEROBOX_TLS12_RENEGOTIATION_PEER"]
fn tls12_ticket_resumption_then_full_renegotiation_authenticates_again() {
    for chrome in [false, true] {
        let (_peer, socket) = peer("resumed", 0xc02f, true);
        let addr = socket.peer_addr().unwrap();
        let cfg = Arc::new(config(true, chrome, true));
        let client = ClientConnection::new(cfg.clone(), "localhost".try_into().unwrap()).unwrap();
        let mut stream = rustls::StreamOwned::new(client, socket);
        marker(&mut stream, "initial").unwrap();
        assert_eq!(
            stream.conn.handshake_kind(),
            Some(rustls::HandshakeKind::Full)
        );
        stream.conn.send_close_notify();
        stream.flush().unwrap();
        assert_eq!(stream.read(&mut [0]).unwrap(), 0);
        let socket = TcpStream::connect(addr).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let client = ClientConnection::new(cfg, "localhost".try_into().unwrap()).unwrap();
        let mut stream = rustls::StreamOwned::new(client, socket);
        marker(&mut stream, "initial").unwrap();
        assert_eq!(
            stream.conn.handshake_kind(),
            Some(rustls::HandshakeKind::Resumed)
        );
        marker(&mut stream, "renewed").unwrap();
        assert_eq!(
            stream.conn.handshake_kind(),
            Some(rustls::HandshakeKind::Full)
        );
        stream.write_all(b"resumed then renewed").unwrap();
        stream.flush().unwrap();
        let mut out = [0; 20];
        stream.read_exact(&mut out).unwrap();
        assert_eq!(&out, b"resumed then renewed");
    }
}
