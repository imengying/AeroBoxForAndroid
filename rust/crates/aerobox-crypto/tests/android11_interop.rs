//! Real legacy handshakes against an independent Go standard-library server.
use rustls::{ClientConfig, ClientConnection, ProtocolVersion, client::ClientHelloLayout};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
    process::{Child, Command, Stdio},
    sync::Arc,
    time::Duration,
};

#[derive(Debug)]
struct FixtureTime;
impl rustls::time_provider::TimeProvider for FixtureTime {
    fn current_time(&self) -> Option<rustls::pki_types::UnixTime> {
        Some(rustls::pki_types::UnixTime::since_unix_epoch(
            Duration::from_secs(1893456000),
        ))
    }
}

struct Peer(Child);
impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct TappedTcp {
    socket: TcpStream,
    written: Vec<u8>,
}
impl Read for TappedTcp {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        self.socket.read(output)
    }
}
impl Write for TappedTcp {
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        let n = self.socket.write(input)?;
        assert!(self.written.len() + n <= 2 * 1024 * 1024);
        self.written.extend_from_slice(&input[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.socket.flush()
    }
}

const PAYLOAD: usize = 65537;
const RSA_CERT: &[u8] = include_bytes!("fixtures/rsa-cert.der");
const RSA_KEY: &[u8] = include_bytes!("fixtures/rsa-key.der");
const EC_CERT: &[u8] = include_bytes!("fixtures/ecdsa-cert.der");
const EC_KEY: &[u8] = include_bytes!("fixtures/ecdsa-key.der");

fn exercise(
    version: &str,
    cipher: u16,
    mutual: &str,
    sha1: bool,
    profile: bool,
    restricted: bool,
    mixed: bool,
) {
    let mut command = Command::new(
        std::env::var_os("AEROBOX_ANDROID11_PEER").expect("independent Go peer required"),
    );
    command.args([
        "--version",
        version,
        "--suite",
        &format!("0x{cipher:04x}"),
        "--mutual",
        mutual,
        "--fixtures",
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures"),
    ]);
    if sha1 {
        command.arg("--rsa-sha1");
    }
    let mut peer = Peer(
        command
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let mut stdout = BufReader::new(peer.0.stdout.take().unwrap());
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let ready: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(ready["phase"], "ready", "{ready}");
    let port = u16::try_from(ready["port"].as_u64().unwrap()).unwrap();
    let version_id = match version {
        "1.0" => ProtocolVersion::TLSv1_0,
        "1.1" => ProtocolVersion::TLSv1_1,
        "1.2" => ProtocolVersion::TLSv1_2,
        _ => unreachable!(),
    };
    let mut provider = aerobox_crypto::legacy_provider::provider();
    if mixed {
        provider.cipher_suites.extend(
            aerobox_crypto::provider()
                .cipher_suites
                .into_iter()
                .filter(|s| s.tls13().is_some()),
        );
    }
    if !profile && !mixed {
        provider
            .cipher_suites
            .extend(aerobox_crypto::legacy_cbc::suites());
        provider
            .cipher_suites
            .retain(|suite| u16::from(suite.suite()) == cipher);
    }
    let mut roots = rustls::RootCertStore::empty();
    roots.add(RSA_CERT.into()).unwrap();
    roots.add(EC_CERT.into()).unwrap();
    let builder = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap()
        .with_root_certificates(roots);
    let client_certificate = if mutual != "none" {
        let hex = ready["client_certificate_der_hex"]
            .as_str()
            .expect("test-only clientAuth certificate");
        assert!(hex.len() <= 65536 && hex.len() % 2 == 0);
        Some(
            (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect::<Vec<_>>(),
        )
    } else {
        None
    };
    let mut config = match mutual {
        "rsa" => builder
            .with_client_auth_cert(
                vec![client_certificate.unwrap().into()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(RSA_KEY.to_vec()).into(),
            )
            .unwrap(),
        "ecdsa" => builder
            .with_client_auth_cert(
                vec![client_certificate.unwrap().into()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(EC_KEY.to_vec()).into(),
            )
            .unwrap(),
        "none" => builder.with_no_client_auth(),
        _ => unreachable!(),
    };
    config.time_provider = Arc::new(FixtureTime);
    config.cert_compressors.clear();
    config.cert_decompressors.clear();
    let versions = if mixed {
        vec![
            ProtocolVersion::TLSv1_0,
            ProtocolVersion::TLSv1_1,
            ProtocolVersion::TLSv1_2,
            ProtocolVersion::TLSv1_3,
        ]
    } else if restricted {
        vec![version_id]
    } else {
        vec![
            ProtocolVersion::TLSv1_0,
            ProtocolVersion::TLSv1_1,
            ProtocolVersion::TLSv1_2,
        ]
    };
    config
        .enable_legacy_tls(&aerobox_crypto::legacy_provider::LEGACY_TLS, &versions)
        .unwrap();
    if mixed {
        config.alpn_protocols = vec![b"h2".to_vec()];
        config.application_settings = Some(
            rustls::client::ApplicationSettings::new(
                rustls::client::ApplicationSettingsCodepoint::Legacy,
                vec![(b"h2".to_vec(), Vec::new())],
            )
            .unwrap(),
        );
        config.initial_key_share_groups = vec![rustls::NamedGroup::X25519];
    }
    if profile {
        config.client_hello_layout = Some(ClientHelloLayout::Android11);
    }
    config.max_fragment_size = if mutual == "none" { None } else { Some(1024) };
    let socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let conn = ClientConnection::new(Arc::new(config), "localhost".try_into().unwrap()).unwrap();
    let mut stream = rustls::StreamOwned::new(
        conn,
        TappedTcp {
            socket,
            written: Vec::new(),
        },
    );
    let sent: Vec<u8> = (0..PAYLOAD).map(|i| ((i * 17 + 3) % 251) as u8).collect();
    stream.write_all(&sent).unwrap();
    stream.flush().unwrap();
    let mut response = vec![0; 36 + PAYLOAD];
    stream.read_exact(&mut response).unwrap();
    assert_eq!(&response[..4], b"AB11");
    assert_eq!(stream.conn.protocol_version(), Some(version_id));
    assert_eq!(
        u16::from(stream.conn.negotiated_cipher_suite().unwrap().suite()),
        cipher
    );
    assert_eq!(stream.conn.alpn_protocol(), None);
    assert_eq!(
        stream.conn.handshake_kind(),
        Some(rustls::HandshakeKind::Full)
    );
    let exporter = stream
        .conn
        .export_keying_material(
            vec![0; 32],
            b"aerobox android11 exporter",
            Some(b"\0android11\0"),
        )
        .unwrap();
    assert_eq!(&response[4..36], exporter.as_slice());
    for (i, actual) in response[36..].iter().enumerate() {
        assert_eq!(*actual, ((i * 29 + 7) % 251) as u8, "byte {i}");
    }
    stream.conn.send_close_notify();
    stream.flush().unwrap();
    let mut tail = Vec::new();
    stream.read_to_end(&mut tail).unwrap();
    assert!(tail.is_empty());
    let mut wire = stream.sock.written.as_slice();
    let mut application_lengths = Vec::new();
    while !wire.is_empty() {
        assert!(wire.len() >= 5);
        let size = usize::from(u16::from_be_bytes([wire[3], wire[4]]));
        assert!(wire.len() >= 5 + size);
        if wire[0] == 23 {
            assert_eq!(
                u16::from_be_bytes([wire[1], wire[2]]),
                u16::from(version_id)
            );
            application_lengths.push(size);
        }
        wire = &wire[5 + size..];
    }
    assert!(!application_lengths.is_empty());
    if version_id == ProtocolVersion::TLSv1_0 {
        // One byte + SHA1 MAC + TLS padding = 32 encrypted bytes, no explicit IV.
        assert_eq!(application_lengths[0], 32, "TLS1.0 1/n-1 split");
        assert!(application_lengths.len() > 1);
    }

    line.clear();
    stdout.read_line(&mut line).unwrap();
    let result: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(result["phase"], "complete", "{result}");
    assert_eq!(result["version"], u16::from(version_id));
    assert_eq!(result["cipher"], cipher);
    assert_eq!(result["ems"], true);
    assert_eq!(result["ocsp"], true);
    assert_eq!(result["resumed"], false);
    assert_eq!(result["close_notify_received"], true);
    assert_eq!(
        result["client_certificates"],
        if mutual == "none" { 0 } else { 1 }
    );
    assert!(peer.0.wait().unwrap().success());
}

#[test]
#[ignore = "requires AEROBOX_ANDROID11_PEER built from tests/reference/android11-peer"]
fn every_android11_cipher_authenticates_and_transfers_with_independent_go() {
    for version in ["1.0", "1.1"] {
        for cipher in [0xc013, 0xc014, 0x002f, 0x0035] {
            for mutual in ["none", "rsa", "ecdsa"] {
                exercise(version, cipher, mutual, false, true, false, false);
            }
        }
    }
    for cipher in [
        0xc02b, 0xc02c, 0xcca9, 0xc02f, 0xc030, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f,
        0x0035,
    ] {
        for mutual in ["none", "rsa", "ecdsa"] {
            exercise("1.2", cipher, mutual, false, true, false, false);
        }
    }
    for cipher in [0xc013, 0xc014, 0xc02f, 0xc030, 0xcca8] {
        exercise("1.2", cipher, "rsa", true, true, false, false);
    }
}

#[test]
#[ignore = "requires AEROBOX_ANDROID11_PEER built from tests/reference/android11-peer"]
fn explicit_old_versions_preserve_rsa_premaster_version_and_ecdsa_signatures() {
    for version in ["1.0", "1.1"] {
        for cipher in [0xc009, 0xc00a, 0x002f, 0x0035] {
            exercise(version, cipher, "ecdsa", false, false, true, false);
        }
    }
}

#[test]
#[ignore = "requires AEROBOX_ANDROID11_PEER built from tests/reference/android11-peer"]
fn mixed_tls10_through_tls13_offer_can_authenticate_old_versions() {
    for version in ["1.0", "1.1", "1.2"] {
        for cipher in [0xc013, 0xc014, 0x002f, 0x0035] {
            for mutual in ["rsa", "ecdsa"] {
                exercise(version, cipher, mutual, false, false, false, true);
            }
        }
    }
    for cipher in [0xc02b, 0xc02f, 0xcca8] {
        exercise("1.2", cipher, "none", false, false, false, true);
    }
}
