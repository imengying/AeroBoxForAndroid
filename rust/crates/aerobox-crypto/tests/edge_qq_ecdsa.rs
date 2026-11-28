//! Edge85/QQ11.1 ECDSA-server TLS1.2 authentication against independent Go.
//! The Go peer deliberately does not select ALPN despite the browser offer.
use rustls::{
    ClientConfig, ClientConnection, NamedGroup, ProtocolVersion,
    client::{ApplicationSettings, ApplicationSettingsCodepoint, ClientHelloLayout},
};
use sha2::{Digest, Sha256};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
    process::{Child, Command, Stdio},
    sync::Arc,
    time::Duration,
};

const PAYLOAD: usize = 65537;
const RSA_CERT: &[u8] = include_bytes!("fixtures/rsa-cert.der");
const RSA_KEY: &[u8] = include_bytes!("fixtures/rsa-key.der");
const EC_CERT: &[u8] = include_bytes!("fixtures/ecdsa-cert.der");
const EC_KEY: &[u8] = include_bytes!("fixtures/ecdsa-key.der");

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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn client_config(
    profile: ClientHelloLayout,
    mutual: &str,
    ready: &serde_json::Value,
) -> ClientConfig {
    // Ordinary provider: do not add the Android11-specific RSA/SHA1 verifier.
    let mut provider = aerobox_crypto::provider();
    provider
        .cipher_suites
        .extend(aerobox_crypto::legacy_cbc::suites());
    provider
        .cipher_suites
        .extend(aerobox_crypto::legacy_rsa::suites());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(RSA_CERT.into()).unwrap();
    roots.add(EC_CERT.into()).unwrap();
    let builder = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .unwrap()
        .with_root_certificates(roots);
    let mut config = if mutual == "none" {
        builder.with_no_client_auth()
    } else {
        // The peer issues clientAuth EKU certificates for the existing keys;
        // their original serverAuth-only fixture certs are not used for mTLS.
        let encoded = ready["client_certificate_der_hex"]
            .as_str()
            .expect("independent peer must supply a clientAuth certificate");
        assert!(!encoded.is_empty() && encoded.len() <= 65536 && encoded.len() % 2 == 0);
        let certificate: Vec<u8> = (0..encoded.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&encoded[i..i + 2], 16).unwrap())
            .collect();
        let key = match mutual {
            "rsa" => RSA_KEY,
            "ecdsa" => EC_KEY,
            _ => unreachable!(),
        };
        builder
            .with_client_auth_cert(
                vec![certificate.into()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(key.to_vec()).into(),
            )
            .unwrap()
    };
    config.time_provider = Arc::new(FixtureTime);
    config
        .enable_legacy_tls(
            &aerobox_crypto::legacy_provider::LEGACY_TLS,
            &[
                ProtocolVersion::TLSv1_0,
                ProtocolVersion::TLSv1_1,
                ProtocolVersion::TLSv1_2,
                ProtocolVersion::TLSv1_3,
            ],
        )
        .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config.cert_compressors.clear();
    config.cert_decompressors = vec![rustls::compress::BROTLI_DECOMPRESSOR];
    if profile == ClientHelloLayout::Qq11_1 {
        config.application_settings = Some(
            ApplicationSettings::new(
                ApplicationSettingsCodepoint::Legacy,
                vec![(b"h2".to_vec(), vec![])],
            )
            .unwrap(),
        );
    }
    config.initial_key_share_groups = vec![NamedGroup::X25519];
    config.enable_tls12_renegotiation = true;
    config.client_hello_layout = Some(profile);
    config.max_fragment_size = if mutual == "none" { None } else { Some(1024) };
    config
}

fn take<'a>(input: &mut &'a [u8], length: usize) -> &'a [u8] {
    assert!(input.len() >= length, "truncated captured ClientHello");
    let (head, tail) = input.split_at(length);
    *input = tail;
    head
}

fn vector<'a>(input: &mut &'a [u8], width: usize) -> &'a [u8] {
    let size = take(input, width)
        .iter()
        .fold(0usize, |n, byte| (n << 8) | usize::from(*byte));
    take(input, size)
}

fn assert_browser_offer(mut wire: &[u8], profile: ClientHelloLayout) {
    let mut handshake = Vec::new();
    while !wire.is_empty() {
        assert_eq!(take(&mut wire, 1), [22]);
        take(&mut wire, 2); // initial compatibility record version
        handshake.extend_from_slice(vector(&mut wire, 2));
    }
    let mut data = handshake.as_slice();
    assert_eq!(take(&mut data, 1), [1]);
    let mut hello = vector(&mut data, 3);
    assert!(data.is_empty());
    assert_eq!(take(&mut hello, 2), [3, 3]);
    take(&mut hello, 32);
    vector(&mut hello, 1);
    let ciphers = vector(&mut hello, 2);
    for cipher in [0xc02bu16, 0xc02c, 0xcca9] {
        assert!(ciphers.chunks_exact(2).any(|id| id == cipher.to_be_bytes()));
    }
    assert_eq!(vector(&mut hello, 1), [0]);
    let mut extensions = vector(&mut hello, 2);
    assert!(hello.is_empty());
    let mut signature_schemes = None;
    let mut alpn = None;
    let mut alps = None;
    while !extensions.is_empty() {
        let kind = u16::from_be_bytes(take(&mut extensions, 2).try_into().unwrap());
        let value = vector(&mut extensions, 2);
        match kind {
            13 => {
                assert!(signature_schemes.is_none());
                let mut input = value;
                let names = vector(&mut input, 2);
                assert!(input.is_empty() && names.len() % 2 == 0);
                signature_schemes = Some(
                    names
                        .chunks_exact(2)
                        .map(|id| u16::from_be_bytes(id.try_into().unwrap()))
                        .collect::<Vec<_>>(),
                );
            }
            16 => {
                assert!(alpn.is_none());
                alpn = Some(value.to_vec());
            }
            17513 => {
                assert!(alps.is_none());
                alps = Some(value.to_vec());
            }
            _ => {}
        }
    }
    let signatures = signature_schemes.expect("browser signature_algorithms offer");
    assert_eq!(
        signatures,
        [
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601
        ]
    );
    assert!(
        !signatures.iter().any(|id| id >> 8 == 2),
        "browser must not advertise SHA1"
    );
    assert_eq!(
        alpn.as_deref(),
        Some(b"\x00\x0c\x02h2\x08http/1.1".as_slice())
    );
    assert_eq!(
        alps.as_deref(),
        (profile == ClientHelloLayout::Qq11_1).then_some(b"\x00\x03\x02h2".as_slice())
    );
}

fn exercise(profile: ClientHelloLayout, cipher: u16, mutual: &str) {
    eprintln!("{profile:?} TLS1.2 ECDSA server suite={cipher:04x} client-auth={mutual}");
    let mut peer = Peer(
        Command::new(
            std::env::var_os("AEROBOX_ANDROID11_PEER").expect("independent Go peer required"),
        )
        .args([
            "--version",
            "1.2",
            "--suite",
            &format!("0x{cipher:04x}"),
            "--mutual",
            mutual,
            "--bytes",
            &PAYLOAD.to_string(),
            "--fixtures",
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures"),
        ])
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
    let config = client_config(profile, mutual, &ready);
    let mut conn =
        ClientConnection::new(Arc::new(config), "localhost".try_into().unwrap()).unwrap();
    let mut first_flight = Vec::new();
    while conn.wants_write() {
        conn.write_tls(&mut first_flight).unwrap();
    }
    assert_browser_offer(&first_flight, profile);
    let mut socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    socket.write_all(&first_flight).unwrap();
    let mut stream = rustls::StreamOwned::new(conn, socket);
    let sent: Vec<_> = (0..PAYLOAD).map(|i| ((i * 17 + 3) % 251) as u8).collect();
    stream.write_all(&sent).unwrap();
    stream.flush().unwrap();
    let mut response = vec![0; 36 + PAYLOAD];
    stream.read_exact(&mut response).unwrap();
    assert_eq!(&response[..4], b"AB11");
    assert_eq!(
        stream.conn.protocol_version(),
        Some(ProtocolVersion::TLSv1_2)
    );
    assert_eq!(
        u16::from(stream.conn.negotiated_cipher_suite().unwrap().suite()),
        cipher
    );
    assert_eq!(
        stream.conn.handshake_kind(),
        Some(rustls::HandshakeKind::Full)
    );
    assert_eq!(
        stream.conn.peer_certificates().unwrap()[0].as_ref(),
        EC_CERT
    );
    assert_eq!(
        stream.conn.alpn_protocol(),
        None,
        "Go peer intentionally declines ALPN"
    );
    assert!(
        stream.conn.peer_application_settings().is_none(),
        "TLS1.2 cannot negotiate ALPS"
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
        assert_eq!(
            *actual,
            ((i * 29 + 7) % 251) as u8,
            "server payload byte {i}"
        );
    }
    stream.conn.send_close_notify();
    stream.flush().unwrap();
    let mut tail = Vec::new();
    stream.read_to_end(&mut tail).unwrap();
    assert!(tail.is_empty());
    line.clear();
    stdout.read_line(&mut line).unwrap();
    let result: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(result["phase"], "complete", "{result}");
    assert_eq!(result["version"], 0x0303u16);
    assert_eq!(result["cipher"], cipher);
    assert_eq!(result["mutual"], mutual);
    assert_eq!(result["bytes_each_direction"], PAYLOAD);
    assert_eq!(result["client_sha256"], hex(&Sha256::digest(&sent)));
    assert_eq!(
        result["server_sha256"],
        hex(&Sha256::digest(&response[36..]))
    );
    assert_eq!(result["exporter"], hex(&exporter));
    assert_eq!(result["ems"], true);
    assert_eq!(result["ocsp"], true);
    assert_eq!(result["rsa_sha1"], false);
    assert_eq!(result["resumed"], false);
    assert_eq!(result["close_notify_received"], true);
    assert_eq!(
        result["client_certificates"],
        if mutual == "none" { 0 } else { 1 }
    );
    assert_eq!(
        result["verified_client_chains"].as_u64().unwrap() > 0,
        mutual != "none"
    );
    assert!(peer.0.wait().unwrap().success());
}

#[test]
#[ignore = "requires AEROBOX_ANDROID11_PEER built from tests/reference/android11-peer"]
fn edge_qq_ecdsa_server_suites_authenticate_all_client_modes_and_transfer() {
    for profile in [ClientHelloLayout::Edge85, ClientHelloLayout::Qq11_1] {
        for cipher in [0xc02b, 0xc02c, 0xcca9] {
            for mutual in ["none", "rsa", "ecdsa"] {
                exercise(profile, cipher, mutual);
            }
        }
    }
}
