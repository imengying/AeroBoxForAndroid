//! Full Android `ios` fingerprint with TLS1.2 SHA2-CBC negotiation.
//! Real authenticated TLS1.2 against a pinned independent uTLS/Go reference.
use rustls::{ClientConfig, ClientConnection, ProtocolVersion};
use sha2::{Digest, Sha256};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
    process::{Child, ChildStdout, Command, Stdio},
    sync::Arc,
    time::Duration,
};

const SUITES: [u16; 6] = [0xc023, 0xc024, 0xc027, 0xc028, 0x003c, 0x003d];
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
fn start(cipher: u16, mutual: &str) -> (Peer, BufReader<ChildStdout>, serde_json::Value) {
    let mut peer = Peer(
        Command::new(std::env::var_os("AEROBOX_ANDROID_BROWSER_CBC_PEER").expect("reference peer"))
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
    let mut output = BufReader::new(peer.0.stdout.take().unwrap());
    let mut line = String::new();
    output.read_line(&mut line).unwrap();
    let ready: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(ready["phase"], "ready", "{ready}");
    (peer, output, ready)
}
fn config(_cipher: u16, mutual: &str, ready: &serde_json::Value, wrong_root: bool) -> ClientConfig {
    let provider =
        aerobox_crypto::android_browser::provider(aerobox_crypto::android_browser::Profile::Ios14);
    let mut roots = rustls::RootCertStore::empty();
    if wrong_root {
        // Distinct issuer name avoids confusing an unsupported-signature error
        // with an unknown issuer when the RSA and P256 fixtures share a subject.
        roots
            .add(include_bytes!("fixtures/p521-ca.der").as_slice().into())
            .unwrap();
    } else {
        roots.add(RSA_CERT.into()).unwrap();
        roots.add(EC_CERT.into()).unwrap();
    }
    let builder = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .unwrap()
        .with_root_certificates(roots);
    let mut config = if mutual == "none" {
        builder.with_no_client_auth()
    } else {
        let text = ready["client_certificate_der_hex"].as_str().unwrap();
        assert!(!text.is_empty() && text.len() <= 65536 && text.len() % 2 == 0);
        let certificate: Vec<u8> = (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect();
        let key = if mutual == "rsa" { RSA_KEY } else { EC_KEY };
        builder
            .with_client_auth_cert(
                vec![certificate.into()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(key.to_vec()).into(),
            )
            .unwrap()
    };
    config
        .enable_legacy_tls(
            &aerobox_crypto::legacy_tdes::LEGACY_TLS_WITH_TDES,
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
    config.cert_decompressors.clear();
    config.initial_key_share_groups = vec![rustls::NamedGroup::X25519];
    config.enable_tls12_renegotiation = true;
    config.client_hello_layout = Some(rustls::client::ClientHelloLayout::Ios14);
    config.time_provider = Arc::new(FixtureTime);
    config.max_fragment_size = (mutual != "none").then_some(1024);
    config
}
fn socket(ready: &serde_json::Value) -> TcpStream {
    let port = u16::try_from(ready["port"].as_u64().unwrap()).unwrap();
    let socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    socket
}
fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn exercise(cipher: u16, mutual: &str) {
    eprintln!("Android browser SHA2-CBC suite={cipher:04x} client-auth={mutual}");
    let (mut peer, mut output, ready) = start(cipher, mutual);
    let connection = ClientConnection::new(
        Arc::new(config(cipher, mutual, &ready, false)),
        "localhost".try_into().unwrap(),
    )
    .unwrap();
    let mut stream = rustls::StreamOwned::new(connection, socket(&ready));
    let sent: Vec<u8> = (0..PAYLOAD).map(|i| ((i * 17 + 3) % 251) as u8).collect();
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
        if matches!(cipher, 0xc023 | 0xc024) {
            EC_CERT
        } else {
            RSA_CERT
        }
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
    for (i, byte) in response[36..].iter().enumerate() {
        assert_eq!(*byte, ((i * 29 + 7) % 251) as u8, "payload byte {i}");
    }
    stream.conn.send_close_notify();
    stream.flush().unwrap();
    let mut tail = Vec::new();
    stream.read_to_end(&mut tail).unwrap();
    assert!(tail.is_empty());
    let mut line = String::new();
    output.read_line(&mut line).unwrap();
    let result: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(result["phase"], "complete", "{result}");
    assert_eq!(result["version"], 0x0303);
    assert_eq!(result["cipher"], cipher);
    assert_eq!(result["mutual"], mutual);
    assert_eq!(result["bytes_each_direction"], PAYLOAD);
    assert_eq!(result["client_sha256"], hex(&Sha256::digest(&sent)));
    assert_eq!(
        result["server_sha256"],
        hex(&Sha256::digest(&response[36..]))
    );
    assert_eq!(result["exporter"], hex(&exporter));
    for key in ["ems", "ocsp", "close_notify_received"] {
        assert_eq!(result[key], true);
    }
    assert_eq!(result["resumed"], false);
    assert_eq!(result["client_certificates"], usize::from(mutual != "none"));
    assert_eq!(
        result["verified_client_chains"].as_u64().unwrap() > 0,
        mutual != "none"
    );
    assert!(peer.0.wait().unwrap().success());
}

#[test]
#[ignore = "requires AEROBOX_ANDROID_BROWSER_CBC_PEER"]
fn all_six_suites_authenticate_exchange_data_and_verify_client_certificates() {
    for cipher in SUITES {
        for mutual in ["none", "rsa", "ecdsa"] {
            exercise(cipher, mutual);
        }
    }
}

#[test]
#[ignore = "requires AEROBOX_ANDROID_BROWSER_CBC_PEER"]
fn all_six_suites_reject_wrong_server_identity_and_untrusted_certificates() {
    for cipher in SUITES {
        for wrong_root in [false, true] {
            let (_peer, _output, ready) = start(cipher, "none");
            let name = if wrong_root {
                "localhost"
            } else {
                "unrelated.test"
            };
            let mut connection = ClientConnection::new(
                Arc::new(config(cipher, "none", &ready, wrong_root)),
                name.try_into().unwrap(),
            )
            .unwrap();
            let error = connection.complete_io(&mut socket(&ready)).unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidData, "{error}");
            assert!(connection.is_handshaking());
            let mut plaintext = [0u8; 1];
            assert!(connection.reader().read(&mut plaintext).is_err());
        }
    }
}
