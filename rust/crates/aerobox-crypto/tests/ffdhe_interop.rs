//! Explicit FFDHE TLS1.3 prerequisite against independent Go modular arithmetic.
//! This does not enable or claim a complete Firefox wire fingerprint.

use rustls::{
    CertificateError, ClientConfig, ClientConnection, Error, NamedGroup, ProtocolVersion,
};
use sha2::{Digest, Sha256};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
    process::{Child, ChildStdout, Command, Stdio},
    sync::Arc,
    time::Duration,
};

const PAYLOAD: usize = 65537;
const RSA_CERT: &[u8] = include_bytes!("fixtures/rsa-cert.der");
const RSA_KEY: &[u8] = include_bytes!("fixtures/rsa-key.der");
const WRONG_ROOT: &[u8] = include_bytes!("fixtures/p521-ca.der");
const EXPORTER_LABEL: &[u8] = b"aerobox android browser tls13 exporter";
const EXPORTER_CONTEXT: &[u8] = b"\0android\0tls13\0";

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

fn read_report(output: &mut BufReader<ChildStdout>) -> serde_json::Value {
    let mut line = String::new();
    output.by_ref().take(65537).read_line(&mut line).unwrap();
    assert!(!line.is_empty() && line.len() <= 65536 && line.ends_with('\n'));
    serde_json::from_str(&line).unwrap()
}

fn start(args: &[String]) -> (Peer, BufReader<ChildStdout>, serde_json::Value) {
    let mut peer = Peer(
        Command::new(std::env::var_os("AEROBOX_TLS_PROFILE_PEER").expect("independent Go peer"))
            .args([
                "-android-browser-exchange",
                "-alps=0",
                "-brotli=false",
                "-fixtures",
                concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures"),
            ])
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let mut output = BufReader::new(peer.0.stdout.take().unwrap());
    let ready = read_report(&mut output);
    assert_eq!(ready["phase"], "ready", "{ready}");
    (peer, output, ready)
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

fn decode(text: &str) -> Vec<u8> {
    assert!(!text.is_empty() && text.len() <= 65536 && text.len() % 2 == 0);
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn config(group: u16, retry: bool) -> ClientConfig {
    use rustls::crypto::SupportedKxGroup;
    let selected: &'static dyn SupportedKxGroup = match group {
        256 => &aerobox_crypto::ffdhe::FFDHE2048,
        257 => &aerobox_crypto::ffdhe::FFDHE3072,
        _ => panic!("invalid test group"),
    };
    let mut provider = aerobox_crypto::provider();
    provider
        .kx_groups
        .retain(|g| g.name() == NamedGroup::X25519);
    provider.kx_groups.push(selected);
    provider
        .cipher_suites
        .retain(|suite| u16::from(suite.suite()) == 0x1301);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(RSA_CERT.into()).unwrap();
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.initial_key_share_groups = vec![if retry {
        NamedGroup::X25519
    } else {
        selected.name()
    }];
    config.alpn_protocols = vec![b"h2".to_vec()];
    config.resumption = rustls::client::Resumption::disabled();
    config.time_provider = Arc::new(FixtureTime);
    config.cert_compressors.clear();
    config.cert_decompressors.clear();
    config
}

fn set_mutual_auth(config: &mut ClientConfig, ready: &serde_json::Value) {
    // The disposable clientAuth certificate uses the existing fixture key.
    // Go validates its purpose/time/signature then pins its exact DER and proof.
    let certificate = decode(ready["client_certificate_der_hex"].as_str().unwrap());
    let key = rustls::sign::CertifiedKey::from_der(
        vec![certificate.into()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(RSA_KEY.to_vec()).into(),
        &aerobox_crypto::provider(),
    )
    .unwrap();
    config.client_auth_cert_resolver = Arc::new(rustls::sign::SingleCertAndKey::from(key));
    config.max_fragment_size = Some(512);
}

fn exercise(group: u16, retry: bool, mutual: bool) {
    eprintln!("FFDHE {group} retry={retry} mutual={mutual}");
    let mut args = vec![
        format!("-group={group}"),
        format!("-expect-shares={}", if retry { 29 } else { group }),
    ];
    if mutual {
        args.push("-mutual".into());
    }
    let (mut peer, mut output, ready) = start(&args);
    let mut config = config(group, retry);
    if mutual {
        set_mutual_auth(&mut config, &ready);
    }
    let conn = ClientConnection::new(Arc::new(config), "localhost".try_into().unwrap()).unwrap();
    let mut stream = rustls::StreamOwned::new(conn, socket(&ready));
    let sent: Vec<u8> = (0..PAYLOAD).map(|i| ((i * 17 + 3) % 251) as u8).collect();
    stream.write_all(&sent).unwrap();
    stream.flush().unwrap();
    let mut response = vec![0; 36 + PAYLOAD];
    stream.read_exact(&mut response).unwrap();
    assert_eq!(&response[..4], b"AB13");
    assert_eq!(
        stream.conn.protocol_version(),
        Some(ProtocolVersion::TLSv1_3)
    );
    assert_eq!(
        u16::from(stream.conn.negotiated_cipher_suite().unwrap().suite()),
        0x1301
    );
    assert_eq!(
        u16::from(stream.conn.negotiated_key_exchange_group().unwrap().name()),
        group
    );
    assert_eq!(
        stream.conn.handshake_kind(),
        Some(if retry {
            rustls::HandshakeKind::FullWithHelloRetryRequest
        } else {
            rustls::HandshakeKind::Full
        })
    );
    assert_eq!(stream.conn.alpn_protocol(), Some(b"h2".as_slice()));
    assert_eq!(stream.conn.peer_application_settings(), None);
    assert_eq!(
        stream.conn.peer_certificates().unwrap()[0].as_ref(),
        RSA_CERT
    );
    let exporter = stream
        .conn
        .export_keying_material(vec![0; 32], EXPORTER_LABEL, Some(EXPORTER_CONTEXT))
        .unwrap();
    assert_eq!(&response[4..36], exporter.as_slice());
    for (i, byte) in response[36..].iter().enumerate() {
        assert_eq!(*byte, ((i * 29 + 7) % 251) as u8, "payload byte {i}");
    }
    stream.conn.send_close_notify();
    stream.flush().unwrap();
    assert_eq!(stream.read(&mut [0; 1]).unwrap(), 0);
    assert!(stream.conn.process_new_packets().unwrap().peer_has_closed());
    let report = read_report(&mut output);
    assert_eq!(report["phase"], "complete", "{report}");
    let result = &report["result"];
    assert_eq!(result["group"], group);
    assert_eq!(result["hello_retry"], retry);
    assert_eq!(result["compressed"], false);
    assert_eq!(result["compression_algorithm"].as_u64().unwrap_or(0), 0);
    assert_eq!(
        result["client_verified_chain"].as_bool().unwrap_or(false),
        mutual
    );
    assert_eq!(result["bytes"], PAYLOAD);
    assert_eq!(result["exporter"], hex(&exporter));
    assert_eq!(result["client_sha256"], hex(&Sha256::digest(&sent)));
    assert_eq!(
        result["server_sha256"],
        hex(&Sha256::digest(&response[36..]))
    );
    assert_eq!(result["close_notify"], true);
    assert_eq!(result["resumed"], false);
    assert_eq!(result["alps"], 0);
    assert!(peer.0.wait().unwrap().success());
}

#[test]
#[ignore = "requires AEROBOX_TLS_PROFILE_PEER with the explicit FFDHE test overlay"]
fn ffdhe_direct_and_hrr_verify_independent_go_finished_exporter_mtls_and_duplex_data() {
    for group in [256, 257] {
        for retry in [false, true] {
            for mutual in [false, true] {
                exercise(group, retry, mutual);
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Failure {
    Finished,
    WrongName,
    WrongRoot,
}

fn reject(group: u16, expected: Failure) {
    eprintln!("FFDHE {group} rejects {expected:?}");
    let mut args = vec![format!("-group={group}"), "-expect-shares=29".into()];
    if matches!(expected, Failure::Finished) {
        args.push("-bad-finished".into());
    }
    let (_peer, _output, ready) = start(&args);
    let mut config = config(group, true);
    if matches!(expected, Failure::WrongRoot) {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(WRONG_ROOT.into()).unwrap();
        let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(aerobox_crypto::provider()),
        )
        .build()
        .unwrap();
        config.dangerous().set_certificate_verifier(verifier);
    }
    let name = if matches!(expected, Failure::WrongName) {
        "wrong.example"
    } else {
        "localhost"
    };
    let mut client = ClientConnection::new(Arc::new(config), name.try_into().unwrap()).unwrap();
    let mut socket = socket(&ready);
    let failure = loop {
        while client.wants_write() {
            assert!(client.write_tls(&mut socket).unwrap() > 0);
        }
        assert!(
            client.read_tls(&mut socket).unwrap() > 0,
            "peer closed before TLS rejected input"
        );
        match client.process_new_packets() {
            Ok(_) => assert!(client.is_handshaking(), "accepted a negative fixture"),
            Err(error) => break error,
        }
    };
    let correct = match expected {
        Failure::Finished => matches!(failure, Error::DecryptError),
        Failure::WrongName => matches!(
            failure,
            Error::InvalidCertificate(
                CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. }
            )
        ),
        Failure::WrongRoot => matches!(
            failure,
            Error::InvalidCertificate(CertificateError::UnknownIssuer)
        ),
    };
    assert!(correct, "expected {expected:?}, got {failure:?}");
    assert_eq!(client.process_new_packets().unwrap_err(), failure);
    assert!(
        client
            .writer()
            .write(b"no write after failed authentication")
            .is_err()
    );
    assert!(
        client
            .export_keying_material([0u8; 32], EXPORTER_LABEL, Some(EXPORTER_CONTEXT))
            .is_err()
    );
}

#[test]
#[ignore = "requires AEROBOX_TLS_PROFILE_PEER with the explicit FFDHE test overlay"]
fn ffdhe_hrr_rejects_invalid_finished_wrong_name_and_unrelated_root() {
    for group in [256, 257] {
        for expected in [Failure::Finished, Failure::WrongName, Failure::WrongRoot] {
            reject(group, expected);
        }
    }
}
