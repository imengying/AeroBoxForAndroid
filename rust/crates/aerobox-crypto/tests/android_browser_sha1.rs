//! Real TLS1.2 ECDSA-SHA1 handshakes for Android's Safari16/iOS14 fingerprints.
//! A separate Go peer verifies certificates and both actual handshake signatures.
//! This tests algorithm prerequisites, not browser layouts or Apple applications.
use aerobox_crypto::android_browser::{self, Profile};
use rustls::{CertificateError, ClientConfig, ClientConnection, ProtocolVersion};
use sha2::{Digest, Sha256};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
    process::{Child, ChildStdout, Command, Stdio},
    sync::{Arc, OnceLock},
    time::Duration,
};

const CURVES: [&str; 3] = ["P-256", "P-384", "P-521"];
const PAYLOAD: usize = 65537;
const CIPHER: u16 = 0xc02b;
const FIXTURES: &[u8] = include_bytes!("../src/android_browser/sha1-fixtures.json");
const WRONG_ROOT: &[u8] = include_bytes!("fixtures/p521-ca.der");
const EXPORTER_LABEL: &[u8] = b"aerobox android browser sha1 exporter";
const EXPORTER_CONTEXT: &[u8] = b"\0android\0sha1\0";

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

fn fixtures() -> &'static serde_json::Value {
    static VALUE: OnceLock<serde_json::Value> = OnceLock::new();
    VALUE.get_or_init(|| serde_json::from_slice(FIXTURES).unwrap())
}

fn curve(name: &str) -> &'static serde_json::Value {
    fixtures()["curves"]
        .as_array()
        .unwrap()
        .iter()
        .find(|curve| curve["curve"] == name)
        .unwrap()
}

fn bytes(value: &serde_json::Value) -> Vec<u8> {
    let text = value.as_str().unwrap();
    assert!(!text.is_empty() && text.len() <= 65536 && text.len() % 2 == 0);
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn read_report(output: &mut BufReader<ChildStdout>) -> serde_json::Value {
    let mut line = String::new();
    output.by_ref().take(65537).read_line(&mut line).unwrap();
    assert!(!line.is_empty() && line.len() <= 65536 && line.ends_with('\n'));
    serde_json::from_str(&line).unwrap()
}

fn start(
    server: &str,
    client: &str,
    weak: bool,
) -> (Peer, BufReader<ChildStdout>, serde_json::Value) {
    let mut command = Command::new(
        std::env::var_os("AEROBOX_ANDROID_BROWSER_SHA1_PEER")
            .expect("independent Go reference peer"),
    );
    command.args([
        "--server-curve",
        server,
        "--client-curve",
        client,
        "--bytes",
        &PAYLOAD.to_string(),
        "--fixtures",
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/android_browser/sha1-fixtures.json"
        ),
    ]);
    if weak {
        command.arg("--weak-certificate");
    }
    let mut peer = Peer(
        command
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let mut output = BufReader::new(peer.0.stdout.take().unwrap());
    let ready = read_report(&mut output);
    assert_eq!(ready["phase"], "ready", "{ready}");
    assert_eq!(ready["fixture_sha256"], hex(&Sha256::digest(FIXTURES)));
    assert_eq!(ready["server_curve"], server);
    assert_eq!(ready["client_curve"], client);
    assert_eq!(ready["weak_certificate"], weak);
    (peer, output, ready)
}

fn config(profile: Option<Profile>, client: &str, wrong_root: bool) -> ClientConfig {
    let mut provider = profile.map_or_else(aerobox_crypto::provider, android_browser::provider);
    provider
        .cipher_suites
        .retain(|suite| u16::from(suite.suite()) == CIPHER);
    assert_eq!(provider.cipher_suites.len(), 1);
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(if wrong_root {
            WRONG_ROOT.to_vec().into()
        } else {
            bytes(&fixtures()["ca_der"]).into()
        })
        .unwrap();
    let builder = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap()
        .with_root_certificates(roots);
    let mut config = if client == "none" {
        builder.with_no_client_auth()
    } else {
        builder
            .with_client_auth_cert(
                vec![bytes(&curve(client)["sha256_cert_der"]).into()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(bytes(&curve(client)["key_der"]))
                    .into(),
            )
            .unwrap()
    };
    config.time_provider = Arc::new(FixtureTime);
    // Exercise the independent observer across fragmented handshake records.
    config.max_fragment_size = (client != "none").then_some(512);
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

fn exercise(profile: Profile, server: &str, client: &str) {
    eprintln!("Android browser {profile:?} ECDSA-SHA1 server={server} client={client}");
    let (mut peer, mut output, ready) = start(server, client, false);
    let connection = ClientConnection::new(
        Arc::new(config(Some(profile), client, false)),
        "localhost".try_into().unwrap(),
    )
    .unwrap();
    let mut stream = rustls::StreamOwned::new(connection, socket(&ready));
    let sent: Vec<u8> = (0..PAYLOAD).map(|i| ((i * 17 + 3) % 251) as u8).collect();
    stream.write_all(&sent).unwrap();
    stream.flush().unwrap();
    let mut response = vec![0; 36 + PAYLOAD];
    stream.read_exact(&mut response).unwrap();
    assert_eq!(&response[..4], b"ABS1");
    assert_eq!(
        stream.conn.protocol_version(),
        Some(ProtocolVersion::TLSv1_2)
    );
    assert_eq!(
        u16::from(stream.conn.negotiated_cipher_suite().unwrap().suite()),
        CIPHER
    );
    assert_eq!(stream.conn.alpn_protocol(), None);
    assert_eq!(
        stream.conn.handshake_kind(),
        Some(rustls::HandshakeKind::Full)
    );
    let certificates = stream.conn.peer_certificates().unwrap();
    assert_eq!(certificates.len(), 1);
    assert_eq!(
        certificates[0].as_ref(),
        bytes(&curve(server)["sha256_cert_der"])
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
    let mut extra = [0; 1];
    assert_eq!(stream.read(&mut extra).unwrap(), 0, "no extra plaintext");
    assert!(stream.conn.process_new_packets().unwrap().peer_has_closed());
    let result = read_report(&mut output);
    assert_eq!(result["phase"], "complete", "{result}");
    assert_eq!(result["version"], 0x0303);
    assert_eq!(result["cipher"], CIPHER);
    assert_eq!(result["server_curve"], server);
    assert_eq!(result["client_curve"], client);
    assert_eq!(result["server_signature"], 0x0203);
    if client == "none" {
        assert_eq!(result["certificate_request"], serde_json::json!([]));
        assert_eq!(result["client_signature"], 0);
    } else {
        assert_eq!(result["certificate_request"], serde_json::json!([0x0203]));
        assert_eq!(result["client_signature"], 0x0203);
    }
    assert_eq!(result["client_certificates"], usize::from(client != "none"));
    assert_eq!(
        result["verified_client_chains"].as_u64().unwrap() > 0,
        client != "none"
    );
    assert_eq!(result["bytes_each_direction"], PAYLOAD);
    assert_eq!(result["client_sha256"], hex(&Sha256::digest(&sent)));
    assert_eq!(
        result["server_sha256"],
        hex(&Sha256::digest(&response[36..]))
    );
    assert_eq!(result["exporter"], hex(&exporter));
    for key in [
        "client_offered_ecdsa_sha1",
        "ems",
        "ocsp",
        "close_notify_received",
    ] {
        assert_eq!(result[key], true, "{key}");
    }
    assert_eq!(result["resumed"], false);
    assert!(peer.0.wait().unwrap().success());
}

fn assert_failed_session(connection: &mut ClientConnection, error: &std::io::Error) {
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData, "{error}");
    let tls_error = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
        .expect("TLS failure retained by complete_io");
    assert_eq!(&connection.process_new_packets().unwrap_err(), tls_error);
    assert!(connection.is_handshaking());
    let mut plaintext = [0; 1];
    assert!(connection.reader().read(&mut plaintext).is_err());
    assert!(
        connection
            .export_keying_material(vec![0; 32], EXPORTER_LABEL, Some(EXPORTER_CONTEXT))
            .is_err()
    );
}

#[test]
#[ignore = "requires AEROBOX_ANDROID_BROWSER_SHA1_PEER"]
fn both_android_profiles_verify_sha1_handshakes_with_three_server_and_client_curves() {
    for profile in [Profile::Safari16, Profile::Ios14] {
        for server in CURVES {
            for client in ["none", "P-256", "P-384", "P-521"] {
                exercise(profile, server, client);
            }
        }
    }
}

#[test]
#[ignore = "requires AEROBOX_ANDROID_BROWSER_SHA1_PEER"]
fn ordinary_provider_does_not_opt_into_ecdsa_sha1_handshakes() {
    for server in CURVES {
        eprintln!("Ordinary provider rejects ECDSA-SHA1 server={server}");
        let (mut peer, mut output, ready) = start(server, "none", false);
        let mut connection = ClientConnection::new(
            Arc::new(config(None, "none", false)),
            "localhost".try_into().unwrap(),
        )
        .unwrap();
        let error = connection.complete_io(&mut socket(&ready)).unwrap_err();
        assert_failed_session(&mut connection, &error);
        assert!(
            matches!(
                error
                    .get_ref()
                    .and_then(|inner| inner.downcast_ref::<rustls::Error>()),
                Some(rustls::Error::AlertReceived(
                    rustls::AlertDescription::HandshakeFailure
                ))
            ),
            "{error:?}"
        );
        let result = read_report(&mut output);
        assert_eq!(result["phase"], "error", "{result}");
        assert_eq!(result["client_offered_ecdsa_sha1"], false);
        assert_eq!(result["server_signature"], 0);
        assert!(
            result["error"]
                .as_str()
                .unwrap()
                .contains("signature algorithms"),
            "{result}"
        );
        assert!(!peer.0.wait().unwrap().success());
    }
}

#[test]
#[ignore = "requires AEROBOX_ANDROID_BROWSER_SHA1_PEER"]
fn both_android_profiles_reject_wrong_identity_wrong_root_and_sha1_signed_certificates() {
    for profile in [Profile::Safari16, Profile::Ios14] {
        for server in CURVES {
            for reason in ["wrong-name", "wrong-root", "sha1-certificate"] {
                eprintln!("Android browser {profile:?} rejects {reason} server={server}");
                let weak = reason == "sha1-certificate";
                let (_peer, _output, ready) = start(server, "none", weak);
                let name = if reason == "wrong-name" {
                    "unrelated.test"
                } else {
                    "localhost"
                };
                let mut connection = ClientConnection::new(
                    Arc::new(config(Some(profile), "none", reason == "wrong-root")),
                    name.try_into().unwrap(),
                )
                .unwrap();
                let error = connection.complete_io(&mut socket(&ready)).unwrap_err();
                assert_failed_session(&mut connection, &error);
                let tls_error = error
                    .get_ref()
                    .and_then(|inner| inner.downcast_ref::<rustls::Error>())
                    .unwrap();
                let rustls::Error::InvalidCertificate(certificate_error) = tls_error else {
                    panic!("expected {reason} certificate rejection, got {tls_error:?}");
                };
                let expected = match reason {
                    "wrong-name" => matches!(
                        certificate_error,
                        CertificateError::NotValidForName
                            | CertificateError::NotValidForNameContext { .. }
                    ),
                    "wrong-root" => matches!(certificate_error, CertificateError::UnknownIssuer),
                    "sha1-certificate" => {
                        matches!(certificate_error,
                        CertificateError::UnsupportedSignatureAlgorithmContext { .. }
                        | CertificateError::UnsupportedSignatureAlgorithmForPublicKeyContext { .. })
                    }
                    _ => unreachable!(),
                };
                assert!(expected, "expected {reason}, got {certificate_error:?}");
            }
        }
    }
}
