//! Exercise the real production config builder with an independent RFC9345 peer.
use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use rustls::{CertificateError, ClientConnection, Error, HandshakeKind, ProtocolVersion};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
    process::{Child, ChildStdout, Command, Stdio},
    sync::OnceLock,
    time::Duration,
};

const FIXTURES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../crates/aerobox-crypto/src/delegated_credentials/fixtures.json"
);
const PAYLOAD: usize = 65537;
const LABEL: &[u8] = b"aerobox delegated credential exporter";
const CONTEXT: &[u8] = b"\0android\0rfc9345\0";

fn fixture() -> &'static serde_json::Value {
    static VALUE: OnceLock<serde_json::Value> = OnceLock::new();
    VALUE.get_or_init(|| serde_json::from_slice(&std::fs::read(FIXTURES).unwrap()).unwrap())
}
fn decode(value: &serde_json::Value) -> Vec<u8> {
    let text = value.as_str().unwrap();
    assert!(text.len() % 2 == 0 && text.len() < 131072);
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}
fn pem(label: &str, value: &[u8]) -> String {
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        STANDARD.encode(value)
    )
}
fn hash(value: &[u8]) -> String {
    aerobox_primitives::digest::digest(&aerobox_primitives::digest::SHA256, value)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
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
#[derive(Clone, Copy, Debug)]
enum Fault {
    None,
    Name,
    Root,
    Pin,
}
fn config(mutual: bool, fault: Fault) -> ClientConfig {
    let certificate = decode(&fixture()["certificates"]["valid"]);
    let (_, cert) = x509_parser::parse_x509_certificate(&certificate).unwrap();
    let digest = aerobox_primitives::digest::digest(
        &aerobox_primitives::digest::SHA256,
        cert.public_key().raw,
    );
    let pin = if matches!(fault, Fault::Pin) {
        STANDARD.encode([0; 32])
    } else {
        STANDARD.encode(digest)
    };
    let roots = if matches!(fault, Fault::Root) {
        std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../crates/aerobox-crypto/tests/fixtures/p521-ca.der"
        ))
        .unwrap()
    } else {
        decode(&fixture()["ca"])
    };
    let options = TlsClientOptions {
        fingerprint: Some(TlsClientFingerprint::Firefox120),
        root_certificates: vec![pem("CERTIFICATE", &roots)],
        certificate_public_key_sha256: vec![pin],
        ..Default::default()
    };
    let credentials = mutual.then(|| {
        (
            pem("PRIVATE KEY", &decode(&fixture()["issuer_key"])).into_bytes(),
            pem("CERTIFICATE", &certificate).into_bytes(),
        )
    });
    let mut config = try_create_client_config_with_options(
        true,
        vec![],
        vec!["h2".into()],
        true,
        credentials,
        false,
        &Default::default(),
        &options,
    )
    .unwrap();
    config.time_provider = Arc::new(FixedTime);
    config.max_fragment_size = Some(137);
    config
}
struct Peer(Child);
impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn report(output: &mut BufReader<ChildStdout>) -> serde_json::Value {
    let mut line = String::new();
    output.by_ref().take(65537).read_line(&mut line).unwrap();
    assert!(line.ends_with('\n') && line.len() <= 65536);
    serde_json::from_str(&line).unwrap()
}
fn peer(
    curve: &str,
    cipher: u16,
    group: u16,
    mode: &str,
    mutual: bool,
    cookie: bool,
) -> (Peer, BufReader<ChildStdout>, TcpStream) {
    let mut command = Command::new(std::env::var_os("AEROBOX_DELEGATED_CREDENTIAL_PEER").unwrap());
    command
        .args(["-fixtures", FIXTURES, "-curve", curve, "-mode", mode])
        .arg(format!("-cipher={cipher}"))
        .arg(format!("-group={group}"));
    if mutual {
        command.arg("-mutual");
    }
    if cookie {
        command.arg("-cookie");
    }
    let mut child = Peer(
        command
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let mut output = BufReader::new(child.0.stdout.take().unwrap());
    let ready = report(&mut output);
    assert_eq!(ready["phase"], "ready");
    let socket = TcpStream::connect((
        "127.0.0.1",
        u16::try_from(ready["port"].as_u64().unwrap()).unwrap(),
    ))
    .unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    (child, output, socket)
}
fn exchange(curve: &str, cipher: u16, group: u16, mutual: bool, mode: &str, cookie: bool) {
    eprintln!(
        "production Firefox DC: {curve} {cipher:04x} group={group} mutual={mutual} {mode} cookie={cookie}"
    );
    let (mut peer, mut output, socket) = peer(curve, cipher, group, mode, mutual, cookie);
    let client = ClientConnection::new(
        Arc::new(config(mutual, Fault::None)),
        "localhost".try_into().unwrap(),
    )
    .unwrap();
    let mut stream = rustls::StreamOwned::new(client, socket);
    let sent: Vec<_> = (0..PAYLOAD).map(|i| ((i * 17 + 3) % 251) as u8).collect();
    stream.write_all(&sent).unwrap();
    stream.flush().unwrap();
    let mut received = vec![0; 36 + PAYLOAD];
    stream.read_exact(&mut received).unwrap();
    assert_eq!(&received[..4], b"ABDC");
    let exporter = stream
        .conn
        .export_keying_material(vec![0; 32], LABEL, Some(CONTEXT))
        .unwrap();
    assert_eq!(&received[4..36], exporter);
    for (i, byte) in received[36..].iter().enumerate() {
        assert_eq!(*byte, ((i * 29 + 7) % 251) as u8);
    }
    assert_eq!(
        stream.conn.protocol_version(),
        Some(ProtocolVersion::TLSv1_3)
    );
    assert_eq!(
        u16::from(stream.conn.negotiated_cipher_suite().unwrap().suite()),
        cipher
    );
    assert_eq!(
        u16::from(stream.conn.negotiated_key_exchange_group().unwrap().name()),
        group
    );
    let retried = group == 25 || cookie;
    assert_eq!(
        stream.conn.handshake_kind(),
        Some(if retried {
            HandshakeKind::FullWithHelloRetryRequest
        } else {
            HandshakeKind::Full
        })
    );
    assert_eq!(
        stream.conn.peer_certificates().unwrap()[0].as_ref(),
        decode(&fixture()["certificates"]["valid"])
    );
    stream.conn.send_close_notify();
    stream.flush().unwrap();
    assert_eq!(stream.read(&mut [0]).unwrap(), 0);
    let report = report(&mut output);
    assert_eq!(report["phase"], "complete");
    let result = &report["result"];
    assert_eq!(result["delegated"], mode != "omit");
    assert_eq!(result["cipher"], cipher);
    assert_eq!(result["group"], group);
    assert_eq!(result["hello_retry"], retried);
    assert_eq!(result["client_verified"], mutual);
    assert_eq!(result["client_finished"], true);
    assert_eq!(result["close_notify"], true);
    assert_eq!(result["bytes"], PAYLOAD);
    assert_eq!(result["client_sha256"], hash(&sent));
    assert_eq!(result["server_sha256"], hash(&received[36..]));
    assert!(peer.0.wait().unwrap().success());
}

#[test]
#[ignore = "requires AEROBOX_DELEGATED_CREDENTIAL_PEER"]
fn production_firefox_delegation_three_suites_preserve_full_profile_and_pin() {
    for cipher in [0x1301, 0x1302, 0x1303] {
        for curve in ["P-256", "P-384", "P-521"] {
            for group in [29, 23, 25] {
                for mutual in [false, true] {
                    exchange(curve, cipher, group, mutual, "valid", false);
                }
            }
        }
        exchange("P-256", cipher, 29, true, "omit", false);
        exchange("P-384", cipher, 23, true, "valid", true);
    }
}

#[test]
#[ignore = "requires AEROBOX_DELEGATED_CREDENTIAL_PEER"]
fn production_firefox_checks_identity_and_pin_before_dc_and_rejects_unoffered_keys() {
    for cipher in [0x1301, 0x1302, 0x1303] {
        for (mode, fault) in [
            ("bad-issuer", Fault::Name),
            ("bad-issuer", Fault::Root),
            ("bad-issuer", Fault::Pin),
            ("unadvertised-delegated", Fault::None),
            ("bad-cv", Fault::None),
            ("bad-finished", Fault::None),
        ] {
            let (mut peer, mut output, mut socket) = peer("P-256", cipher, 29, mode, false, false);
            let name = if matches!(fault, Fault::Name) {
                "wrong.invalid"
            } else {
                "localhost"
            };
            let mut client =
                ClientConnection::new(Arc::new(config(false, fault)), name.try_into().unwrap())
                    .unwrap();
            let error = loop {
                while client.wants_write() {
                    client.write_tls(&mut socket).unwrap();
                }
                assert!(client.is_handshaking());
                assert!(
                    client.read_tls(&mut (&mut socket).take(137)).unwrap() > 0,
                    "EOF before protocol rejection"
                );
                if let Err(error) = client.process_new_packets() {
                    break error;
                }
            };
            match fault {
                Fault::Name => assert!(matches!(
                    &error,
                    Error::InvalidCertificate(
                        CertificateError::NotValidForName
                            | CertificateError::NotValidForNameContext { .. }
                    )
                )),
                Fault::Root => assert!(matches!(
                    &error,
                    Error::InvalidCertificate(CertificateError::UnknownIssuer)
                )),
                Fault::Pin => assert!(
                    matches!(&error, Error::General(message) if message == "TLS certificate public key pin mismatch")
                ),
                Fault::None => match mode {
                    "unadvertised-delegated" => assert!(
                        matches!(&error, Error::General(message) if message.contains("delegated credential")),
                        "{error:?}"
                    ),
                    "bad-cv" => assert!(matches!(
                        &error,
                        Error::InvalidCertificate(CertificateError::BadSignature)
                    )),
                    "bad-finished" => assert!(matches!(&error, Error::DecryptError)),
                    _ => unreachable!(),
                },
            }
            assert_eq!(client.process_new_packets().unwrap_err(), error);
            assert!(client.reader().read(&mut [0]).is_err());
            assert!(
                client
                    .export_keying_material(vec![0; 32], LABEL, Some(CONTEXT))
                    .is_err()
            );
            while client.wants_write() {
                if client.write_tls(&mut socket).is_err() {
                    break;
                }
            }
            drop(socket);
            let report = report(&mut output);
            assert_eq!(report["phase"], "rejected");
            assert_eq!(report["result"]["client_finished"], false);
            assert!(!peer.0.wait().unwrap().success());
        }
    }
}
