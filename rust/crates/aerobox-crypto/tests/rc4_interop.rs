//! Independent Go handshake validation candidate for explicit RC4-SHA capability.
//! Requires the future separately reviewed RC4 peer documented in peer-contract.md;
//! the current CBC peer cannot run these tests. No successful execution is claimed.
//! Actual TLS handshakes exercise rustls's 16-byte AeadKey extraction and old PRFs.
use rustls::{CertificateError, ClientConfig, ClientConnection, ProtocolVersion};
use sha2::{Digest, Sha256};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
    process::{Child, ChildStdout, Command, Stdio},
    sync::Arc,
    time::Duration,
};

const VERSIONS: [(&str, ProtocolVersion); 3] = [
    ("1.0", ProtocolVersion::TLSv1_0),
    ("1.1", ProtocolVersion::TLSv1_1),
    ("1.2", ProtocolVersion::TLSv1_2),
];
const SUITES: [u16; 3] = [0xc007, 0xc011, 0x0005];
const PAYLOAD: usize = 65537;
const FIRST_WRITE: usize = 17;
const MAX_WIRE: usize = 1024 * 1024;
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

struct TappedTcp {
    socket: TcpStream,
    written: Vec<u8>,
    received: Vec<u8>,
}
impl Read for TappedTcp {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let n = self.socket.read(output)?;
        assert!(self.received.len() + n <= MAX_WIRE, "server wire limit");
        self.received.extend_from_slice(&output[..n]);
        Ok(n)
    }
}
impl Write for TappedTcp {
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        let n = self.socket.write(input)?;
        assert!(self.written.len() + n <= MAX_WIRE, "client wire limit");
        self.written.extend_from_slice(&input[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.socket.flush()
    }
}

fn read_report(output: &mut BufReader<ChildStdout>) -> serde_json::Value {
    let mut line = String::new();
    output.by_ref().take(131073).read_line(&mut line).unwrap();
    assert!(!line.is_empty() && line.len() <= 131072 && line.ends_with('\n'));
    serde_json::from_str(&line).unwrap()
}

fn start(
    version: &str,
    cipher: u16,
    mutual: &str,
) -> (Peer, BufReader<ChildStdout>, serde_json::Value) {
    let mut peer = Peer(
        Command::new(std::env::var_os("AEROBOX_RC4_TLS_PEER").expect("reference peer"))
            .args([
                "--version",
                version,
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
    let ready = read_report(&mut output);
    assert_eq!(ready["phase"], "ready", "{ready}");
    (peer, output, ready)
}

fn config(
    version: ProtocolVersion,
    cipher: u16,
    mutual: &str,
    ready: &serde_json::Value,
    wrong_root: bool,
) -> ClientConfig {
    let mut provider = aerobox_crypto::provider();
    provider.cipher_suites = aerobox_crypto::legacy_rc4::suites()
        .into_iter()
        .filter(|suite| u16::from(suite.suite()) == cipher)
        .collect();
    assert_eq!(provider.cipher_suites.len(), 1);
    let mut roots = rustls::RootCertStore::empty();
    if wrong_root {
        // Use a distinct issuer name as well as a distinct key. The RSA/P256
        // self-signed fixtures share a subject, so swapping them can trigger
        // a signature-algorithm error before chain search reaches UnknownIssuer.
        roots
            .add(include_bytes!("fixtures/p521-ca.der").as_slice().into())
            .unwrap();
    } else {
        roots.add(RSA_CERT.into()).unwrap();
        roots.add(EC_CERT.into()).unwrap();
    }
    let builder = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap()
        .with_root_certificates(roots);
    let mut config = if mutual == "none" {
        builder.with_no_client_auth()
    } else {
        assert!(matches!(mutual, "rsa" | "ecdsa"));
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
    if version != ProtocolVersion::TLSv1_2 {
        config
            .enable_legacy_tls(&aerobox_crypto::legacy_rc4::LEGACY_TLS_WITH_RC4, &[version])
            .unwrap();
    }
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

fn check_records(mut wire: &[u8], version: ProtocolVersion, client: bool) {
    let mut encrypted = false;
    let mut first_encrypted = true;
    let mut applications = Vec::new();
    let mut alerts = 0;
    while !wire.is_empty() {
        assert!(wire.len() >= 5, "partial TLS record header");
        let size = usize::from(u16::from_be_bytes([wire[3], wire[4]]));
        assert!(wire.len() >= 5 + size, "partial TLS record body");
        if encrypted {
            assert_eq!(u16::from_be_bytes([wire[1], wire[2]]), u16::from(version));
            assert!((20..=16404).contains(&size));
            if first_encrypted {
                assert_eq!(wire[0], 22, "first encrypted record is Finished");
                assert_eq!(size, 36, "16-byte Finished and 20-byte MAC, no IV/padding");
                first_encrypted = false;
            }
            match wire[0] {
                21 => {
                    alerts += 1;
                    assert_eq!(size, 22, "close_notify and MAC");
                }
                22 => (),
                23 => applications.push(size),
                other => panic!("unexpected encrypted record type {other}"),
            }
        } else if wire[0] == 20 {
            assert_eq!(&wire[5..5 + size], &[1], "ChangeCipherSpec");
            encrypted = true;
        } else {
            assert_eq!(wire[0], 22, "plaintext record is handshake");
        }
        wire = &wire[5 + size..];
    }
    assert!(encrypted && !first_encrypted);
    assert!(!applications.is_empty());
    assert_eq!(alerts, 1, "authenticated close_notify in each direction");
    if client {
        // RC4 is a stream cipher in every version. Only CBC uses TLS1.0's
        // 1/n-1 split; this must agree with buffered/unbuffered length estimates.
        assert_eq!(
            applications[0], 37,
            "17-byte first write plus MAC; no CBC split"
        );
    }
}

fn exercise(version_text: &str, version: ProtocolVersion, cipher: u16, mutual: &str) {
    eprintln!("Explicit RC4 capability TLS{version_text} suite={cipher:04x} client-auth={mutual}");
    let (mut peer, mut output, ready) = start(version_text, cipher, mutual);
    let connection = ClientConnection::new(
        Arc::new(config(version, cipher, mutual, &ready, false)),
        "localhost".try_into().unwrap(),
    )
    .unwrap();
    let mut stream = rustls::StreamOwned::new(
        connection,
        TappedTcp {
            socket: socket(&ready),
            written: Vec::new(),
            received: Vec::new(),
        },
    );
    let sent: Vec<u8> = (0..PAYLOAD).map(|i| ((i * 17 + 3) % 251) as u8).collect();
    // Flush a known-size record to check that stream records add only a 20-byte MAC.
    stream.write_all(&sent[..FIRST_WRITE]).unwrap();
    stream.flush().unwrap();
    stream.write_all(&sent[FIRST_WRITE..]).unwrap();
    stream.flush().unwrap();
    let mut response = vec![0; 36 + PAYLOAD];
    stream.read_exact(&mut response).unwrap();
    assert_eq!(&response[..4], b"AB11");
    assert_eq!(stream.conn.protocol_version(), Some(version));
    assert_eq!(
        u16::from(stream.conn.negotiated_cipher_suite().unwrap().suite()),
        cipher
    );
    assert_eq!(stream.conn.alpn_protocol(), None);
    assert_eq!(
        stream.conn.handshake_kind(),
        Some(rustls::HandshakeKind::Full)
    );
    assert_eq!(
        stream.conn.peer_certificates().unwrap()[0].as_ref(),
        if cipher == 0xc007 { EC_CERT } else { RSA_CERT }
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
    let mut tail = [0; 1];
    assert_eq!(stream.read(&mut tail).unwrap(), 0, "no extra plaintext");
    assert!(stream.conn.process_new_packets().unwrap().peer_has_closed());
    check_records(&stream.sock.written, version, true);
    check_records(&stream.sock.received, version, false);

    let result = read_report(&mut output);
    assert_eq!(result["phase"], "complete", "{result}");
    assert_eq!(result["version"], u16::from(version));
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
        assert_eq!(result[key], true, "{key}");
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
#[ignore = "requires AEROBOX_RC4_TLS_PEER"]
fn all_rc4_versions_and_suites_authenticate_exchange_data_and_verify_client_certificates() {
    for (version_text, version) in VERSIONS {
        for cipher in SUITES {
            for mutual in ["none", "rsa", "ecdsa"] {
                exercise(version_text, version, cipher, mutual);
            }
        }
    }
}

#[test]
#[ignore = "requires AEROBOX_RC4_TLS_PEER"]
fn all_rc4_versions_and_suites_reject_wrong_server_identity_and_untrusted_certificates() {
    for (version_text, version) in VERSIONS {
        for cipher in SUITES {
            for wrong_root in [false, true] {
                eprintln!(
                    "Explicit RC4 capability reject TLS{version_text} suite={cipher:04x} wrong-root={wrong_root}"
                );
                let (_peer, _output, ready) = start(version_text, cipher, "none");
                let name = if wrong_root {
                    "localhost"
                } else {
                    "unrelated.test"
                };
                let mut connection = ClientConnection::new(
                    Arc::new(config(version, cipher, "none", &ready, wrong_root)),
                    name.try_into().unwrap(),
                )
                .unwrap();
                let error = connection.complete_io(&mut socket(&ready)).unwrap_err();
                assert_eq!(error.kind(), std::io::ErrorKind::InvalidData, "{error}");
                let tls_error = error
                    .get_ref()
                    .and_then(|inner| inner.downcast_ref::<rustls::Error>())
                    .expect("TLS error preserved by complete_io");
                let expected = if wrong_root {
                    matches!(
                        tls_error,
                        rustls::Error::InvalidCertificate(CertificateError::UnknownIssuer)
                    )
                } else {
                    matches!(
                        tls_error,
                        rustls::Error::InvalidCertificate(
                            CertificateError::NotValidForName
                                | CertificateError::NotValidForNameContext { .. }
                        )
                    )
                };
                assert!(
                    expected,
                    "expected certificate rejection, got {tls_error:?}"
                );
                assert_eq!(&connection.process_new_packets().unwrap_err(), tls_error);
                assert!(connection.is_handshaking());
                let mut plaintext = [0; 1];
                assert!(connection.reader().read(&mut plaintext).is_err());
                assert!(
                    connection
                        .export_keying_material(vec![0; 32], b"rejected-peer", None)
                        .is_err()
                );
            }
        }
    }
}
