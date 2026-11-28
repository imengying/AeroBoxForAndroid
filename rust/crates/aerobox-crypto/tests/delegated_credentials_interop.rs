//! Real RFC9345 authentication using a standalone Go record/key-schedule peer.
use aerobox_crypto::delegated_credentials::Verifier;
use rustls::{
    CertificateError, ClientConfig, ClientConnection, DigitallySignedStruct, Error, HandshakeKind,
    InvalidMessage, ProtocolVersion, SignatureScheme,
    client::{
        DelegatedCredential, WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
};
use sha2::{Digest, Sha256};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
    process::{Child, ChildStdout, Command, Stdio},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

const PAYLOAD: usize = 65537;
const EXPORTER_LABEL: &[u8] = b"aerobox delegated credential exporter";
const EXPORTER_CONTEXT: &[u8] = b"\0android\0rfc9345\0";

fn fixture() -> &'static serde_json::Value {
    static FIXTURES: OnceLock<serde_json::Value> = OnceLock::new();
    FIXTURES.get_or_init(|| {
        serde_json::from_str(include_str!("../src/delegated_credentials/fixtures.json")).unwrap()
    })
}
fn decode(value: &serde_json::Value) -> Vec<u8> {
    let text = value.as_str().unwrap();
    assert!(!text.is_empty() && text.len() % 2 == 0 && text.len() < 131072);
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Debug)]
struct FixtureTime;
impl rustls::time_provider::TimeProvider for FixtureTime {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(Duration::from_secs(1893456000)))
    }
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
    assert!(
        !line.is_empty() && line.len() <= 65536 && line.ends_with('\n'),
        "bounded report: {line}"
    );
    serde_json::from_str(&line).unwrap()
}
fn start(args: &[String]) -> (Peer, BufReader<ChildStdout>, TcpStream) {
    let mut peer = Peer(
        Command::new(
            std::env::var_os("AEROBOX_DELEGATED_CREDENTIAL_PEER").expect("standalone Go DC peer"),
        )
        .args([
            "-fixtures",
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/delegated_credentials/fixtures.json"
            ),
        ])
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap(),
    );
    let mut output = BufReader::new(peer.0.stdout.take().unwrap());
    let ready = report(&mut output);
    assert_eq!(ready["phase"], "ready");
    let port = u16::try_from(ready["port"].as_u64().unwrap()).unwrap();
    let stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(35)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(35)))
        .unwrap();
    (peer, output, stream)
}

#[derive(Debug, Default)]
struct ObservedCalls {
    chain: AtomicUsize,
    delegated: AtomicUsize,
}
#[derive(Debug)]
struct ObservedVerifier {
    inner: Verifier,
    calls: Arc<ObservedCalls>,
    reject_pin: bool,
    omit_ed25519: bool,
}
impl ServerCertVerifier for ObservedVerifier {
    fn verify_server_cert(
        &self,
        cert: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        self.calls.chain.fetch_add(1, Ordering::SeqCst);
        let verified = self
            .inner
            .verify_server_cert(cert, chain, name, ocsp, now)?;
        if self.reject_pin {
            let (_, parsed) = x509_parser::parse_x509_certificate(cert.as_ref())
                .map_err(|_| Error::InvalidCertificate(CertificateError::BadEncoding))?;
            let actual_pin = Sha256::digest(parsed.public_key().raw);
            let required_pin = [0xa5; 32];
            if actual_pin.as_slice() != required_pin {
                return Err(Error::General("DC fixture SPKI pin rejected".into()));
            }
        }
        Ok(verified)
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        sig: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, sig)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        sig: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, sig)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        let mut schemes = self.inner.supported_verify_schemes();
        if self.omit_ed25519 {
            schemes.retain(|scheme| *scheme != SignatureScheme::ED25519);
        }
        schemes
    }
    fn supported_delegated_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_delegated_verify_schemes()
    }
    fn verify_tls13_delegated_credential(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dc: &DelegatedCredential,
        sig: &DigitallySignedStruct,
        now: UnixTime,
    ) -> Result<HandshakeSignatureValid, Error> {
        assert_eq!(
            self.calls.chain.load(Ordering::SeqCst),
            1,
            "delegation must follow original identity/pin checks"
        );
        self.calls.delegated.fetch_add(1, Ordering::SeqCst);
        self.inner
            .verify_tls13_delegated_credential(message, cert, dc, sig, now)
    }
}

#[derive(Clone, Copy, Debug)]
enum Fault {
    None,
    WrongName,
    WrongRoot,
    Pin,
    NoOffer,
    UnadvertisedIssuer,
}
fn config(curve: &str, mutual: bool, fault: Fault) -> (ClientConfig, Arc<ObservedCalls>) {
    let provider = Arc::new(aerobox_crypto::provider());
    let mut roots = rustls::RootCertStore::empty();
    let root: CertificateDer<'static> = if matches!(fault, Fault::WrongRoot) {
        include_bytes!("fixtures/p521-ca.der").to_vec().into()
    } else {
        decode(&fixture()["ca"]).into()
    };
    roots.add(root).unwrap();
    let inner = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .unwrap();
    let wrapper = if curve == "Ed25519" {
        Verifier::with_schemes(inner, vec![SignatureScheme::ED25519]).unwrap()
    } else {
        Verifier::new(inner)
    };
    let calls = Arc::new(ObservedCalls::default());
    let verifier = Arc::new(ObservedVerifier {
        inner: wrapper,
        calls: calls.clone(),
        reject_pin: matches!(fault, Fault::Pin),
        omit_ed25519: matches!(fault, Fault::UnadvertisedIssuer),
    });
    let builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    let mut config = if mutual {
        builder
            .with_client_auth_cert(
                vec![decode(&fixture()["certificates"]["valid"]).into()],
                PrivatePkcs8KeyDer::from(decode(&fixture()["issuer_key"])).into(),
            )
            .unwrap()
    } else {
        builder.with_no_client_auth()
    };
    config.enable_delegated_credentials = !matches!(fault, Fault::NoOffer);
    config.time_provider = Arc::new(FixtureTime);
    config.alpn_protocols = vec![b"h2".to_vec()];
    config.cert_compressors.clear();
    config.cert_decompressors.clear();
    config.max_fragment_size = Some(512);
    (config, calls)
}

fn exercise(curve: &str, cipher: u16, group: u16, mutual: bool, mode: &str, cookie: bool) {
    eprintln!(
        "DC {curve} suite={cipher:04x} group={group} mutual={mutual} mode={mode} cookie={cookie}"
    );
    let mut args = vec![
        format!("-curve={curve}"),
        format!("-cipher={cipher}"),
        format!("-group={group}"),
        format!("-mode={mode}"),
    ];
    if mutual {
        args.push("-mutual".into());
    }
    if cookie {
        args.push("-cookie".into());
    }
    let (mut peer, mut output, socket) = start(&args);
    let (config, calls) = config(curve, mutual, Fault::None);
    let client = ClientConnection::new(Arc::new(config), "localhost".try_into().unwrap()).unwrap();
    let mut stream = rustls::StreamOwned::new(client, socket);
    let sent: Vec<u8> = (0..PAYLOAD).map(|i| ((i * 17 + 3) % 251) as u8).collect();
    stream.write_all(&sent).unwrap();
    stream.flush().unwrap();
    let mut response = vec![0; 36 + PAYLOAD];
    stream.read_exact(&mut response).unwrap();
    assert_eq!(&response[..4], b"ABDC");
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
    assert_eq!(
        stream.conn.handshake_kind(),
        Some(if group != 29 || cookie {
            HandshakeKind::FullWithHelloRetryRequest
        } else {
            HandshakeKind::Full
        })
    );
    assert_eq!(stream.conn.alpn_protocol(), Some(b"h2".as_slice()));
    assert_eq!(
        stream.conn.peer_certificates().unwrap()[0].as_ref(),
        decode(
            &fixture()["certificates"][if mode == "short-inside" {
                "short"
            } else {
                "valid"
            }]
        )
    );
    let exporter = stream
        .conn
        .export_keying_material(vec![0; 32], EXPORTER_LABEL, Some(EXPORTER_CONTEXT))
        .unwrap();
    assert_eq!(&response[4..36], exporter);
    for (i, byte) in response[36..].iter().enumerate() {
        assert_eq!(*byte, ((i * 29 + 7) % 251) as u8);
    }
    assert_eq!(calls.chain.load(Ordering::SeqCst), 1);
    assert_eq!(
        calls.delegated.load(Ordering::SeqCst),
        usize::from(mode != "omit")
    );
    stream.conn.send_close_notify();
    stream.flush().unwrap();
    assert_eq!(stream.read(&mut [0]).unwrap(), 0);
    assert!(stream.conn.process_new_packets().unwrap().peer_has_closed());
    let report = report(&mut output);
    assert_eq!(report["phase"], "complete", "{report}");
    let result = &report["result"];
    assert_eq!(result["cipher"], cipher);
    assert_eq!(result["group"], group);
    assert_eq!(result["delegated"], mode != "omit");
    assert_eq!(result["hello_retry"], group != 29 || cookie);
    assert_eq!(result["client_verified"], mutual);
    assert_eq!(result["client_finished"], true);
    assert_eq!(result["close_notify"], true);
    assert_eq!(result["bytes"], PAYLOAD);
    assert_eq!(result["exporter"], hex(&exporter));
    assert_eq!(result["client_sha256"], hex(&Sha256::digest(&sent)));
    assert_eq!(
        result["server_sha256"],
        hex(&Sha256::digest(&response[36..]))
    );
    assert!(peer.0.wait().unwrap().success());
}

#[test]
#[ignore = "requires AEROBOX_DELEGATED_CREDENTIAL_PEER"]
fn rfc9345_all_delegated_keys_three_tls13_suites_retry_mutual_and_full_authentication() {
    for curve in ["P-256", "P-384", "P-521", "Ed25519"] {
        for group in [29, 23, 25] {
            for mutual in [false, true] {
                exercise(curve, 0x1301, group, mutual, "valid", false);
            }
        }
        for cipher in [0x1302, 0x1303] {
            exercise(curve, cipher, 29, false, "valid", false);
            exercise(curve, cipher, 25, true, "valid", false);
        }
    }
    for cipher in [0x1301, 0x1302, 0x1303] {
        exercise("P-256", cipher, 29, true, "omit", false);
    }
    for mode in ["seven-days", "now-expiry", "short-inside"] {
        exercise("P-256", 0x1301, 29, false, mode, false);
    }
    exercise("P-256", 0x1302, 29, true, "valid", true);
}

#[derive(Clone, Copy, Debug)]
enum Rejection {
    Credential,
    BadCV,
    BadFinished,
    Duplicate,
    Malformed,
    WrongPosition,
    Identity,
    Pin,
    NoOffer,
    UnsupportedCritical,
}
fn reject(
    mode: &str,
    fault: Fault,
    expected: Rejection,
    issuer_case: Option<&str>,
    cipher: u16,
    group: u16,
) {
    eprintln!("DC reject {mode} {fault:?} {expected:?} issuer={issuer_case:?} cipher={cipher:04x}");
    let mut args = vec![
        format!("-mode={mode}"),
        format!("-cipher={cipher}"),
        format!("-group={group}"),
    ];
    if let Some(case) = issuer_case {
        args.push(format!("-issuer-case={case}"));
    }
    let (mut peer, mut output, mut socket) = start(&args);
    let (config, calls) = config("P-256", false, fault);
    let name = if matches!(fault, Fault::WrongName) {
        "wrong.invalid"
    } else {
        "localhost"
    };
    let mut client = ClientConnection::new(Arc::new(config), name.try_into().unwrap()).unwrap();
    let error = loop {
        while client.wants_write() {
            client.write_tls(&mut socket).unwrap();
        }
        assert!(client.is_handshaking(), "negative handshake completed");
        assert!(
            client.read_tls(&mut (&mut socket).take(137)).unwrap() > 0,
            "peer EOF before client protocol rejection"
        );
        if let Err(error) = client.process_new_packets() {
            break error;
        }
    };
    let correct = match expected {
        Rejection::Credential => {
            matches!(&error, Error::General(_))
                || matches!(
                    &error,
                    Error::InvalidCertificate(
                        CertificateError::UnsupportedSignatureAlgorithmForPublicKeyContext { .. }
                            | CertificateError::BadEncoding
                    )
                )
        }
        Rejection::BadCV => matches!(
            &error,
            Error::InvalidCertificate(CertificateError::BadSignature)
        ),
        Rejection::BadFinished => matches!(&error, Error::DecryptError),
        Rejection::Duplicate => matches!(
            &error,
            Error::InvalidMessage(InvalidMessage::DuplicateExtension(34))
        ),
        Rejection::Malformed => matches!(&error, Error::InvalidMessage(_)),
        Rejection::WrongPosition => {
            matches!(&error, Error::General(_))
                || matches!(
                    &error,
                    Error::InvalidMessage(InvalidMessage::UnknownHelloRetryRequestExtension)
                )
        }
        Rejection::Identity => matches!(
            &error,
            Error::InvalidCertificate(
                CertificateError::UnknownIssuer
                    | CertificateError::NotValidForName
                    | CertificateError::NotValidForNameContext { .. }
            )
        ),
        Rejection::Pin => {
            matches!(&error, Error::General(message) if message == "DC fixture SPKI pin rejected")
        }
        Rejection::NoOffer => {
            matches!(&error, Error::General(message) if message == "unadvertised delegated credential")
        }
        // The pinned WebPKI backend reports this through rustls's unmapped
        // certificate-error wrapper. Its Display is the exact variant name.
        // Keep both outer variants and the precise inner error; do not accept
        // an arbitrary certificate or provider failure.
        Rejection::UnsupportedCritical => matches!(
            &error,
            Error::InvalidCertificate(CertificateError::Other(inner))
                if inner.0.to_string() == "UnsupportedCriticalExtension"
        ),
    };
    assert!(correct, "{mode}: unexpected rejection {error:?}");
    if matches!(
        expected,
        Rejection::Identity | Rejection::Pin | Rejection::UnsupportedCritical
    ) {
        assert_eq!(calls.chain.load(Ordering::SeqCst), 1);
        assert_eq!(
            calls.delegated.load(Ordering::SeqCst),
            0,
            "original authentication failure must prevent DC verification"
        );
    }
    let repeated = client.process_new_packets().unwrap_err();
    if let (
        Error::InvalidCertificate(CertificateError::Other(original)),
        Error::InvalidCertificate(CertificateError::Other(repeated)),
    ) = (&error, &repeated)
    {
        // OtherError deliberately never compares equal, even to its own clone.
        // A permanent connection failure must retain the same backend error.
        assert!(matches!(expected, Rejection::UnsupportedCritical));
        assert!(Arc::ptr_eq(&original.0, &repeated.0));
    } else {
        assert_eq!(repeated, error);
    }
    assert!(client.reader().read(&mut [0]).is_err());
    assert!(
        client
            .export_keying_material(vec![0; 32], EXPORTER_LABEL, Some(EXPORTER_CONTEXT))
            .is_err()
    );
    // Deliver the actual fatal alert so the peer reports protocol rejection.
    while client.wants_write() {
        if client.write_tls(&mut socket).is_err() {
            break;
        }
    }
    drop(socket);
    let report = report(&mut output);
    assert_eq!(report["phase"], "rejected", "{report}");
    assert_eq!(report["result"]["client_finished"], false);
    assert_eq!(report["result"]["close_notify"], false);
    assert!(!peer.0.wait().unwrap().success());
}

#[test]
#[ignore = "requires AEROBOX_DELEGATED_CREDENTIAL_PEER"]
fn rfc9345_rejects_invalid_identity_delegation_algorithms_locations_and_finished() {
    for mode in [
        "expired",
        "too-long",
        "cert-expiry",
        "bad-issuer",
        "wrong-role",
        "certificate-context",
        "wrong-expected",
        "bad-key",
        "rsa-key",
        "sha1-cv",
        "sha1-issuer",
        "pkcs1-issuer",
        "bad-delegated-scheme",
        "unadvertised-delegated",
        "missing_usage",
        "malformed_usage",
        "duplicate_usage",
        "missing_key_usage",
        "wrong_key_usage",
    ] {
        reject(mode, Fault::None, Rejection::Credential, None, 0x1301, 29);
    }
    for mode in ["truncated", "trailing", "empty-spki", "empty-signature"] {
        reject(mode, Fault::None, Rejection::Malformed, None, 0x1301, 29);
    }
    reject(
        "duplicate",
        Fault::None,
        Rejection::Duplicate,
        None,
        0x1301,
        29,
    );
    for mode in ["nonleaf", "serverhello", "encryptedextensions"] {
        reject(
            mode,
            Fault::None,
            Rejection::WrongPosition,
            None,
            0x1301,
            29,
        );
    }
    reject(
        "hrr",
        Fault::None,
        Rejection::WrongPosition,
        None,
        0x1301,
        23,
    );
    reject(
        "critical_usage",
        Fault::None,
        Rejection::UnsupportedCritical,
        None,
        0x1301,
        29,
    );
    reject(
        "unadvertised",
        Fault::NoOffer,
        Rejection::NoOffer,
        None,
        0x1301,
        29,
    );
    reject(
        "valid",
        Fault::UnadvertisedIssuer,
        Rejection::Credential,
        Some("Ed25519"),
        0x1301,
        29,
    );
    for issuer in [
        "P-256-cross",
        "P-384-cross",
        "P-521-cross",
        "RSA-sha256",
        "RSA-sha384",
        "RSA-sha512",
    ] {
        reject(
            "valid",
            Fault::None,
            Rejection::Credential,
            Some(issuer),
            0x1301,
            29,
        );
    }
    for cipher in [0x1301, 0x1302, 0x1303] {
        reject("bad-cv", Fault::None, Rejection::BadCV, None, cipher, 29);
        reject(
            "bad-finished",
            Fault::None,
            Rejection::BadFinished,
            None,
            cipher,
            29,
        );
        reject(
            "valid",
            Fault::WrongName,
            Rejection::Identity,
            None,
            cipher,
            29,
        );
        reject(
            "valid",
            Fault::WrongRoot,
            Rejection::Identity,
            None,
            cipher,
            29,
        );
        reject("bad-issuer", Fault::Pin, Rejection::Pin, None, cipher, 29);
    }
}

#[test]
fn standalone_dc_fixture_is_an_independent_ca_with_four_delegated_keys() {
    assert_eq!(fixture()["now"], 1893456000_u64);
    assert_eq!(fixture()["curves"].as_array().unwrap().len(), 3);
    assert!(decode(&fixture()["ed25519"]["credential"]).len() > 300);
    assert_ne!(
        decode(&fixture()["ca"]),
        include_bytes!("fixtures/rsa-cert.der")
    );
}
