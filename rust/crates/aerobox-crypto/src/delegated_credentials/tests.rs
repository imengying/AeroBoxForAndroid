//! Independent OpenSSL signatures plus public-API policy and resumption tests.
use super::*;
use rustls::{
    ClientConfig, ClientConnection, Connection, HandshakeKind, NamedGroup, RootCertStore,
    ServerConfig, ServerConnection,
    client::{
        ClientHelloLayout, ClientSessionMemoryCache, ClientSessionStore, Resumption,
        Tls12ClientSessionValue, Tls13ClientSessionValue, WebPkiServerVerifier,
    },
    internal::msgs::codec::Codec,
    pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
};
use std::{
    io::{Cursor, Read, Write},
    sync::{
        OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

fn fixture() -> &'static serde_json::Value {
    static VALUE: OnceLock<serde_json::Value> = OnceLock::new();
    VALUE.get_or_init(|| serde_json::from_str(include_str!("fixtures.json")).unwrap())
}

fn bytes(value: &serde_json::Value) -> Vec<u8> {
    let text = value.as_str().unwrap();
    assert!(!text.is_empty() && text.len() % 2 == 0 && text.len() < 65536);
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn cert(name: &str) -> CertificateDer<'static> {
    bytes(&fixture()["certificates"][name]).into()
}

fn time(seconds: u64) -> UnixTime {
    UnixTime::since_unix_epoch(Duration::from_secs(seconds))
}

fn now() -> UnixTime {
    time(fixture()["now"].as_u64().unwrap())
}

fn inner_with_root(root: CertificateDer<'static>) -> Arc<dyn ServerCertVerifier> {
    let mut roots = RootCertStore::empty();
    roots.add(root).unwrap();
    WebPkiServerVerifier::builder_with_provider(Arc::new(roots), Arc::new(crate::provider()))
        .build()
        .unwrap()
}

fn inner() -> Arc<dyn ServerCertVerifier> {
    inner_with_root(bytes(&fixture()["ca"]).into())
}

fn dss(bytes: &[u8]) -> DigitallySignedStruct {
    DigitallySignedStruct::read_bytes(bytes).unwrap()
}

fn validate(
    verifier: &Verifier,
    certificate: &CertificateDer<'_>,
    credential: &DelegatedCredential,
    cv: &DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, Error> {
    verifier.verify_tls13_delegated_credential(
        &bytes(&fixture()["message"]),
        certificate,
        credential,
        cv,
        now(),
    )
}

fn verify_original(
    verifier: &dyn ServerCertVerifier,
    certificate: &CertificateDer<'_>,
) -> Result<ServerCertVerified, Error> {
    verifier.verify_server_cert(
        certificate,
        &[],
        &ServerName::try_from("localhost").unwrap(),
        &[],
        now(),
    )
}

// Sign independently altered metadata with the actual leaf RSA key. A wrong
// delegated SPKI/algorithm must not be rejected merely due to a stale issuer
// signature over the previous credential.
fn reissue(public_key: &[u8], expected: SignatureScheme, offset: u32) -> DelegatedCredential {
    let mut raw = offset.to_be_bytes().to_vec();
    raw.extend_from_slice(&u16::from(expected).to_be_bytes());
    raw.extend_from_slice(&(public_key.len() as u32).to_be_bytes()[1..]);
    raw.extend_from_slice(public_key);
    let credential_len = raw.len();
    raw.extend_from_slice(&[8, 4, 0, 1, 0]);
    let unsigned = DelegatedCredential::from_bytes(&raw).unwrap();
    let key = crate::provider()
        .key_provider
        .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(bytes(
            &fixture()["issuer_key"],
        ))))
        .unwrap();
    let signer = key
        .choose_scheme(&[SignatureScheme::RSA_PSS_SHA256])
        .unwrap();
    let signature = signer
        .sign(&unsigned.server_signature_input(&cert("valid")))
        .unwrap();
    raw.truncate(credential_len + 2);
    raw.extend_from_slice(&(signature.len() as u16).to_be_bytes());
    raw.extend_from_slice(&signature);
    DelegatedCredential::from_bytes(&raw).unwrap()
}

#[test]
fn openssl_delegation_and_cv_authenticate_all_three_curves() {
    let inner = inner();
    let verifier = Verifier::new(inner.clone());
    let certificate = cert("valid");
    verify_original(&verifier, &certificate).unwrap();
    let message = bytes(&fixture()["message"]);
    for case in fixture()["curves"].as_array().unwrap() {
        let credential = DelegatedCredential::from_bytes(&bytes(&case["credential"])).unwrap();
        let cv = dss(&bytes(&case["certificate_verify"]));
        validate(&verifier, &certificate, &credential, &cv).unwrap();
        // CertificateVerify is signed by the delegated EC key, not by the
        // authenticated original RSA certificate key.
        assert!(
            inner
                .verify_tls13_signature(&message, &certificate, &cv)
                .is_err()
        );
        let mut changed = message.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert!(
            verifier
                .verify_tls13_delegated_credential(&changed, &certificate, &credential, &cv, now())
                .is_err()
        );
    }
}

#[test]
fn issuer_policy_is_distinct_from_delegated_key_rules() {
    let inner = inner();
    let verifier = Verifier::new(inner.clone());
    let cv = dss(&bytes(&fixture()["curves"][0]["certificate_verify"]));
    for case in fixture()["issuer_cases"].as_array().unwrap() {
        let certificate = CertificateDer::from(bytes(&case["certificate"]));
        let credential = DelegatedCredential::from_bytes(&bytes(&case["credential"])).unwrap();
        verify_original(&verifier, &certificate).unwrap();
        if credential.signature().scheme != SignatureScheme::RSA_PKCS1_SHA1 {
            // Demonstrate that strong PKCS1 and cross-curve fixtures contain
            // real correct signatures, independently of our narrower DC policy.
            inner
                .verify_tls12_signature(
                    &credential.server_signature_input(&certificate),
                    &certificate,
                    credential.signature(),
                )
                .unwrap();
        }
        assert_eq!(
            validate(&verifier, &certificate, &credential, &cv).is_ok(),
            case["accepted"].as_bool().unwrap(),
            "{}",
            case["name"]
        );
    }
}

#[test]
fn exact_certificate_context_and_both_signature_algorithms_are_bound() {
    let verifier = Verifier::new(inner());
    let case = &fixture()["curves"][0];
    let raw = bytes(&case["credential"]);
    let credential = DelegatedCredential::from_bytes(&raw).unwrap();
    let cv = dss(&bytes(&case["certificate_verify"]));
    verify_original(&verifier, &cert("alternate")).unwrap();
    assert!(validate(&verifier, &cert("alternate"), &credential, &cv).is_err());
    let signature_start = 9 + bytes(&case["spki"]).len();
    for index in [3, signature_start + 1, raw.len() - 1] {
        let mut changed = raw.clone();
        changed[index] ^= 1;
        let credential = DelegatedCredential::from_bytes(&changed).unwrap();
        assert!(validate(&verifier, &cert("valid"), &credential, &cv).is_err());
    }
    let mut wrong_cv = bytes(&case["certificate_verify"]);
    *wrong_cv.last_mut().unwrap() ^= 1;
    assert!(validate(&verifier, &cert("valid"), &credential, &dss(&wrong_cv)).is_err());
    for scheme in [
        SignatureScheme::ECDSA_SHA1_Legacy,
        SignatureScheme::RSA_PKCS1_SHA256,
        SignatureScheme::RSA_PSS_SHA256,
        SignatureScheme::ECDSA_NISTP384_SHA384,
    ] {
        let mut wrong = bytes(&case["certificate_verify"]);
        wrong[..2].copy_from_slice(&u16::from(scheme).to_be_bytes());
        assert!(validate(&verifier, &cert("valid"), &credential, &dss(&wrong)).is_err());
    }
    let input = credential.server_signature_input(&cert("valid"));
    let mut wrong_role = input.clone();
    let server = wrong_role
        .windows(6)
        .position(|part| part == b"server")
        .unwrap();
    wrong_role[server..server + 6].copy_from_slice(b"client");
    assert!(
        verifier
            .inner
            .verify_tls13_signature(&wrong_role, &cert("valid"), credential.signature())
            .is_err()
    );
}

#[test]
fn delegated_key_algorithm_and_curve_must_match_cv_even_with_a_valid_issuer() {
    let verifier = Verifier::new(inner());
    let case = &fixture()["curves"][0];
    let cv = dss(&bytes(&case["certificate_verify"]));
    let original = DelegatedCredential::from_bytes(&bytes(&case["credential"])).unwrap();
    let certificate = cert("valid");
    let (_, parsed) = x509_parser::parse_x509_certificate(certificate.as_ref()).unwrap();
    for public_key in [
        bytes(&fixture()["curves"][1]["spki"]),
        parsed.public_key().raw.to_vec(),
        vec![0x30, 0],
    ] {
        let credential = reissue(&public_key, cv.scheme, original.valid_time());
        verifier
            .inner
            .verify_tls13_signature(
                &credential.server_signature_input(&certificate),
                &certificate,
                credential.signature(),
            )
            .unwrap();
        assert!(validate(&verifier, &certificate, &credential, &cv).is_err());
    }
    for scheme in [
        SignatureScheme::ECDSA_SHA1_Legacy,
        SignatureScheme::RSA_PSS_SHA256,
    ] {
        let credential = reissue(&bytes(&case["spki"]), scheme, original.valid_time());
        let mut wire = bytes(&case["certificate_verify"]);
        wire[..2].copy_from_slice(&u16::from(scheme).to_be_bytes());
        assert!(validate(&verifier, &certificate, &credential, &dss(&wire)).is_err());
    }
}

#[test]
fn delegation_usage_key_usage_and_der_are_strict() {
    let offset =
        u32::try_from(now().as_secs() + 86400 - fixture()["not_before"].as_u64().unwrap()).unwrap();
    validate_certificate(&cert("valid"), offset, now()).unwrap();
    for name in [
        "missing_usage",
        "critical_usage",
        "malformed_usage",
        "duplicate_usage",
        "missing_key_usage",
        "wrong_key_usage",
    ] {
        assert!(
            validate_certificate(&cert(name), offset, now()).is_err(),
            "{name}"
        );
    }
    let mut trailing = cert("valid").to_vec();
    trailing.push(0);
    assert!(validate_certificate(&trailing.into(), offset, now()).is_err());
    let root: CertificateDer<'static> = bytes(&fixture()["ca"]).into();
    assert!(validate_certificate(&root, offset, now()).is_err());
}

#[test]
fn lifetime_is_remaining_seven_days_and_strictly_inside_certificate_expiry() {
    let not_before = fixture()["not_before"].as_u64().unwrap();
    let seconds = now().as_secs();
    let offset = |end| u32::try_from(end - not_before).unwrap();
    // valid_time may be years because it is relative to the old certificate,
    // while the permitted remaining validity is at most seven days.
    for end in [seconds, seconds + 1, seconds + 604800] {
        validate_certificate(&cert("valid"), offset(end), now()).unwrap();
    }
    for end in [seconds - 1, seconds + 604801] {
        assert!(validate_certificate(&cert("valid"), offset(end), now()).is_err());
    }
    validate_certificate(&cert("short"), offset(seconds + 86399), now()).unwrap();
    assert!(validate_certificate(&cert("short"), offset(seconds + 86400), now()).is_err());
    assert!(validate_certificate(&cert("valid"), u32::MAX, now()).is_err());
    assert!(validate_certificate(&cert("valid"), offset(seconds), time(u64::MAX)).is_err());
    assert!(validate_certificate(&cert("valid"), offset(seconds), time(not_before - 1)).is_err());
}

#[test]
fn wrapper_preserves_original_chain_name_pin_and_ordinary_algorithms() {
    let inner = inner();
    let verifier = Verifier::new(inner.clone());
    assert_eq!(
        verifier.supported_verify_schemes(),
        inner.supported_verify_schemes()
    );
    assert_eq!(
        verifier.supported_delegated_verify_schemes(),
        FIREFOX_SCHEMES
    );
    let certificate = cert("valid");
    verify_original(&verifier, &certificate).unwrap();
    let wrong_name = ServerName::try_from("wrong.invalid").unwrap();
    assert!(
        verifier
            .verify_server_cert(&certificate, &[], &wrong_name, &[], now())
            .is_err()
    );
    let wrong = Verifier::new(inner_with_root(CertificateDer::from(
        include_bytes!("../../tests/fixtures/p521-ca.der").to_vec(),
    )));
    assert!(verify_original(&wrong, &certificate).is_err());
    let pinned = Verifier::new(Arc::new(Pinned {
        inner,
        chain_calls: AtomicUsize::new(0),
    }));
    assert!(
        matches!(verify_original(&pinned, &certificate), Err(Error::General(s)) if s == "fixture pin rejected")
    );
    assert!(
        matches!(pinned.verify_ech_rejection_cert(&certificate, &[], &ServerName::try_from("localhost").unwrap(), &[], now()), Err(Error::General(s)) if s == "fixture ECH pin rejected")
    );
}

#[derive(Debug)]
struct Pinned {
    inner: Arc<dyn ServerCertVerifier>,
    chain_calls: AtomicUsize,
}
impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        cert: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        time: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        self.chain_calls.fetch_add(1, Ordering::SeqCst);
        self.inner
            .verify_server_cert(cert, chain, name, ocsp, time)?;
        Err(invalid("fixture pin rejected"))
    }
    fn verify_ech_rejection_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Err(invalid("fixture ECH pin rejected"))
    }
    fn verify_tls12_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(msg, cert, dss)
    }
    fn verify_tls13_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(msg, cert, dss)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

fn config(inner: Arc<dyn ServerCertVerifier>) -> ClientConfig {
    let mut config = ClientConfig::builder_with_provider(Arc::new(crate::provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(inner)
        .with_no_client_auth();
    config.time_provider = Arc::new(FixtureTime);
    config.cert_decompressors.clear();
    config.cert_compressors.clear();
    config
}

#[derive(Debug)]
struct FixtureTime;
impl rustls::time_provider::TimeProvider for FixtureTime {
    fn current_time(&self) -> Option<UnixTime> {
        Some(now())
    }
}

#[test]
fn opt_in_requires_capable_verifier_and_rejects_conflicting_configuration() {
    let plain = config(inner());
    assert!(!plain.enable_delegated_credentials);
    let mut unsupported = plain;
    unsupported.enable_delegated_credentials = true;
    assert!(ClientConnection::new(Arc::new(unsupported), "localhost".try_into().unwrap()).is_err());
    let mut base = config(Arc::new(Verifier::new(inner())));
    base.enable_delegated_credentials = true;
    assert!(ClientConnection::new(Arc::new(base.clone()), "localhost".try_into().unwrap()).is_ok());
    let mut early = base.clone();
    early.enable_early_data = true;
    assert!(ClientConnection::new(Arc::new(early), "localhost".try_into().unwrap()).is_err());
    let mut layout = base.clone();
    layout.client_hello_layout = Some(ClientHelloLayout::Chrome133);
    assert!(ClientConnection::new(Arc::new(layout), "localhost".try_into().unwrap()).is_err());
    assert!(
        rustls::quic::ClientConnection::new(
            Arc::new(base.clone()),
            rustls::quic::Version::V1,
            "localhost".try_into().unwrap(),
            vec![]
        )
        .is_err()
    );
    assert!(
        ClientConnection::new_reality(
            Arc::new(base),
            "localhost".try_into().unwrap(),
            Box::new(NoReality)
        )
        .is_err()
    );
}

#[derive(Debug)]
struct NoReality;
impl rustls::reality::ClientHooks for NoReality {
    fn start_key_exchange(
        &mut self,
        _: &'static dyn rustls::crypto::SupportedKxGroup,
    ) -> Result<Box<dyn rustls::crypto::ActiveKeyExchange>, Error> {
        panic!("DC conflict must fail before REALITY key exchange")
    }
    fn session_id(&mut self, _: &[u8]) -> Result<[u8; 32], Error> {
        panic!("DC conflict must fail before REALITY session")
    }
    fn server_hello(&mut self, _: &[u8], _: &[u8]) -> Result<(), Error> {
        panic!("DC conflict must fail before REALITY response")
    }
}

#[test]
fn delegated_advertisement_never_changes_ordinary_verify_schemes_or_enables_legacy_cv() {
    let inner = inner();
    for schemes in [
        vec![],
        vec![SignatureScheme::ECDSA_SHA1_Legacy],
        vec![SignatureScheme::RSA_PSS_SHA256],
        vec![SignatureScheme::ED25519; 2],
        vec![SignatureScheme::ED25519; 33],
    ] {
        assert!(Verifier::with_schemes(inner.clone(), schemes).is_err());
    }
    let narrow =
        Verifier::with_schemes(inner.clone(), vec![SignatureScheme::ECDSA_NISTP384_SHA384])
            .unwrap();
    let case = &fixture()["curves"][0];
    assert!(
        validate(
            &narrow,
            &cert("valid"),
            &DelegatedCredential::from_bytes(&bytes(&case["credential"])).unwrap(),
            &dss(&bytes(&case["certificate_verify"]))
        )
        .is_err()
    );
    let ed = Verifier::with_schemes(inner.clone(), vec![SignatureScheme::ED25519]).unwrap();
    assert_eq!(
        ed.supported_verify_schemes(),
        inner.supported_verify_schemes()
    );
}

#[derive(Debug)]
struct CountingStore {
    inner: ClientSessionMemoryCache,
    takes: AtomicUsize,
    inserts: AtomicUsize,
}
impl CountingStore {
    fn new() -> Self {
        Self {
            inner: ClientSessionMemoryCache::new(4),
            takes: AtomicUsize::new(0),
            inserts: AtomicUsize::new(0),
        }
    }
}
impl ClientSessionStore for CountingStore {
    fn set_kx_hint(&self, name: ServerName<'static>, group: NamedGroup) {
        self.inner.set_kx_hint(name, group)
    }
    fn kx_hint(&self, name: &ServerName<'_>) -> Option<NamedGroup> {
        self.inner.kx_hint(name)
    }
    fn set_tls12_session(&self, name: ServerName<'static>, value: Tls12ClientSessionValue) {
        self.inner.set_tls12_session(name, value)
    }
    fn tls12_session(&self, name: &ServerName<'_>) -> Option<Tls12ClientSessionValue> {
        self.inner.tls12_session(name)
    }
    fn remove_tls12_session(&self, name: &ServerName<'static>) {
        self.inner.remove_tls12_session(name)
    }
    fn insert_tls13_ticket(&self, name: ServerName<'static>, value: Tls13ClientSessionValue) {
        self.inserts.fetch_add(1, Ordering::SeqCst);
        self.inner.insert_tls13_ticket(name, value)
    }
    fn take_tls13_ticket(&self, name: &ServerName<'static>) -> Option<Tls13ClientSessionValue> {
        self.takes.fetch_add(1, Ordering::SeqCst);
        self.inner.take_tls13_ticket(name)
    }
}

fn transfer(from: &mut Connection, to: &mut Connection) -> bool {
    let mut wire = Vec::new();
    while from.wants_write() {
        from.write_tls(&mut wire).unwrap();
    }
    if wire.is_empty() {
        return false;
    }
    let mut wire = Cursor::new(wire);
    while wire.position() < wire.get_ref().len() as u64 {
        to.read_tls(&mut wire).unwrap();
        to.process_new_packets().unwrap();
    }
    true
}

fn handshake(client: &mut Connection, server: &mut Connection) {
    for _ in 0..32 {
        let progress = transfer(client, server) | transfer(server, client);
        if !progress && !client.is_handshaking() && !server.is_handshaking() {
            return;
        }
    }
    panic!("bounded handshake stalled");
}

#[test]
fn opt_in_disables_ticket_retrieval_and_storage_across_reuse_without_server_dc() {
    // A DC-capable client may receive a normal certificate. Even then the opt-in
    // is full-authentication-only, so a ticket must not bypass future DC expiry.
    let mut server = ServerConfig::builder_with_provider(Arc::new(crate::provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert("valid")],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(bytes(&fixture()["issuer_key"]))),
        )
        .unwrap();
    server.time_provider = Arc::new(FixtureTime);
    server.send_tls13_tickets = 2;
    server.cert_compressors.clear();
    server.cert_decompressors.clear();
    let server = Arc::new(server);
    let storage = Arc::new(CountingStore::new());
    let mut normal = config(Arc::new(Verifier::new(inner())));
    normal.resumption = Resumption::store(storage.clone());
    let mut enabled = normal.clone();
    enabled.enable_delegated_credentials = true;
    let normal = Arc::new(normal);
    let enabled = Arc::new(enabled);
    for (cfg, expect_resumed, check_unchanged) in [
        (normal.clone(), false, false),
        (normal.clone(), true, false),
        (enabled.clone(), false, true),
        (enabled, false, true),
    ] {
        let takes = storage.takes.load(Ordering::SeqCst);
        let inserts = storage.inserts.load(Ordering::SeqCst);
        let mut client = Connection::Client(
            ClientConnection::new(cfg, "localhost".try_into().unwrap()).unwrap(),
        );
        let mut peer = Connection::Server(ServerConnection::new(server.clone()).unwrap());
        handshake(&mut client, &mut peer);
        assert_eq!(
            client.handshake_kind() == Some(HandshakeKind::Resumed),
            expect_resumed
        );
        assert_eq!(
            peer.handshake_kind() == Some(HandshakeKind::Resumed),
            expect_resumed
        );
        let mut client_exporter = [0; 32];
        let mut peer_exporter = [0; 32];
        client
            .export_keying_material(&mut client_exporter, b"dc reuse", Some(b"bound"))
            .unwrap();
        peer.export_keying_material(&mut peer_exporter, b"dc reuse", Some(b"bound"))
            .unwrap();
        assert_eq!(client_exporter, peer_exporter);
        client.writer().write_all(b"authenticated").unwrap();
        transfer(&mut client, &mut peer);
        let mut data = [0; 13];
        peer.reader().read_exact(&mut data).unwrap();
        assert_eq!(&data, b"authenticated");
        if check_unchanged {
            assert_eq!(storage.takes.load(Ordering::SeqCst), takes);
            assert_eq!(storage.inserts.load(Ordering::SeqCst), inserts);
        } else {
            assert!(storage.takes.load(Ordering::SeqCst) > takes);
            assert!(storage.inserts.load(Ordering::SeqCst) > inserts);
        }
        client.send_close_notify();
        peer.send_close_notify();
        handshake(&mut client, &mut peer);
        assert_eq!(client.reader().read(&mut [0]).unwrap(), 0);
        assert_eq!(peer.reader().read(&mut [0]).unwrap(), 0);
    }
}

#[test]
fn public_parser_rejects_empty_truncated_oversized_and_trailing_credentials() {
    let raw = bytes(&fixture()["curves"][0]["credential"]);
    for n in 0..raw.len() {
        assert!(DelegatedCredential::from_bytes(&raw[..n]).is_err(), "{n}");
    }
    let mut trailing = raw.clone();
    trailing.push(0);
    assert!(DelegatedCredential::from_bytes(&trailing).is_err());
    for length in [[0, 0, 0], [0, 0x10, 1], [0xff; 3]] {
        let mut invalid = raw.clone();
        invalid[6..9].copy_from_slice(&length);
        assert!(DelegatedCredential::from_bytes(&invalid).is_err());
    }
    let mut empty_signature = raw;
    let at = 9 + bytes(&fixture()["curves"][0]["spki"]).len() + 2;
    empty_signature[at..at + 2].fill(0);
    assert!(DelegatedCredential::from_bytes(&empty_signature).is_err());
}

#[test]
fn openssl_ed25519_delegated_key_requires_explicit_advertisement() {
    let case = &fixture()["ed25519"];
    let credential = DelegatedCredential::from_bytes(&bytes(&case["credential"])).unwrap();
    let cv = dss(&bytes(&case["certificate_verify"]));
    let firefox = Verifier::new(inner());
    assert!(validate(&firefox, &cert("valid"), &credential, &cv).is_err());
    let verifier = Verifier::with_schemes(inner(), vec![SignatureScheme::ED25519]).unwrap();
    verify_original(&verifier, &cert("valid")).unwrap();
    validate(&verifier, &cert("valid"), &credential, &cv).unwrap();
    let mut wrong = bytes(&case["certificate_verify"]);
    *wrong.last_mut().unwrap() ^= 1;
    assert!(validate(&verifier, &cert("valid"), &credential, &dss(&wrong)).is_err());
}

#[test]
fn dc_issuer_checks_do_not_depend_on_inner_tls_signature_assertions() {
    #[derive(Debug)]
    struct SignatureBypass(Arc<dyn ServerCertVerifier>);
    impl ServerCertVerifier for SignatureBypass {
        fn verify_server_cert(
            &self,
            cert: &CertificateDer<'_>,
            chain: &[CertificateDer<'_>],
            name: &ServerName<'_>,
            ocsp: &[u8],
            time: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            self.0.verify_server_cert(cert, chain, name, ocsp, time)
        }
        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.0.supported_verify_schemes()
        }
    }
    let verifier = Verifier::new(Arc::new(SignatureBypass(inner())));
    let case = &fixture()["curves"][0];
    let mut raw = bytes(&case["credential"]);
    *raw.last_mut().unwrap() ^= 1;
    let cv = dss(&bytes(&case["certificate_verify"]));
    verify_original(&verifier, &cert("valid")).unwrap();
    assert!(
        validate(
            &verifier,
            &cert("valid"),
            &DelegatedCredential::from_bytes(&raw).unwrap(),
            &cv
        )
        .is_err()
    );
    for case in fixture()["issuer_cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case["name"].as_str().unwrap().ends_with("-cross"))
    {
        let certificate = bytes(&case["certificate"]).into();
        verify_original(&verifier, &certificate).unwrap();
        let credential = DelegatedCredential::from_bytes(&bytes(&case["credential"])).unwrap();
        assert!(validate(&verifier, &certificate, &credential, &cv).is_err());
    }
}
