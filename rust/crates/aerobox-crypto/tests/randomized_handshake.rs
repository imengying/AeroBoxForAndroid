//! Real authentication, independent shares and application data for dynamic plans.
#[path = "support/randomized.rs"]
mod support;
use rustls::{
    ClientConfig, ClientConnection, Connection, Error, NamedGroup, RootCertStore, ServerConfig,
    ServerConnection, SignatureScheme,
    client::WebPkiServerVerifier,
    pki_types::{CertificateDer, PrivatePkcs8KeyDer, UnixTime},
    server::WebPkiClientVerifier,
    time_provider::TimeProvider,
};
use std::{
    io::{ErrorKind, Read, Write},
    sync::Arc,
    time::Duration,
};
#[derive(Debug)]
struct Clock;
impl TimeProvider for Clock {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(Duration::from_secs(1893456000)))
    }
}
fn roots() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    for cert in [
        include_bytes!("fixtures/rsa-cert.der").as_slice(),
        include_bytes!("fixtures/ecdsa-cert.der").as_slice(),
        include_bytes!("fixtures/p521-ca.der").as_slice(),
    ] {
        roots.add(cert.into()).unwrap();
    }
    roots
}
fn client(plan: &serde_json::Value, mutual: bool) -> ClientConfig {
    let mut config = support::config(plan, false).unwrap();
    config.time_provider = Arc::new(Clock);
    let verifier = WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots()),
        config.crypto_provider().clone(),
    )
    .build()
    .unwrap();
    config.dangerous().set_certificate_verifier(verifier);
    if mutual {
        let key = rustls::sign::CertifiedKey::from_der(
            vec![include_bytes!("fixtures/p521-cert.der").as_slice().into()],
            PrivatePkcs8KeyDer::from(include_bytes!("fixtures/p521-key.der").to_vec()).into(),
            &aerobox_crypto::provider(),
        )
        .unwrap();
        config.client_auth_cert_resolver = Arc::new(rustls::sign::SingleCertAndKey::from(key));
        config.max_fragment_size = Some(512);
    }
    config
}
fn server(
    plan: &serde_json::Value,
    suite: u16,
    group: u16,
    mutual: bool,
    force: Option<SignatureScheme>,
) -> ServerConfig {
    let mut provider = aerobox_crypto::randomized::provider(&[suite]).unwrap();
    provider.kx_groups = vec![support::production_hybrid::group(NamedGroup::from(group))];
    let version = if (0x1301..=0x1303).contains(&suite) {
        &rustls::version::TLS13
    } else {
        &rustls::version::TLS12
    };
    let builder = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[version])
        .unwrap();
    let builder = if mutual {
        // ClientCertificateRequest is independent of the client's offer for
        // server signatures. Demand P521/SHA512 even when the plan omits it.
        let mut auth = aerobox_crypto::provider();
        let algorithms = auth.signature_verification_algorithms;
        let index = algorithms
            .mapping
            .iter()
            .position(|(s, _)| *s == SignatureScheme::ECDSA_NISTP521_SHA512)
            .unwrap();
        auth.signature_verification_algorithms.mapping = &algorithms.mapping[index..index + 1];
        builder.with_client_cert_verifier(
            WebPkiClientVerifier::builder_with_provider(Arc::new(roots()), Arc::new(auth))
                .build()
                .unwrap(),
        )
    } else {
        builder.with_no_client_auth()
    };
    let ecdsa = matches!(
        suite,
        0xcca9 | 0xc02b | 0xc02c | 0xc023 | 0xc009 | 0xc00a | 0xc007
    );
    let (cert, key) = if ecdsa {
        (
            include_bytes!("fixtures/ecdsa-cert.der").as_slice(),
            include_bytes!("fixtures/ecdsa-key.der").as_slice(),
        )
    } else {
        (
            include_bytes!("fixtures/rsa-cert.der").as_slice(),
            include_bytes!("fixtures/rsa-key.der").as_slice(),
        )
    };
    let mut key = rustls::sign::CertifiedKey::from_der(
        vec![CertificateDer::from(cert)],
        PrivatePkcs8KeyDer::from(key.to_vec()).into(),
        &aerobox_crypto::provider(),
    )
    .unwrap();
    if let Some(scheme) = force {
        key.key = Arc::new(ForcedSignature {
            key: key.key.clone(),
            scheme,
        });
    }
    let mut config =
        builder.with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(key)));
    config.time_provider = Arc::new(Clock);
    config.require_ems = false;
    config.send_tls13_tickets = 0;
    if support::ids(plan, "extensions").contains(&16) {
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    }
    config
}
#[derive(Debug)]
struct ForcedSignature {
    key: Arc<dyn rustls::sign::SigningKey>,
    scheme: SignatureScheme,
}
impl rustls::sign::SigningKey for ForcedSignature {
    fn choose_scheme(&self, _offered: &[SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
        self.key.choose_scheme(&[self.scheme])
    }
    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        self.key.algorithm()
    }
    fn public_key(&self) -> Option<rustls::pki_types::SubjectPublicKeyInfoDer<'_>> {
        self.key.public_key()
    }
}
fn drain(c: &mut Connection) -> Vec<u8> {
    let mut wire = vec![];
    while c.wants_write() {
        c.write_tls(&mut wire).unwrap();
    }
    wire
}
fn feed(c: &mut Connection, wire: &[u8]) -> Result<(), Error> {
    for chunk in wire.chunks(137) {
        let mut chunk = chunk;
        while !chunk.is_empty() {
            assert!(c.read_tls(&mut chunk).unwrap() > 0);
            c.process_new_packets()?;
        }
    }
    Ok(())
}
fn handshake(a: &mut Connection, b: &mut Connection) -> Result<(), Error> {
    for _ in 0..32 {
        let left = drain(a);
        feed(b, &left)?;
        let right = drain(b);
        feed(a, &right)?;
        if !a.is_handshaking() && !b.is_handshaking() && left.is_empty() && right.is_empty() {
            return Ok(());
        }
    }
    panic!("handshake did not settle")
}
fn pair(
    plan: &serde_json::Value,
    suite: u16,
    group: u16,
    mutual: bool,
    name: &str,
    force: Option<SignatureScheme>,
) -> (Connection, Connection) {
    (
        Connection::Client(
            ClientConnection::new(
                Arc::new(client(plan, mutual)),
                name.to_owned().try_into().unwrap(),
            )
            .unwrap(),
        ),
        Connection::Server(
            ServerConnection::new(Arc::new(server(plan, suite, group, mutual, force))).unwrap(),
        ),
    )
}
fn exchange(a: &mut Connection, b: &mut Connection) {
    for reverse in [false, true] {
        let (sender, receiver) = if reverse {
            (&mut *b, &mut *a)
        } else {
            (&mut *a, &mut *b)
        };
        let payload: Vec<_> = (0..65537).map(|i| ((i * 31 + 17) % 251) as u8).collect();
        for chunk in payload.chunks(8192) {
            sender.writer().write_all(chunk).unwrap();
            feed(receiver, &drain(sender)).unwrap();
            let mut actual = vec![0; chunk.len()];
            receiver.reader().read_exact(&mut actual).unwrap();
            assert_eq!(actual, chunk);
        }
    }
    a.send_close_notify();
    feed(b, &drain(a)).unwrap();
    assert_eq!(b.reader().read(&mut [0]).unwrap(), 0);
    b.send_close_notify();
    feed(a, &drain(b)).unwrap();
    assert_eq!(a.reader().read(&mut [0]).unwrap(), 0);
}
#[test]
fn dynamic_tls13_all_selected_shares_and_hrr_retain_independent_private_keys() {
    let rows: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("fixtures/randomized-plans.json")).unwrap();
    let mut count = 0;
    for row in rows.iter().take(8) {
        let plan = &row["plan"];
        if support::structure(plan).is_err() {
            continue;
        }
        let suite = support::ids(plan, "suites")[0];
        for group in support::ids(plan, "groups") {
            for mutual in [false, true] {
                let (mut a, mut b) = pair(plan, suite, group, mutual, "localhost", None);
                handshake(&mut a, &mut b).unwrap();
                assert_eq!(
                    u16::from(a.negotiated_key_exchange_group().unwrap().name()),
                    group
                );
                let retry = !support::ids(plan, "shares").contains(&group);
                assert_eq!(
                    a.handshake_kind() == Some(rustls::HandshakeKind::FullWithHelloRetryRequest),
                    retry
                );
                assert_eq!(b.peer_certificates().is_some(), mutual);
                assert_eq!(
                    a.export_keying_material([0; 32], b"randomized live", Some(b"context"))
                        .unwrap(),
                    b.export_keying_material([0; 32], b"randomized live", Some(b"context"))
                        .unwrap()
                );
                exchange(&mut a, &mut b);
                count += 1;
            }
        }
    }
    assert!(count >= 40);
}
#[test]
fn dynamic_tls12_authentication_optional_ems_data_and_close() {
    let rows: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("fixtures/randomized-plans.json")).unwrap();
    let mut count = 0;
    let mut ems = [0, 0];
    for row in rows.iter().take(8) {
        let plan = &row["plan"];
        if support::structure(plan).is_err() {
            continue;
        }
        for suite in support::ids(plan, "suites").into_iter().filter(|s| {
            matches!(
                s,
                0xcca8
                    | 0xcca9
                    | 0xc02f
                    | 0xc02b
                    | 0xc030
                    | 0xc02c
                    | 0xc027
                    | 0xc013
                    | 0xc023
                    | 0xc009
                    | 0xc014
                    | 0xc00a
                    | 0xc012
            )
        }) {
            let (mut a, mut b) = pair(plan, suite, 23, true, "localhost", None);
            handshake(&mut a, &mut b).unwrap();
            assert!(b.peer_certificates().is_some());
            let expected = support::ids(plan, "extensions").contains(&23);
            ems[usize::from(expected)] += 1;
            let export = a.export_keying_material([0; 32], b"randomized live", None);
            if expected {
                assert_eq!(
                    export.unwrap(),
                    b.export_keying_material([0; 32], b"randomized live", None)
                        .unwrap()
                );
            } else {
                assert!(
                    export
                        .unwrap_err()
                        .to_string()
                        .contains("require extended master secret")
                );
            }
            exchange(&mut a, &mut b);
            count += 1;
        }
    }
    assert!(count >= 30 && ems.iter().all(|n| *n > 0));
}
#[test]
fn actual_sent_signature_list_and_hostname_are_enforced_before_data() {
    let rows: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("fixtures/randomized-plans.json")).unwrap();
    let plan = &rows[3]["plan"];
    assert!(!support::ids(plan, "signatures").contains(&0x0806));
    for suite in [0x1301, 0xc02f] {
        let (mut a, mut b) = pair(
            plan,
            suite,
            23,
            false,
            "localhost",
            Some(SignatureScheme::RSA_PSS_SHA512),
        );
        assert_eq!(
            handshake(&mut a, &mut b).unwrap_err(),
            Error::PeerMisbehaved(rustls::PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme)
        );
        let mut output = [0; 16];
        assert_eq!(
            a.reader().read(&mut output).unwrap_err().kind(),
            ErrorKind::WouldBlock
        );
        assert_eq!(output, [0; 16]);
        let (mut a, mut b) = pair(plan, suite, 23, false, "wrong.example", None);
        assert!(matches!(
            handshake(&mut a, &mut b),
            Err(Error::InvalidCertificate(
                rustls::CertificateError::NotValidForNameContext { .. }
            ))
        ));
    }
}
