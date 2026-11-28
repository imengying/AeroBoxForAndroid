//! Explicit Firefox120 policy shared by wire and independent handshake tests.
use rustls::{
    ClientConfig, NamedGroup, RootCertStore,
    client::{ClientHelloLayout, Resumption, WebPkiServerVerifier},
};
use std::sync::Arc;

pub fn config(mutual: bool, tls13_only: bool) -> ClientConfig {
    let provider = Arc::new(aerobox_crypto::firefox::provider());
    let mut roots = RootCertStore::empty();
    for certificate in [
        include_bytes!("../fixtures/rsa-cert.der").as_slice(),
        include_bytes!("../fixtures/ecdsa-cert.der").as_slice(),
        include_bytes!("../fixtures/p521-ca.der").as_slice(),
    ] {
        roots.add(certificate.into()).unwrap();
    }
    let verifier = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .unwrap();
    let verifier = aerobox_crypto::delegated_credentials::Verifier::new(verifier);
    let versions = if tls13_only {
        vec![&rustls::version::TLS13]
    } else {
        vec![&rustls::version::TLS13, &rustls::version::TLS12]
    };
    let builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&versions)
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier));
    let mut config = if mutual {
        builder
            .with_client_auth_cert(
                vec![include_bytes!("../fixtures/rsa-cert.der").as_slice().into()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(
                    include_bytes!("../fixtures/rsa-key.der").to_vec(),
                )
                .into(),
            )
            .unwrap()
    } else {
        builder.with_no_client_auth()
    };
    config.time_provider = Arc::new(FixtureTime);
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config.cert_compressors.clear();
    config.cert_decompressors.clear();
    config.initial_key_share_groups = vec![NamedGroup::X25519, NamedGroup::secp256r1];
    config.enable_tls12_renegotiation = !tls13_only;
    config.resumption = Resumption::disabled();
    config.enable_delegated_credentials = true;
    config.advertise_record_size_limit = true;
    config.client_hello_layout = Some(ClientHelloLayout::Firefox120);
    config
}

#[derive(Debug)]
struct FixtureTime;
impl rustls::time_provider::TimeProvider for FixtureTime {
    fn current_time(&self) -> Option<rustls::pki_types::UnixTime> {
        Some(rustls::pki_types::UnixTime::since_unix_epoch(
            std::time::Duration::from_secs(1_893_456_000),
        ))
    }
}
