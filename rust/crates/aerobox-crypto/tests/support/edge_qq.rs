//! Shared configuration for the independently checked Edge85/QQ11.1 profiles.
use rustls::{
    ClientConfig, NamedGroup, ProtocolVersion, RootCertStore,
    client::{ApplicationSettings, ApplicationSettingsCodepoint, ClientHelloLayout},
    pki_types::UnixTime,
    time_provider::TimeProvider,
};
use std::{sync::Arc, time::Duration};

#[derive(Debug)]
struct FixtureTime;
impl TimeProvider for FixtureTime {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(Duration::from_secs(1893456000)))
    }
}

pub fn config(profile: ClientHelloLayout, mutual: bool) -> ClientConfig {
    with_version_policy(profile, mutual, false)
}

pub fn with_version_policy(
    profile: ClientHelloLayout,
    mutual: bool,
    tls13_only: bool,
) -> ClientConfig {
    assert!(matches!(
        profile,
        ClientHelloLayout::Edge85 | ClientHelloLayout::Qq11_1
    ));
    let mut roots = RootCertStore::empty();
    roots
        .add(include_bytes!("../fixtures/rsa-cert.der").as_slice().into())
        .unwrap();
    let mut provider = aerobox_crypto::provider();
    provider
        .cipher_suites
        .extend(aerobox_crypto::legacy_cbc::suites());
    provider
        .cipher_suites
        .extend(aerobox_crypto::legacy_rsa::suites());
    let versions = if tls13_only {
        vec![&rustls::version::TLS13]
    } else {
        vec![&rustls::version::TLS13, &rustls::version::TLS12]
    };
    let builder = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&versions)
        .unwrap()
        .with_root_certificates(roots);
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
    if !tls13_only {
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
    }
    config.time_provider = Arc::new(FixtureTime);
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
    config.enable_tls12_renegotiation = !tls13_only;
    config.client_hello_layout = Some(profile);
    config
}
