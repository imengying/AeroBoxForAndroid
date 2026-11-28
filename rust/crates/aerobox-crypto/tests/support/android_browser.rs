//! Android Safari16/iOS14 fingerprint configuration for independent wire tests.
use rustls::{
    ClientConfig, NamedGroup, ProtocolVersion, RootCertStore,
    client::{ClientHelloLayout, Resumption},
};
use std::sync::Arc;

pub fn config(profile: ClientHelloLayout, mutual: bool) -> ClientConfig {
    with_version_policy(profile, mutual, false)
}

pub fn with_version_policy(
    profile: ClientHelloLayout,
    mutual: bool,
    tls13_only: bool,
) -> ClientConfig {
    let crypto = match profile {
        ClientHelloLayout::Safari16 => aerobox_crypto::android_browser::Profile::Safari16,
        ClientHelloLayout::Ios14 => aerobox_crypto::android_browser::Profile::Ios14,
        _ => unreachable!(),
    };
    let provider = aerobox_crypto::android_browser::provider(crypto);
    let mut roots = RootCertStore::empty();
    roots
        .add(include_bytes!("../fixtures/rsa-cert.der").as_slice().into())
        .unwrap();
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
                &aerobox_crypto::legacy_tdes::LEGACY_TLS_WITH_TDES,
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
    config.resumption = Resumption::disabled();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config.cert_compressors.clear();
    config.cert_decompressors = if profile == ClientHelloLayout::Safari16 {
        vec![rustls::compress::ZLIB_DECOMPRESSOR]
    } else {
        vec![]
    };
    config.initial_key_share_groups = vec![NamedGroup::X25519];
    config.enable_tls12_renegotiation = !tls13_only;
    config.client_hello_layout = Some(profile);
    config
}

#[derive(Debug)]
struct FixtureTime;
impl rustls::time_provider::TimeProvider for FixtureTime {
    fn current_time(&self) -> Option<rustls::pki_types::UnixTime> {
        Some(rustls::pki_types::UnixTime::since_unix_epoch(
            std::time::Duration::from_secs(1893456000),
        ))
    }
}
