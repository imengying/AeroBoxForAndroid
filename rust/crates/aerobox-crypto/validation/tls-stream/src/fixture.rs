use rustls::{
    ClientConfig, RootCertStore,
    client::{ApplicationSettings, ApplicationSettingsCodepoint, ClientHelloLayout},
    pki_types::UnixTime,
    time_provider::TimeProvider,
};
use std::{sync::Arc, time::Duration};
#[path = "../../../../../vendor/shoes/src/crypto/rustcrypto_kx.rs"]
mod production_hybrid;
#[derive(Debug)]
struct FixedTime;
impl TimeProvider for FixedTime {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(Duration::from_secs(1893456000)))
    }
}
pub fn config(enabled: bool, chrome: bool, mutual: bool) -> ClientConfig {
    let mut roots = RootCertStore::empty();
    roots
        .add(
            include_bytes!("../../../tests/fixtures/rsa-cert.der")
                .as_slice()
                .into(),
        )
        .unwrap();
    let mut provider = aerobox_crypto::provider();
    provider
        .cipher_suites
        .extend(aerobox_crypto::legacy_cbc::suites());
    provider
        .cipher_suites
        .extend(aerobox_crypto::legacy_rsa::suites());
    provider.kx_groups.insert(
        0,
        production_hybrid::group(rustls::NamedGroup::X25519MLKEM768),
    );
    let builder = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots);
    let mut config = if mutual {
        builder
            .with_client_auth_cert(
                vec![
                    include_bytes!("../../../tests/fixtures/rsa-cert.der")
                        .as_slice()
                        .into(),
                ],
                rustls::pki_types::PrivatePkcs8KeyDer::from(
                    include_bytes!("../../../tests/fixtures/rsa-key.der").to_vec(),
                )
                .into(),
            )
            .unwrap()
    } else {
        builder.with_no_client_auth()
    };
    config.time_provider = Arc::new(FixedTime);
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config.enable_tls12_renegotiation = enabled;
    config.max_fragment_size = Some(137);
    if chrome {
        config.application_settings = Some(
            ApplicationSettings::new(
                ApplicationSettingsCodepoint::Chrome,
                vec![(b"h2".to_vec(), vec![])],
            )
            .unwrap(),
        );
        config.initial_key_share_groups = vec![
            rustls::NamedGroup::X25519MLKEM768,
            rustls::NamedGroup::X25519,
        ];
        config.client_hello_layout = Some(ClientHelloLayout::Chrome133);
    }
    config
}
