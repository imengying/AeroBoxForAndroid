//! A small validation bridge compiling the actual production REALITY crypto
//! modules, without the entire asynchronous protocol kernel. Configuration and
//! wall-clock adapters below are test scaffolding, not another implementation.
#![allow(dead_code)]
use std::sync::Arc;

#[path = "../../../../../vendor/shoes/src/buf_reader.rs"]
mod buf_reader;
mod crypto;
mod clock {
    pub fn unix_seconds() -> std::io::Result<u64> {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(std::io::Error::other)
    }
}
mod reality;

pub fn new_client(browser: bool) -> rustls::ClientConnection {
    let mut provider = aerobox_crypto::provider();
    provider
        .cipher_suites
        .extend(aerobox_crypto::legacy_cbc::suites());
    provider
        .cipher_suites
        .extend(aerobox_crypto::legacy_rsa::suites());
    provider.kx_groups.insert(
        0,
        crypto::rustcrypto_kx::group(rustls::NamedGroup::X25519MLKEM768),
    );
    let (hooks, verifier) = reality::authentication(
        provider
            .signature_verification_algorithms
            .supported_schemes(),
    );
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config.application_settings = Some(
        rustls::client::ApplicationSettings::new(
            rustls::client::ApplicationSettingsCodepoint::Chrome,
            vec![(b"h2".to_vec(), vec![])],
        )
        .unwrap(),
    );
    config.initial_key_share_groups = vec![
        rustls::NamedGroup::X25519MLKEM768,
        rustls::NamedGroup::X25519,
    ];
    if browser {
        config.initial_key_share_groups = vec![rustls::NamedGroup::X25519];
        config.client_hello_layout = Some(rustls::client::ClientHelloLayout::Chrome133);
    }
    rustls::ClientConnection::new_reality(Arc::new(config), "cover.test".try_into().unwrap(), hooks)
        .unwrap()
}
