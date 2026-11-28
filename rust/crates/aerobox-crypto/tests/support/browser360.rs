//! Full pinned 360 7.5 configuration; fixtures authenticate at their valid time.
use rustls::{ClientConfig, ProtocolVersion, RootCertStore, client::ClientHelloLayout};
use std::sync::Arc;

pub fn configure(config: &mut ClientConfig) {
    config.cert_compressors.clear();
    config.cert_decompressors.clear();
    config.alpn_protocols = ["spdy/2", "spdy/3", "spdy/3.1", "http/1.1"]
        .map(|s| s.as_bytes().to_vec())
        .into();
    config.enable_tls12_renegotiation = true;
    config.require_ems = false;
    config
        .enable_legacy_tls(
            &aerobox_crypto::browser360::LEGACY_TLS,
            &[
                ProtocolVersion::TLSv1_0,
                ProtocolVersion::TLSv1_1,
                ProtocolVersion::TLSv1_2,
            ],
        )
        .unwrap();
    config.client_hello_layout = Some(ClientHelloLayout::Browser360_7_5);
    config.time_provider = Arc::new(FixtureTime);
}

pub fn config() -> ClientConfig {
    let mut roots = RootCertStore::empty();
    roots
        .add(include_bytes!("../fixtures/rsa-cert.der").as_slice().into())
        .unwrap();
    roots
        .add(
            include_bytes!("../fixtures/ecdsa-cert.der")
                .as_slice()
                .into(),
        )
        .unwrap();
    let mut config =
        ClientConfig::builder_with_provider(Arc::new(aerobox_crypto::browser360::provider()))
            .with_protocol_versions(&[&rustls::version::TLS12])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    configure(&mut config);
    config
}

#[derive(Debug)]
pub struct FixtureTime;
impl rustls::time_provider::TimeProvider for FixtureTime {
    fn current_time(&self) -> Option<rustls::pki_types::UnixTime> {
        Some(rustls::pki_types::UnixTime::since_unix_epoch(
            std::time::Duration::from_secs(1893456000),
        ))
    }
}
