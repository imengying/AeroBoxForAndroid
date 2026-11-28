//! The old client versions remain explicit and cannot weaken TLS1.3 downgrade checks.
use rustls::{ClientConfig, ClientConnection, ProtocolVersion};
use std::{io::Read, sync::Arc};

const VERSIONS: &[ProtocolVersion] = &[
    ProtocolVersion::TLSv1_0,
    ProtocolVersion::TLSv1_1,
    ProtocolVersion::TLSv1_2,
    ProtocolVersion::TLSv1_3,
];

fn config() -> ClientConfig {
    let mut provider = aerobox_crypto::provider();
    provider
        .cipher_suites
        .extend(aerobox_crypto::legacy_cbc::suites());
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    config
        .enable_legacy_tls(&aerobox_crypto::legacy_provider::LEGACY_TLS, VERSIONS)
        .unwrap();
    config
}

#[test]
fn tls13_offer_rejects_both_downgrade_markers_for_every_lower_version() {
    for &version in &VERSIONS[..3] {
        for marker in [b"DOWNGRD\0", b"DOWNGRD\x01"] {
            let mut client =
                ClientConnection::new(Arc::new(config()), "localhost".try_into().unwrap()).unwrap();
            client.write_tls(&mut Vec::new()).unwrap();
            let mut body = u16::from(version).to_be_bytes().to_vec();
            let mut random = [42; 32];
            random[24..].copy_from_slice(marker);
            body.extend(random);
            body.push(0);
            body.extend(0xc013u16.to_be_bytes());
            body.extend([0, 0, 0]);
            let mut message = vec![2, 0, (body.len() >> 8) as u8, body.len() as u8];
            message.extend(body);
            let mut record = vec![22, 3, 1, (message.len() >> 8) as u8, message.len() as u8];
            record.extend(message);
            client.read_tls(&mut record.as_slice()).unwrap();
            let error = client.process_new_packets().unwrap_err();
            assert!(
                format!("{error:?}").contains("AttemptedDowngrade"),
                "{version:?}: {error:?}"
            );
            assert_eq!(client.process_new_packets().unwrap_err(), error);
            assert!(client.reader().read_to_end(&mut Vec::new()).is_err());
        }
    }
}

#[test]
fn mixed_version_opt_in_requires_real_modern_and_old_cipher_implementations() {
    let mut old_only =
        ClientConfig::builder_with_provider(Arc::new(aerobox_crypto::legacy_provider::provider()))
            .with_protocol_versions(&[&rustls::version::TLS12])
            .unwrap()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
    assert!(
        old_only
            .enable_legacy_tls(&aerobox_crypto::legacy_provider::LEGACY_TLS, VERSIONS)
            .is_err()
    );
    let mut modern_only = ClientConfig::builder_with_provider(Arc::new(aerobox_crypto::provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    assert!(
        modern_only
            .enable_legacy_tls(&aerobox_crypto::legacy_provider::LEGACY_TLS, VERSIONS)
            .is_err()
    );
    ClientConnection::new(Arc::new(config()), "localhost".try_into().unwrap()).unwrap();
}
