//! Native 360 policy, strong name/pin verification and real asynchronous stream.
use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};

fn policy() -> TlsClientOptions {
    TlsClientOptions {
        fingerprint: Some(TlsClientFingerprint::Browser360_7_5),
        ..Default::default()
    }
}
#[test]
fn browser360_native_policy_separates_real_capabilities_and_advertisement() {
    let options = policy();
    let config = client(&options, false).unwrap();
    assert_eq!(
        config.client_hello_layout,
        Some(ClientHelloLayout::Browser360_7_5)
    );
    assert!(config.enable_tls12_renegotiation && !config.require_ems);
    assert!(config.cert_decompressors.is_empty() && config.initial_key_share_groups.is_empty());
    assert_eq!(
        config.alpn_protocols,
        ["spdy/2", "spdy/3", "spdy/3.1", "http/1.1"].map(|s| s.as_bytes().to_vec())
    );
    assert!(client(&options, true).is_err());
    let names = profile_provider(TlsClientFingerprint::Browser360_7_5)
        .unwrap()
        .cipher_suites
        .iter()
        .map(|s| s.suite().as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(names.len(), 13);
    let mut exact = options.clone();
    exact.cipher_suites = names;
    client(&exact, false).unwrap();
    exact.cipher_suites.reverse();
    assert!(client(&exact, false).is_err());
    for bad in [
        TlsClientOptions {
            min_version: Some(TlsVersion::V12),
            ..options.clone()
        },
        TlsClientOptions {
            max_version: Some(TlsVersion::V13),
            ..options.clone()
        },
        TlsClientOptions {
            cipher_suites: vec!["TLS_RSA_WITH_AES_256_CBC_SHA256".into()],
            ..options.clone()
        },
        TlsClientOptions {
            cipher_suites: vec!["TLS_RSA_WITH_RC4_128_MD5".into()],
            ..options.clone()
        },
    ] {
        assert!(client(&bad, false).is_err());
    }
    let groups =
        serde_json::from_str::<TlsKeyExchangeGroups>(r#"["SecP256r1","SecP384r1","SecP521r1"]"#)
            .unwrap();
    validate_policy(&groups, &options).unwrap();
    let groups =
        serde_json::from_str::<TlsKeyExchangeGroups>(r#"["X25519","SecP256r1","SecP384r1"]"#)
            .unwrap();
    assert!(validate_policy(&groups, &options).is_err());
    let ordinary = client(&Default::default(), false).unwrap();
    assert!(ordinary.client_hello_layout.is_none());
    assert!(!ordinary.enable_tls12_renegotiation);
}

fn native_pair(
    config: ClientConfig,
    name: &str,
    cert: &rcgen::CertifiedKey<rcgen::KeyPair>,
) -> Result<(), rustls::Error> {
    let mut provider = aerobox_crypto::browser360::provider();
    provider
        .cipher_suites
        .retain(|s| u16::from(s.suite()) == 0xc009);
    let mut server = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )
        .unwrap();
    server.require_ems = false;
    let mut server = rustls::ServerConnection::new(Arc::new(server))?;
    let mut client =
        rustls::ClientConnection::new(Arc::new(config), name.to_owned().try_into().unwrap())?;
    for _ in 0..12 {
        let mut wire = vec![];
        client.write_tls(&mut wire).unwrap();
        server.read_tls(&mut wire.as_slice()).unwrap();
        server.process_new_packets()?;
        wire.clear();
        server.write_tls(&mut wire).unwrap();
        client.read_tls(&mut wire.as_slice()).unwrap();
        client.process_new_packets()?;
        if !client.is_handshaking() && !server.is_handshaking() {
            assert!(matches!(
                client.export_keying_material([0; 32], b"no EMS", None),
                Err(rustls::Error::General(_))
            ));
            return Ok(());
        }
    }
    panic!("360 native TLS1.2 handshake did not converge")
}

#[test]
fn browser360_preserves_strong_certificate_name_and_pin_checks() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let (_, parsed) = x509_parser::parse_x509_certificate(cert.cert.der()).unwrap();
    let pin = STANDARD.encode(aerobox_primitives::digest::digest(
        &aerobox_primitives::digest::SHA256,
        parsed.public_key().raw,
    ));
    let mut options = TlsClientOptions {
        root_certificates: vec![cert.cert.pem()],
        certificate_public_key_sha256: vec![pin],
        ..policy()
    };
    native_pair(client(&options, false).unwrap(), "localhost", &cert).unwrap();
    let error = native_pair(client(&options, false).unwrap(), "wrong.test", &cert).unwrap_err();
    assert!(matches!(
        error,
        rustls::Error::InvalidCertificate(
            rustls::CertificateError::NotValidForName
                | rustls::CertificateError::NotValidForNameContext { .. }
        )
    ));
    options.disable_sni = true;
    native_pair(client(&options, false).unwrap(), "localhost", &cert).unwrap();
    options.certificate_public_key_sha256 = vec![STANDARD.encode([0; 32])];
    let error = native_pair(client(&options, false).unwrap(), "localhost", &cert).unwrap_err();
    assert!(error.to_string().contains("pin"), "{error}");
    let insecure = try_create_client_config_with_options(
        false,
        vec![],
        vec![],
        true,
        None,
        false,
        &Default::default(),
        &options,
    )
    .unwrap();
    let error = native_pair(insecure, "localhost", &cert).unwrap_err();
    assert!(error.to_string().contains("pin"), "{error}");
}

#[tokio::test]
async fn browser360_native_compiler_rejects_reality_quic_and_vision() {
    async fn compile(hop: serde_json::Value) -> io::Result<crate::config::ValidatedConfigs> {
        crate::config::compile_configs(
            serde_json::from_value(serde_json::json!([{
                "address":"127.0.0.1:0","protocol":{"type":"socks"},
                "rules":[{"conditions":{"any_destination":true},"client_chain":hop}]
            }]))
            .map_err(io::Error::other)?,
        )
        .await
    }
    fn hop(protocol: serde_json::Value) -> serde_json::Value {
        serde_json::json!({"address":"127.0.0.1:443","protocol":protocol})
    }
    let base = serde_json::json!({"type":"tls","sni_hostname":"localhost","options":{"fingerprint":"360_7_5"},"protocol":{"type":"noop"}});
    compile(hop(base.clone())).await.unwrap();
    let mut vision = base.clone();
    vision["vision"] = true.into();
    assert!(compile(hop(vision)).await.is_err());
    let reality = serde_json::json!({"type":"reality","fingerprint":"360_7_5","sni_hostname":"localhost","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","short_id":"0101010101010101","protocol":{"type":"noop"}});
    assert!(compile(hop(reality)).await.is_err());
    assert!(
        compile(
            serde_json::json!({"address":"127.0.0.1:443","transport":"quic",
        "quic_settings":{"options":{"fingerprint":"360_7_5"}},"protocol":{"type":"noop"}})
        )
        .await
        .is_err()
    );
}

mod interop;
