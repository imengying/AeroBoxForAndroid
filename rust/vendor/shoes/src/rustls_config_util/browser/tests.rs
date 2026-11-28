use super::*;
use crate::config::tls::TlsClientFingerprint;
use crate::rustls_config_util::try_create_client_config_with_options;
use std::sync::Arc;

fn options() -> TlsClientOptions {
    TlsClientOptions {
        fingerprint: Some(TlsClientFingerprint::Chrome133),
        ..Default::default()
    }
}
fn client(options: &TlsClientOptions, tls13: bool) -> io::Result<ClientConfig> {
    try_create_client_config_with_options(
        true,
        vec![],
        vec![],
        true,
        None,
        tls13,
        &Default::default(),
        options,
    )
}
#[test]
fn explicit_profile_preserves_default_tls_and_rejects_conflicting_policy() {
    // Linking Safari codecs must not change unrelated rustls defaults.
    assert!(rustls::compress::default_cert_compressors().is_empty());
    assert!(rustls::compress::default_cert_decompressors().is_empty());
    let ordinary = client(&Default::default(), false).unwrap();
    assert!(ordinary.client_hello_layout.is_none());
    assert!(!ordinary.enable_tls12_renegotiation);
    assert!(ordinary.cert_decompressors.is_empty());
    assert!(ordinary.alpn_protocols.is_empty());
    let chrome = client(&options(), false).unwrap();
    assert!(chrome.enable_tls12_renegotiation);
    assert_eq!(
        chrome.alpn_protocols,
        [b"h2".to_vec(), b"http/1.1".to_vec()]
    );
    assert_eq!(chrome.cert_decompressors.len(), 1);
    for bad in [
        TlsClientOptions {
            min_version: Some(TlsVersion::V13),
            ..options()
        },
        TlsClientOptions {
            max_version: Some(TlsVersion::V12),
            ..options()
        },
        TlsClientOptions {
            cipher_suites: vec!["TLS_AES_128_GCM_SHA256".into()],
            ..options()
        },
    ] {
        assert!(client(&bad, false).is_err());
    }
    let groups = serde_json::from_str::<TlsKeyExchangeGroups>("[\"X25519\"]").unwrap();
    assert!(
        try_create_client_config_with_options(
            true,
            vec![],
            vec![],
            true,
            None,
            false,
            &groups,
            &options()
        )
        .is_err()
    );
    assert!(serde_json::from_str::<TlsClientOptions>(r#"{"fingerprint":"firefox"}"#).is_err());
    assert!(
        crate::reality::validate_profile_suites(
            &[crate::reality::CipherSuite::AES_128_GCM_SHA256],
            crate::config::tls::TlsClientFingerprint::Chrome133,
        )
        .is_err()
    );
}

fn pair(
    mut client: ClientConfig,
    tls12: bool,
    name: &str,
    cert: &rcgen::CertifiedKey<rcgen::KeyPair>,
) -> Result<(), rustls::Error> {
    client.resumption = rustls::client::Resumption::disabled();
    let mut client =
        rustls::ClientConnection::new(Arc::new(client), name.to_owned().try_into().unwrap())?;
    let server = rustls::ServerConfig::builder_with_provider(aerobox_crypto::shared_provider())
        .with_protocol_versions(&[if tls12 {
            &rustls::version::TLS12
        } else {
            &rustls::version::TLS13
        }])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )
        .unwrap();
    let mut server = rustls::ServerConnection::new(Arc::new(server))?;
    for _ in 0..12 {
        let mut wire = Vec::new();
        client.write_tls(&mut wire).unwrap();
        server.read_tls(&mut wire.as_slice()).unwrap();
        server.process_new_packets()?;
        wire.clear();
        server.write_tls(&mut wire).unwrap();
        for chunk in wire.chunks(23) {
            client.read_tls(&mut chunk.as_ref()).unwrap();
            client.process_new_packets()?;
        }
        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok(());
        }
    }
    panic!("Chrome handshake did not converge")
}
#[test]
fn chrome_keeps_certificate_pin_sni_and_vision_tls13_enforcement() {
    use base64::Engine;
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let (_, parsed) = x509_parser::parse_x509_certificate(cert.cert.der()).unwrap();
    let pin = base64::engine::general_purpose::STANDARD.encode(aerobox_primitives::digest::digest(
        &aerobox_primitives::digest::SHA256,
        parsed.public_key().raw,
    ));
    for profile in [
        TlsClientFingerprint::Chrome133,
        TlsClientFingerprint::Edge85,
        TlsClientFingerprint::Qq11_1,
        TlsClientFingerprint::Safari16,
        TlsClientFingerprint::Ios14,
        TlsClientFingerprint::Firefox120,
    ] {
        let mut policy = TlsClientOptions {
            root_certificates: vec![cert.cert.pem()],
            certificate_public_key_sha256: vec![pin.clone()],
            fingerprint: Some(profile),
            ..Default::default()
        };
        for tls13_only in [false, true] {
            pair(
                client(&policy, tls13_only).unwrap(),
                false,
                "localhost",
                &cert,
            )
            .unwrap();
            assert!(
                pair(
                    client(&policy, tls13_only).unwrap(),
                    false,
                    "wrong.test",
                    &cert
                )
                .is_err()
            );
        }
        pair(client(&policy, false).unwrap(), true, "localhost", &cert).unwrap();
        assert!(pair(client(&policy, true).unwrap(), true, "localhost", &cert).is_err());
        policy.disable_sni = true;
        pair(client(&policy, false).unwrap(), false, "localhost", &cert).unwrap();
        policy.certificate_public_key_sha256 =
            vec![base64::engine::general_purpose::STANDARD.encode([0; 32])];
        assert!(pair(client(&policy, false).unwrap(), false, "localhost", &cert).is_err());
    }
}

#[tokio::test]
async fn native_compiler_keeps_profile_and_rejects_quic_and_reality_conflicts() {
    use serde_json::json;
    async fn compile(client: serde_json::Value) -> io::Result<crate::config::ValidatedConfigs> {
        crate::config::compile_configs(
            serde_json::from_value(json!([{
                "address":"127.0.0.1:0", "protocol":{"type":"socks"},
                "rules":[{"conditions":{"any_destination":true},"client_chain":client}]
            }]))
            .map_err(io::Error::other)?,
        )
        .await
    }
    let protocol = json!({"type":"tls","sni_hostname":"localhost","options":{"fingerprint":"chrome133"},"protocol":{"type":"noop"}});
    let validated = compile(json!({"address":"127.0.0.1:443","protocol":protocol}))
        .await
        .unwrap();
    let crate::config::ResolvedConfig::Server(server) = &validated.configs[0] else {
        panic!("expected server");
    };
    let crate::config::ResolvedRuleActionConfig::Allow { client_chains, .. } =
        &server.rules.iter().next().unwrap().action
    else {
        panic!("expected allow rule")
    };
    let crate::config::ResolvedClientHop::Single(client) = client_chains
        .iter()
        .next()
        .unwrap()
        .hops
        .iter()
        .next()
        .unwrap()
    else {
        panic!("expected single hop")
    };
    let crate::config::ResolvedClientProxyConfig::Tls(tls) = &client.protocol else {
        panic!("expected TLS client");
    };
    assert_eq!(
        tls.options.fingerprint,
        Some(TlsClientFingerprint::Chrome133)
    );
    assert!(compile(json!({"address":"127.0.0.1:443","transport":"quic","quic_settings":{"options":{"fingerprint":"chrome133"}},"protocol":{"type":"noop"}})).await.is_err());
    let mut reality = json!({"address":"127.0.0.1:443","protocol":{"type":"reality","fingerprint":"chrome133","sni_hostname":"cover.test","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","short_id":"0101010101010101","protocol":{"type":"noop"}}});
    compile(reality.clone()).await.unwrap();
    reality["protocol"]["cipher_suites"] = json!(["TLS_AES_128_GCM_SHA256"]);
    assert!(compile(reality).await.is_err());
}

mod firefox_delegated;
mod interop;

#[test]
fn firefox_requires_exact_algorithms_and_uses_two_independent_shares() {
    let base = TlsClientOptions {
        fingerprint: Some(TlsClientFingerprint::Firefox120),
        ..Default::default()
    };
    let groups: TlsKeyExchangeGroups = serde_json::from_str(
        r#"["X25519","SecP256r1","SecP384r1","SecP521r1","FFDHE2048","FFDHE3072"]"#,
    )
    .unwrap();
    let names: Vec<_> = profile_provider(TlsClientFingerprint::Firefox120)
        .unwrap()
        .cipher_suites
        .iter()
        .map(|suite| suite.suite().as_str().unwrap().to_owned())
        .collect();
    let exact = TlsClientOptions {
        cipher_suites: names.clone(),
        min_version: Some(TlsVersion::V12),
        max_version: Some(TlsVersion::V13),
        ..base.clone()
    };
    for tls13_only in [false, true] {
        let config = try_create_client_config_with_options(
            true,
            vec![],
            vec![],
            true,
            None,
            tls13_only,
            &groups,
            &exact,
        )
        .unwrap();
        assert!(config.enable_delegated_credentials && config.advertise_record_size_limit);
        assert_eq!(
            config.initial_key_share_groups,
            [NamedGroup::X25519, NamedGroup::secp256r1]
        );
        assert_eq!(config.enable_tls12_renegotiation, !tls13_only);
        assert!(config.cert_decompressors.is_empty() && config.application_settings.is_none());
        rustls::ClientConnection::new(Arc::new(config), "localhost".try_into().unwrap()).unwrap();
    }
    for bad in [
        TlsClientOptions {
            min_version: Some(TlsVersion::V10),
            ..base.clone()
        },
        TlsClientOptions {
            min_version: Some(TlsVersion::V13),
            ..base.clone()
        },
        TlsClientOptions {
            max_version: Some(TlsVersion::V12),
            ..base.clone()
        },
        TlsClientOptions {
            cipher_suites: names[..16].to_vec(),
            ..base.clone()
        },
    ] {
        assert!(client(&bad, false).is_err());
    }
    let missing_ffdhe: TlsKeyExchangeGroups =
        serde_json::from_str(r#"["X25519","SecP256r1","SecP384r1","SecP521r1"]"#).unwrap();
    assert!(
        try_create_client_config_with_options(
            true,
            vec![],
            vec![],
            true,
            None,
            false,
            &missing_ffdhe,
            &base,
        )
        .is_err()
    );
}

#[tokio::test]
async fn firefox_reality_preflight_uses_its_exact_cipher_order() {
    use serde_json::json;
    let mut config = json!([{
        "address":"127.0.0.1:0", "protocol":{"type":"socks"},
        "rules":[{"conditions":{"any_destination":true}, "client_chain":{
            "address":"127.0.0.1:9", "protocol":{
                "type":"reality", "fingerprint":"firefox120", "sni_hostname":"cover.test",
                "public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "short_id":"0101010101010101", "protocol":{"type":"noop"},
                "cipher_suites":["TLS_AES_128_GCM_SHA256","TLS_CHACHA20_POLY1305_SHA256","TLS_AES_256_GCM_SHA384"]
            }
        }}]
    }]);
    crate::config::compile_configs(serde_json::from_value(config.clone()).unwrap())
        .await
        .unwrap();
    config[0]["rules"][0]["client_chain"]["protocol"]["cipher_suites"] = json!([
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256"
    ]);
    assert!(
        crate::config::compile_configs(serde_json::from_value(config).unwrap())
            .await
            .is_err()
    );
}

#[test]
fn android_safari_ios_require_all_real_suites_p521_and_profile_compression() {
    for profile in [TlsClientFingerprint::Safari16, TlsClientFingerprint::Ios14] {
        let base = TlsClientOptions {
            fingerprint: Some(profile),
            ..Default::default()
        };
        let provider = profile_provider(profile).unwrap();
        let names: Vec<_> = provider
            .cipher_suites
            .iter()
            .map(|suite| suite.suite().as_str().unwrap().to_owned())
            .collect();
        let exact = TlsClientOptions {
            cipher_suites: names.clone(),
            min_version: Some(TlsVersion::V10),
            max_version: Some(TlsVersion::V13),
            ..base.clone()
        };
        let groups: TlsKeyExchangeGroups =
            serde_json::from_str("[\"X25519\",\"SecP256r1\",\"SecP384r1\",\"SecP521r1\"]").unwrap();
        let cfg = try_create_client_config_with_options(
            true,
            vec![],
            vec![],
            true,
            None,
            false,
            &groups,
            &exact,
        )
        .unwrap();
        assert_eq!(
            cfg.cert_decompressors
                .iter()
                .map(|v| u16::from(v.algorithm()))
                .collect::<Vec<_>>(),
            if profile == TlsClientFingerprint::Safari16 {
                vec![1]
            } else {
                vec![]
            }
        );
        assert!(cfg.application_settings.is_none());
        assert_eq!(cfg.initial_key_share_groups, [NamedGroup::X25519]);
        assert!(cfg.enable_tls12_renegotiation);
        rustls::ClientConnection::new(Arc::new(cfg), "localhost".try_into().unwrap()).unwrap();
        // Restricting any suite or omitting P521 cannot silently preserve the
        // fingerprint label while changing its advertised capabilities.
        for bad in [
            TlsClientOptions {
                cipher_suites: names[..names.len() - 1].to_vec(),
                ..base.clone()
            },
            TlsClientOptions {
                min_version: Some(TlsVersion::V12),
                ..base.clone()
            },
            TlsClientOptions {
                max_version: Some(TlsVersion::V12),
                ..base.clone()
            },
        ] {
            assert!(client(&bad, false).is_err());
        }
        let no_p521: TlsKeyExchangeGroups =
            serde_json::from_str("[\"X25519\",\"SecP256r1\",\"SecP384r1\"]").unwrap();
        assert!(
            try_create_client_config_with_options(
                true,
                vec![],
                vec![],
                true,
                None,
                false,
                &no_p521,
                &base
            )
            .is_err()
        );
        let restricted = client(&base, true).unwrap();
        assert!(!restricted.enable_tls12_renegotiation);
        rustls::ClientConnection::new(Arc::new(restricted), "localhost".try_into().unwrap())
            .unwrap();
    }
}

#[test]
fn edge_qq_validate_explicit_versions_curves_ciphers_and_alps() {
    for profile in [TlsClientFingerprint::Edge85, TlsClientFingerprint::Qq11_1] {
        let policy = TlsClientOptions {
            fingerprint: Some(profile),
            ..Default::default()
        };
        let config = client(&policy, false).unwrap();
        assert_eq!(config.initial_key_share_groups, [NamedGroup::X25519]);
        assert!(config.enable_tls12_renegotiation);
        assert_eq!(
            config.application_settings.is_some(),
            profile == TlsClientFingerprint::Qq11_1
        );
        let explicit = TlsClientOptions {
            min_version: Some(TlsVersion::V10),
            max_version: Some(TlsVersion::V13),
            ..policy.clone()
        };
        let groups: TlsKeyExchangeGroups =
            serde_json::from_str("[\"X25519\",\"SecP256r1\",\"SecP384r1\"]").unwrap();
        let good = try_create_client_config_with_options(
            true,
            vec![],
            vec![],
            true,
            None,
            false,
            &groups,
            &explicit,
        )
        .unwrap();
        rustls::ClientConnection::new(Arc::new(good), "localhost".try_into().unwrap()).unwrap();
        for bad in [
            TlsClientOptions {
                min_version: Some(TlsVersion::V12),
                ..policy.clone()
            },
            TlsClientOptions {
                max_version: Some(TlsVersion::V12),
                ..policy.clone()
            },
            TlsClientOptions {
                cipher_suites: vec!["TLS_AES_128_GCM_SHA256".into()],
                ..policy.clone()
            },
        ] {
            assert!(client(&bad, false).is_err());
        }
        let invalid: TlsKeyExchangeGroups = serde_json::from_str("[\"X25519MLKEM768\"]").unwrap();
        assert!(
            try_create_client_config_with_options(
                true,
                vec![],
                vec![],
                true,
                None,
                false,
                &invalid,
                &policy
            )
            .is_err()
        );
    }
}

mod browser360;
