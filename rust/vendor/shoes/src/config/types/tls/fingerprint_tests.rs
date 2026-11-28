use super::*;
use aerobox_fingerprint::{InitError, Profile};
use serde_json::json;

const CANDIDATES: [Profile; 5] = [
    Profile::Chrome133,
    Profile::Firefox120,
    Profile::Edge85,
    Profile::Safari16,
    Profile::Ios14,
];

fn selected(profile: Profile) -> TlsClientOptions {
    TlsClientOptions {
        fingerprint: deserialize_fingerprint_with(json!("random"), || Ok(profile)).unwrap(),
        ..Default::default()
    }
}

#[test]
fn random_field_decodes_all_five_candidates_and_preserves_fixed_serialization() {
    for profile in CANDIDATES {
        let options = selected(profile);
        assert_eq!(options.fingerprint, Some(profile.into()));
        assert_eq!(
            serde_json::to_value(&options).unwrap()["fingerprint"],
            profile.as_str()
        );
        let fixed: TlsClientOptions =
            serde_json::from_value(json!({"fingerprint":profile.as_str()})).unwrap();
        assert_eq!(fixed, options);
    }
}

#[test]
fn missing_null_fixed_and_invalid_fields_do_not_request_random_entropy() {
    assert_eq!(
        serde_json::from_value::<TlsClientOptions>(json!({}))
            .unwrap()
            .fingerprint,
        None
    );
    for (value, expected) in [
        (json!(null), None),
        (json!("chrome133"), Some(TlsClientFingerprint::Chrome133)),
        (json!("android11"), Some(TlsClientFingerprint::Android11)),
        (json!("qq11_1"), Some(TlsClientFingerprint::Qq11_1)),
    ] {
        assert_eq!(
            deserialize_fingerprint_with(value, || panic!("non-random field requested entropy"))
                .unwrap(),
            expected
        );
    }
    for value in [
        json!("randomized_unknown"),
        json!("360"),
        json!(3),
        json!(true),
        json!([]),
    ] {
        assert!(
            deserialize_fingerprint_with(value, || panic!("invalid field requested entropy"))
                .is_err()
        );
    }
    let error = deserialize_fingerprint_with(json!("random"), || {
        Err(InitError::Entropy("injected source error".into()))
    })
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("random TLS fingerprint entropy failed: injected source error")
    );
}

fn client(
    groups: &TlsKeyExchangeGroups,
    options: &TlsClientOptions,
) -> std::io::Result<rustls::ClientConfig> {
    crate::rustls_config_util::try_create_client_config_with_options(
        true,
        vec![],
        vec![],
        true,
        None,
        false,
        groups,
        options,
    )
}

#[test]
fn each_injected_choice_uses_existing_exact_policy_and_reality_suite_order() {
    for profile in CANDIDATES {
        let mut options = selected(profile);
        let fixed = options.fingerprint.unwrap();
        let provider = crate::rustls_config_util::browser::profile_provider(fixed).unwrap();
        options.min_version = Some(
            if matches!(profile, Profile::Chrome133 | Profile::Firefox120) {
                TlsVersion::V12
            } else {
                TlsVersion::V10
            },
        );
        options.max_version = Some(TlsVersion::V13);
        options.cipher_suites = provider
            .cipher_suites
            .iter()
            .map(|suite| suite.suite().as_str().unwrap().to_owned())
            .collect();
        let groups: TlsKeyExchangeGroups = serde_json::from_value(match profile {
            Profile::Chrome133 => json!(["X25519MLKEM768", "X25519", "SecP256r1", "SecP384r1"]),
            Profile::Firefox120 => json!([
                "X25519",
                "SecP256r1",
                "SecP384r1",
                "SecP521r1",
                "FFDHE2048",
                "FFDHE3072"
            ]),
            Profile::Edge85 => json!(["X25519", "SecP256r1", "SecP384r1"]),
            Profile::Safari16 | Profile::Ios14 => {
                json!(["X25519", "SecP256r1", "SecP384r1", "SecP521r1"])
            }
        })
        .unwrap();
        let config = client(&groups, &options).unwrap();
        let expected_layout = match profile {
            Profile::Chrome133 => rustls::client::ClientHelloLayout::Chrome133,
            Profile::Firefox120 => rustls::client::ClientHelloLayout::Firefox120,
            Profile::Edge85 => rustls::client::ClientHelloLayout::Edge85,
            Profile::Safari16 => rustls::client::ClientHelloLayout::Safari16,
            Profile::Ios14 => rustls::client::ClientHelloLayout::Ios14,
        };
        assert_eq!(config.client_hello_layout, Some(expected_layout));
        assert_eq!(
            config.enable_delegated_credentials,
            profile == Profile::Firefox120
        );
        assert_eq!(
            config.advertise_record_size_limit,
            profile == Profile::Firefox120
        );
        for bad in [
            TlsClientOptions {
                min_version: Some(TlsVersion::V13),
                ..options.clone()
            },
            TlsClientOptions {
                max_version: Some(TlsVersion::V12),
                ..options.clone()
            },
            TlsClientOptions {
                cipher_suites: vec!["TLS_AES_128_GCM_SHA256".into()],
                ..options.clone()
            },
        ] {
            assert!(client(&groups, &bad).is_err(), "{profile:?}");
        }
        let mut reordered = options.clone();
        reordered.cipher_suites.swap(0, 1);
        assert!(client(&groups, &reordered).is_err());
        let wrong_groups: TlsKeyExchangeGroups = serde_json::from_value(json!(["X25519"])).unwrap();
        assert!(client(&wrong_groups, &options).is_err());
        let mut ech = options.clone();
        ech.ech = Some(serde_json::from_value(json!({"query_server_name":"cover.test"})).unwrap());
        let ech_policy = client(&groups, &ech);
        assert_eq!(ech_policy.is_ok(), profile == Profile::Chrome133);

        use crate::reality::CipherSuite;
        let expected = if profile == Profile::Firefox120 {
            [
                CipherSuite::AES_128_GCM_SHA256,
                CipherSuite::CHACHA20_POLY1305_SHA256,
                CipherSuite::AES_256_GCM_SHA384,
            ]
        } else {
            [
                CipherSuite::AES_128_GCM_SHA256,
                CipherSuite::AES_256_GCM_SHA384,
                CipherSuite::CHACHA20_POLY1305_SHA256,
            ]
        };
        crate::reality::validate_profile_suites(&expected, fixed).unwrap();
        let mut wrong = expected;
        wrong.swap(1, 2);
        assert!(crate::reality::validate_profile_suites(&wrong, fixed).is_err());
        assert_eq!(options.fingerprint, Some(fixed));
    }
}

#[test]
fn native_tls_and_reality_deserialize_the_same_process_choice_after_errors() {
    let selected = aerobox_fingerprint::random_profile().unwrap();
    for _ in 0..4 {
        let options: TlsClientOptions =
            serde_json::from_value(json!({"fingerprint":"random"})).unwrap();
        assert_eq!(options.fingerprint, Some(selected.into()));
        let reality: super::super::client::ClientProxyConfig = serde_json::from_value(json!({
            "type":"reality","fingerprint":"random","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "short_id":"0101010101010101","sni_hostname":"cover.test","protocol":{"type":"noop"}
        })).unwrap();
        let super::super::client::ClientProxyConfig::Reality { fingerprint, .. } = reality else {
            panic!("expected REALITY");
        };
        assert_eq!(fingerprint, options.fingerprint);
        assert!(
            serde_json::from_value::<TlsClientOptions>(json!({
                "fingerprint":"random","min_version":"invalid"
            }))
            .is_err()
        );
        let bad: TlsClientOptions = serde_json::from_value(json!({
            "fingerprint":"random","cipher_suites":["TLS_AES_128_GCM_SHA256"]
        }))
        .unwrap();
        assert!(client(&Default::default(), &bad).is_err());
        assert_eq!(aerobox_fingerprint::random_profile().unwrap(), selected);
    }
}

#[tokio::test]
async fn native_compilation_keeps_random_choice_and_checks_reality_after_resolution() {
    async fn compile(
        protocol: serde_json::Value,
    ) -> std::io::Result<crate::config::ValidatedConfigs> {
        crate::config::compile_configs(
            serde_json::from_value(json!([{
                "address":"127.0.0.1:0", "protocol":{"type":"socks"},
                "rules":[{"conditions":{"any_destination":true},"client_chain":{
                    "address":"127.0.0.1:443", "protocol":protocol
                }}]
            }]))
            .map_err(std::io::Error::other)?,
        )
        .await
    }
    let selected = TlsClientFingerprint::from(aerobox_fingerprint::random_profile().unwrap());
    let mut reality = json!({"type":"reality","fingerprint":"random",
        "sni_hostname":"cover.test","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "short_id":"0101010101010101","protocol":{"type":"noop"}});
    let tls = json!({"type":"tls","sni_hostname":"cover.test",
        "options":{"fingerprint":"random"},"protocol":{"type":"noop"}});
    for protocol in [tls, reality.clone()] {
        let validated = compile(protocol).await.unwrap();
        let crate::config::ResolvedConfig::Server(server) = &validated.configs[0] else {
            panic!("expected server");
        };
        let crate::config::ResolvedRuleActionConfig::Allow { client_chains, .. } =
            &server.rules.iter().next().unwrap().action
        else {
            panic!("expected allow rule");
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
            panic!("expected client hop");
        };
        let profile = match &client.protocol {
            crate::config::ResolvedClientProxyConfig::Tls(tls) => tls.options.fingerprint,
            crate::config::ResolvedClientProxyConfig::Reality { fingerprint, .. } => *fingerprint,
            other => panic!("unexpected client: {other:?}"),
        };
        assert_eq!(profile, Some(selected));
    }
    let mut suites = vec![
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
    ];
    if selected == TlsClientFingerprint::Firefox120 {
        suites.swap(1, 2);
    }
    reality["cipher_suites"] = json!(suites);
    compile(reality.clone()).await.unwrap();
    suites.swap(1, 2);
    reality["cipher_suites"] = json!(suites);
    let error = compile(reality)
        .await
        .err()
        .expect("wrong REALITY suite order must fail");
    assert!(error.to_string().contains("explicit cipher suite policy"));
    assert_eq!(
        TlsClientFingerprint::from(aerobox_fingerprint::random_profile().unwrap()),
        selected
    );
}

#[test]
fn randomized_token_does_not_call_the_fixed_profile_resolver() {
    let result = super::deserialize_fingerprint_with(json!("randomized"), || {
        panic!("randomized must not select one of the five fixed random profiles")
    })
    .unwrap();
    assert_eq!(result, Some(super::TlsClientFingerprint::Randomized));
    assert_eq!(serde_json::to_string(&result).unwrap(), "\"randomized\"");
}
