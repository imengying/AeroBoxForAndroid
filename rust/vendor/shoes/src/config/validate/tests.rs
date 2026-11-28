use super::*;
use crate::config::composition;
use crate::config::pem::convert_cert_paths;
use crate::dns::IpStrategy;

#[test]
fn websocket_early_data_validation_reaches_clients_and_every_server_target() {
    use crate::tcp::{
        tcp_client_handler_factory::create_tcp_client_handler,
        tcp_server_handler_factory::create_tcp_server_handler,
    };
    use serde_json::json;
    use std::sync::Arc;

    let resolver: Arc<dyn crate::resolver::Resolver> =
        Arc::new(crate::resolver::NativeResolver::new());
    let selector = Arc::new(crate::client_proxy_selector::ClientProxySelector::new(
        vec![],
    ));
    for server in [false, true] {
        for (options, expected) in [
            (json!({}), None),
            (json!({"max_early_data": 0}), None),
            (
                json!({"max_early_data": 32, "matching_path": "/ws", "matching_headers": {"Host": "example.test"}}),
                None,
            ),
            (
                json!({"max_early_data": 32, "early_data_header_name": "X-Early", "matching_headers": {"Host": "example.test"}}),
                None,
            ),
            (
                json!({"early_data_header_name": "X-Early"}),
                Some("early_data_header_name requires max_early_data > 0"),
            ),
            (
                json!({"max_early_data": 32}),
                Some(if server {
                    "WebSocket path early data requires matching_path"
                } else {
                    "WebSocket early data requires matching_headers.Host"
                }),
            ),
            (
                json!({"max_early_data": 4096, "matching_path": "/ws"}),
                Some("WebSocket early data limit exceeds HTTP line budget"),
            ),
            (
                json!({"max_early_data": 32, "early_data_header_name": "Host"}),
                Some("reserved WebSocket early data header"),
            ),
            (
                json!({"max_early_data": 32, "early_data_header_name": "X-Early", "matching_headers": {"x-EARLY": "YQ"}}),
                Some("duplicate or conflicting WebSocket header"),
            ),
            (
                json!({"max_early_data": 32, "early_data_header_name": "X-Early", "matching_headers": {"Host": "example.test", "Connection": "Upgrade"}}),
                if server {
                    None
                } else {
                    Some("matching_headers conflicts with WebSocket handshake")
                },
            ),
        ] {
            let mut protocol = options.clone();
            protocol["protocol"] = if server {
                json!({"type": "forward", "targets": "127.0.0.1:80"})
            } else {
                json!({"type": "portforward"})
            };
            let (config, factory_result) = if server {
                let protocol = json!({"type": "ws", "targets": [
                    {"matching_path": "/other", "protocol": {"type": "forward", "targets": "127.0.0.1:81"}},
                    protocol
                ]});
                let handler = create_tcp_server_handler(
                    crate::config::test_support::from_json(protocol.clone()).unwrap(),
                    &selector,
                    &resolver,
                    None,
                );
                (
                    json!([{"address": "0.0.0.0:1080", "protocol": protocol}]),
                    handler.map(|_| ()),
                )
            } else {
                protocol["type"] = "ws".into();
                let handler = create_tcp_client_handler(
                    crate::config::test_support::from_json(protocol.clone()).unwrap(),
                    &crate::address::NetLocation::from_str("127.0.0.1:443", None).unwrap(),
                    resolver.clone(),
                );
                (
                    json!([{"address": "0.0.0.0:1080", "protocol": {"type": "socks"}, "rules": [{
                        "masks": "0.0.0.0/0", "action": "allow", "client_chain": {
                            "address": "127.0.0.1:443", "protocol": {"type": "tls", "verify": false, "protocol": protocol}
                        }
                    }]}]),
                    handler.map(|_| ()),
                )
            };
            let yaml = serde_yaml::to_string(&config).unwrap();
            let validated = create_server_configs(serde_yaml::from_str(&yaml).unwrap()).map(|_| ());
            for (stage, result) in [("preparation", validated), ("factory", factory_result)] {
                if let Some(expected) = expected {
                    assert_eq!(
                        result.unwrap_err().to_string(),
                        expected,
                        "{stage}, server={server}, options={options}"
                    );
                } else {
                    result.unwrap_or_else(|error| {
                        panic!("{stage}, server={server}, options={options}: {error}")
                    });
                }
            }
        }
    }
}

















thread_local! {
    pub(super) static CLIENT_VALIDATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}



#[test]
fn native_vless_configuration_rejects_ambiguous_vision_and_secrets() {
    use serde_json::json;

    const KEY: &str = "CQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let client = json!({
        "type": "vless", "user_id": "550e8400-e29b-41d4-a716-446655440000",
        "encryption": format!("mlkem768x25519plus.native.0rtt.{KEY}"), "vision": true,
    });
    let server = json!({
        "type": "vless", "user_id": "550e8400-e29b-41d4-a716-446655440000",
        "decryption": format!("mlkem768x25519plus.native.600s.{KEY}"), "vision": true,
    });
    let mut client_config = serde_json::from_value(client.clone()).unwrap();
    validate_client_proxy_config(&mut client_config, &HashMap::new(), None).unwrap();
    for outer in ["TLS", "REALITY"] {
        let error = validate_client_vision_protocol(true, &client_config, outer).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("outer TLS/REALITY vision: false")
        );
        assert!(!error.to_string().contains(KEY));
        validate_client_vision_protocol(false, &client_config, outer).unwrap();
    }
    let validate_server = |value: serde_json::Value| {
        let config = serde_json::from_value(value).unwrap();
        let config = resolve_server_proxy_config(
            config,
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
            GlobalLimits::default(),
            ServerProtocolContext::Stream,
        )?;
        Ok::<_, std::io::Error>(config)
    };
    let server_config = validate_server(server.clone()).unwrap();
    assert!(
        validate_resolved_server_vision(true, &server_config)
            .unwrap_err()
            .to_string()
            .contains("outer TLS/REALITY vision: false")
    );
    validate_resolved_server_vision(false, &server_config).unwrap();
    for (key, value) in [
        ("encryption", json!("none")),
        ("encryption", json!("invalid-secret-do-not-log")),
        ("h2mux", json!({})),
    ] {
        let mut value_config = client.clone();
        value_config[key] = value;
        let mut config = serde_json::from_value(value_config).unwrap();
        let error = validate_client_proxy_config(&mut config, &HashMap::new(), None).unwrap_err();
        assert!(!error.to_string().contains("do-not-log"));
        assert!(!format!("{config:?}").contains("do-not-log"));
    }
    for (key, value) in [
        ("decryption", json!("none")),
        ("decryption", json!("invalid-secret-do-not-log")),
        ("fallback", json!("127.0.0.1:80")),
        ("encryption_limits", json!({"max_replays": 0})),
    ] {
        let mut config = server.clone();
        config[key] = value;
        let error = validate_server(config).unwrap_err();
        assert!(!error.to_string().contains("do-not-log"));
    }
    for disabled in ["", "none"] {
        let mut config = client.clone();
        config["encryption"] = json!(disabled);
        config["vision"] = json!(false);
        let mut config = serde_json::from_value(config).unwrap();
        validate_client_proxy_config(&mut config, &HashMap::new(), None).unwrap();
        validate_client_vision_protocol(true, &config, "TLS").unwrap();
        let mut config = server.clone();
        config["decryption"] = json!(disabled);
        config["vision"] = json!(false);
        validate_resolved_server_vision(true, &validate_server(config).unwrap()).unwrap();
    }
}

#[test]
fn server_secrets_must_be_nonempty() {
    use serde_json::json;
    for mut value in [
        json!({"type": "trojan", "password": ""}),
        json!({"type": "shadowsocks", "cipher": "aes-128-gcm", "password": ""}),
        json!({"type": "hysteria2", "password": ""}),
        json!({"type": "tuic", "uuid": "550e8400-e29b-41d4-a716-446655440000", "password": ""}),
    ] {
        for password in ["", "do-not-log-this-secret", " "] {
            value["password"] = json!(password);
            let protocol = serde_json::from_value(value.clone()).unwrap();
            let result = validate_server_auth(&protocol);
            assert_eq!(result.is_ok(), !password.is_empty());
            if let Err(error) = result {
                assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
                assert!(!error.to_string().contains("do-not-log-this-secret"));
            }
        }
    }
    for password in ["", "do-not-log-this-secret"] {
        let protocol = serde_json::from_value(json!({
            "type": "trojan", "password": "do-not-log-this-secret",
            "shadowsocks": {"cipher": "aes-128-gcm", "password": password}
        }))
        .unwrap();
        assert_eq!(
            validate_server_auth(&protocol).is_ok(),
            !password.is_empty()
        );
        for protocol_type in ["anytls", "naive"] {
            let mut user = json!({"password": password});
            if protocol_type == "naive" {
                user["username"] = json!("user");
            }
            let mut valid_user = user.clone();
            valid_user["password"] = json!("do-not-log-this-secret");
            for users in [user.clone(), json!([valid_user, user])] {
                let protocol = serde_json::from_value(json!({
                    "type": protocol_type, "users": users
                }))
                .unwrap();
                let result = validate_server_auth(&protocol);
                assert_eq!(result.is_ok(), !password.is_empty());
                if let Err(error) = result {
                    assert!(!error.to_string().contains("do-not-log-this-secret"));
                }
            }
        }
    }
    let protocol = ServerProxyConfig::Shadowsocks {
        config: ShadowsocksConfig::Aead2022 {
            cipher: "aes-128-gcm".try_into().unwrap(),
            key_bytes: vec![0; 1].into_boxed_slice(),
            identity_keys: Vec::new(),
        },
        udp_enabled: true,
    };
    assert!(validate_server_auth(&protocol).is_err());
}

#[test]
fn shadowsocks_identity_keys_validate_programmatic_clients_and_reject_servers() {
    for cipher in ["aes-128-gcm", "aes-256-gcm", "chacha20-poly1305"] {
        let cipher: crate::shadowsocks::ShadowsocksCipher = cipher.try_into().unwrap();
        let required = cipher.key_len();
        for (user_len, identity_len) in [
            (required, 0),
            (required, required),
            (required, required + 1),
            (0, required),
            (required + 1, required),
        ] {
            let config = ShadowsocksConfig::Aead2022 {
                key_bytes: vec![0x33; user_len].into_boxed_slice(),
                identity_keys: vec![vec![0x11; identity_len].into_boxed_slice()],
                cipher,
            };
            let mut client = ClientProxyConfig::Shadowsocks {
                config: config.clone(),
                udp_enabled: true,
                plugin: None,
            };
            assert_eq!(
                validate_client_proxy_config(&mut client, &HashMap::new(), None).is_ok(),
                user_len == required
                    && identity_len == required
                    && matches!(cipher.name(), "aes-128-gcm" | "aes-256-gcm")
            );
            assert!(
                validate_server_auth(&ServerProxyConfig::Shadowsocks {
                    config,
                    udp_enabled: true,
                })
                .is_err()
            );
        }
    }
}

#[test]
fn optional_server_auth_preserves_no_auth_and_http_empty_username() {
    use serde_json::json;
    for protocol_type in ["http", "socks", "mixed"] {
        for (username, password, http_valid, socks_valid) in [
            (None, None, true, true),
            (Some("user"), Some("secret"), true, true),
            (None, Some("secret"), true, false),
            (Some(""), Some("secret"), true, false),
            (Some("user"), None, false, false),
            (Some("user"), Some(""), false, false),
            (None, Some(""), false, false),
            (Some(""), None, false, false),
            (Some(""), Some(""), false, false),
        ] {
            let protocol = serde_json::from_value(json!({
                "type": protocol_type, "username": username, "password": password
            }))
            .unwrap();
            assert_eq!(
                validate_server_auth(&protocol).is_ok(),
                if protocol_type == "http" {
                    http_valid
                } else {
                    socks_valid
                },
                "{protocol_type}: {username:?}, {password:?}"
            );
        }
        for value in [
            "a".to_string(),
            "a".repeat(255),
            "a".repeat(256),
            format!("{}a", "\u{e9}".repeat(127)),
            "\u{e9}".repeat(128),
        ] {
            for field in ["username", "password"] {
                let mut protocol = json!({
                    "type": protocol_type, "username": "user", "password": "secret"
                });
                protocol[field] = json!(value);
                let protocol = serde_json::from_value(protocol).unwrap();
                assert_eq!(
                    validate_server_auth(&protocol).is_ok(),
                    protocol_type == "http" || value.len() <= 255,
                    "{protocol_type}: {field}, {} bytes",
                    value.len()
                );
            }
        }
    }
}

#[test]
fn server_protocol_context_enforces_transport_and_termination() {
    use serde_json::json;
    for (value, valid_context) in [
        (
            json!({"type": "hysteria2", "password": "secret"}),
            ServerProtocolContext::Quic,
        ),
        (
            json!({"type": "tuic", "uuid": "550e8400-e29b-41d4-a716-446655440000", "password": "secret"}),
            ServerProtocolContext::Quic,
        ),
        (
            json!({"type": "naive", "users": [{"username": "user", "password": "secret"}]}),
            ServerProtocolContext::Tls,
        ),
    ] {
        for context in [
            ServerProtocolContext::Stream,
            ServerProtocolContext::Tls,
            ServerProtocolContext::Quic,
        ] {
            let protocol = serde_json::from_value(value.clone()).unwrap();
            let result = resolve_server_proxy_config(
                protocol,
                &HashMap::new(),
                &HashMap::new(),
                &HashMap::new(),
                GlobalLimits::default(),
                context,
            );
            assert_eq!(result.is_ok(), context == valid_context);
            if let Err(error) = result {
                assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
                assert!(!error.to_string().contains("secret"));
            }
        }
    }
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    for protocol in [
        json!({"type": "hysteria2", "password": "secret"}),
        json!({"type": "tuic", "uuid": "550e8400-e29b-41d4-a716-446655440000", "password": "secret"}),
    ] {
        let configs = serde_json::from_value(json!([{
            "address": "127.0.0.1:9000", "transport": "quic", "protocol": protocol,
            "quic_settings": {"cert": cert.cert.pem(), "key": cert.signing_key.serialize_pem()}
        }]))
        .unwrap();
        assert!(create_server_configs(configs).is_ok());
    }
}

#[test]
fn nested_structure_errors_precede_protocol_field_errors() {
    let config = serde_json::from_value(serde_json::json!({
        "address": "example.com:443",
        "protocol": {
            "type": "reality", "public_key": "invalid",
            "protocol": {"type": "websocket", "protocol": {"type": "direct"}}
        }
    }))
    .unwrap();
    let error =
        resolve_client_config(config, &HashMap::new()).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert_eq!(
        error.to_string(),
        "direct cannot be used as an inner proxy protocol"
    );
}

#[test]
fn tls_sni_distinguishes_inheritance_disable_and_override() {
    for (sni, valid) in [
        (NoneOrOne::Unspecified, false),
        (NoneOrOne::None, true),
        (NoneOrOne::One("example.com".to_owned()), true),
        (NoneOrOne::One("example.com.".to_owned()), true),
        (NoneOrOne::One("0x1f.example".to_owned()), true),
        (NoneOrOne::One("example.0x1f".to_owned()), false),
        (NoneOrOne::One("0x7f000001".to_owned()), false),
        (NoneOrOne::One("invalid name".to_owned()), false),
    ] {
        let mut protocol = serde_json::from_value(serde_json::json!({
            "type": "tls", "protocol": {"type": "socks"}
        }))
        .unwrap();
        let ClientProxyConfig::Tls(ref mut tls) = protocol else {
            unreachable!()
        };
        tls.sni_hostname = sni;
        assert_eq!(
            validate_client_proxy_config(&mut protocol, &HashMap::new(), Some("invalid name"))
                .is_ok(),
            valid,
        );
    }
}

#[test]
fn reality_sni_defaults_only_at_the_outer_client_layer() {
    let protocol = serde_json::json!({
        "type": "reality", "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "protocol": {"type": "socks"}
    });
    for (address, protocol, valid) in [
        ("example.com:443", protocol.clone(), true),
        ("127.0.0.1:443", protocol.clone(), false),
        (
            "example.com:443",
            serde_json::json!({"type": "websocket", "protocol": protocol}),
            false,
        ),
    ] {
        let config: ClientConfig = serde_json::from_value(serde_json::json!({
            "address": address, "protocol": protocol
        }))
        .unwrap();
        assert_eq!(
            resolve_client_config(config, &HashMap::new()).is_ok(),
            valid
        );
    }
}

#[test]
fn reality_mldsa_client_key_validation() {
    let (_, valid) = crate::reality::generate_mldsa65_keypair().unwrap();
    for (key, expected) in [
        (None, true),
        (Some(valid.as_str()), true),
        (Some(""), false),
        (Some("AA"), false),
        (Some("invalid!"), false),
    ] {
        let mut value = serde_json::json!({
            "address": "cover.test:443", "protocol": {
                "type": "reality", "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "protocol": {"type": "socks"}
            }
        });
        if let Some(key) = key {
            value["protocol"]["mldsa65_verify"] = key.into();
        }
        let config: ClientConfig = serde_json::from_value(value).unwrap();
        assert_eq!(
            resolve_client_config(config, &HashMap::new()).is_ok(),
            expected
        );
    }
}

#[tokio::test]
async fn reality_mldsa_server_seed_validation() {
    let (valid, _) = crate::reality::generate_mldsa65_keypair().unwrap();
    for (seed, expected) in [
        (None, true),
        (Some(valid.as_str()), true),
        (Some(""), false),
        (Some("AA"), false),
        (Some("invalid!"), false),
    ] {
        let mut value = serde_json::json!({
            "address": "0.0.0.0:4443", "protocol": {"type": "tls", "reality_targets": {
                "cover.test": {"private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "dest": "cover.test:443", "protocol": {"type": "socks"}}
            }}
        });
        if let Some(seed) = seed {
            value["protocol"]["reality_targets"]["cover.test"]["mldsa65_seed"] = seed.into();
        }
        let result = validate_configs_test(vec![serde_json::from_value(value).unwrap()]).await;
        assert_eq!(result.is_ok(), expected, "{result:?}");
    }
}

async fn validate_configs_test(configs: Vec<Config>) -> std::io::Result<Vec<ResolvedConfig>> {
    let (converted_configs, _) = convert_cert_paths(configs).await?;
    let validated = create_server_configs(converted_configs)?;
    Ok(validated.configs)
}



#[test]
fn hybrid_only_rejects_vision_and_tuic_early_handshakes() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let tls_target = serde_json::json!({
        "cert": cert.cert.pem(), "key": cert.signing_key.serialize_pem(),
        "key_exchange_groups": ["X25519MLKEM768"], "vision": true,
        "protocol": {"type": "vless", "user_id": "550e8400-e29b-41d4-a716-446655440000"}
    });
    for protocol in [
        serde_json::json!({"type": "tls", "tls_targets": {"localhost": tls_target}}),
        serde_json::json!({"type": "tls", "default_tls_target": tls_target}),
    ] {
        let server: ServerProxyConfig = serde_json::from_value(protocol).unwrap();
        let error = resolve_server_proxy_config(
            server,
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
            GlobalLimits::default(),
            ServerProtocolContext::Stream,
        )
        .unwrap_err();
        assert!(error.to_string().contains("hybrid-only"), "{error}");
    }
    let client: ClientProxyConfig = serde_json::from_value(serde_json::json!({
        "type": "tls", "key_exchange_groups": ["SecP256r1MLKEM768"], "vision": true,
        "protocol": {"type": "vless", "user_id": "550e8400-e29b-41d4-a716-446655440000"}
    }))
    .unwrap();
    assert!(
        validate_client_proxy_structure(&client)
            .unwrap_err()
            .to_string()
            .contains("hybrid-only")
    );
    let server: ServerConfig = serde_json::from_value(serde_json::json!({
            "address": "0.0.0.0:443", "transport": "quic",
            "quic_settings": {"cert": cert.cert.pem(), "key": cert.signing_key.serialize_pem(), "key_exchange_groups": ["X25519MLKEM768"]},
            "protocol": {"type": "tuic", "uuid": "550e8400-e29b-41d4-a716-446655440000", "password": "test", "zero_rtt_handshake": true}
        })).unwrap();
    assert!(
        resolve_server_config(
            server,
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
            GlobalLimits::default(),
        )
        .unwrap_err()
        .to_string()
        .contains("zero_rtt_handshake")
    );
}

#[test]
fn quic_allowlists_cannot_be_ignored_by_direct_or_later_hops() {
    use serde_json::json;
    for groups in [
        None,
        Some(json!(["X25519MLKEM768"])),
        Some(json!(["X25519"])),
    ] {
        let mut settings = json!({});
        if let Some(ref groups) = groups {
            settings["key_exchange_groups"] = groups.clone();
        }
        let direct =
            json!({"protocol": {"type": "direct"}, "transport": "quic", "quic_settings": settings});
        let config: ClientConfig = serde_json::from_value(direct).unwrap();
        let result = resolve_client_config(config, &HashMap::new());
        assert_eq!(result.is_err(), groups.is_some());

        let proxy = json!({"address": "127.0.0.1:443", "protocol": {"type": "socks"}, "transport": "quic", "quic_settings": settings});
        let group_configs = HashMap::from([(
            "proxy".into(),
            HopPlan::Single(DraftClient::Ready(crate::config::test_support::client(
                serde_json::from_value::<ClientConfig>(proxy.clone()).unwrap(),
            ))),
        )]);
        for hop in [
            proxy.clone(),
            json!("proxy"),
            json!({"pool": ["proxy", proxy.clone()]}),
        ] {
            let direct = json!({"protocol": {"type": "direct"}});
            for chain in [json!([hop]), json!([direct, hop])] {
                let later_hop = chain.as_array().unwrap().len() > 1;
                let parsed: super::super::types::ClientChain =
                    serde_json::from_value(chain.clone()).unwrap();
                let result = compiler::compile_chain(
                    parsed.hops,
                    &group_configs,
                    &HashMap::new(),
                    GlobalLimits::default(),
                );
                assert_eq!(result.is_err(), later_hop && groups.is_some(), "{chain}");
                if let Err(error) = result {
                    assert!(error.to_string().contains("QUIC key_exchange_groups"));
                }
                let spec: DnsServerSpec = serde_json::from_value(json!({
                    "url": "https://1.1.1.1/dns-query", "client_chain": {"chain": chain}
                }))
                .unwrap();
                let result = expand_dns_specs(
                    &[spec],
                    &group_configs,
                    &HashMap::new(),
                    &HashSet::new(),
                    GlobalLimits::default(),
                );
                assert_eq!(result.is_err(), later_hop && groups.is_some());
                if let Err(error) = result {
                    assert!(error.to_string().contains("QUIC key_exchange_groups"));
                }
            }
        }
    }
}

#[tokio::test]
async fn test_validate_config_success() {
    use crate::config::types::ClientConfigGroup;
    use crate::config::types::groups::RuleConfigGroup;

    let configs = vec![
        Config::RuleConfigGroup(RuleConfigGroup {
            rule_group: "test-rules".to_string(),
            rules: OneOrSome::One(RuleConfig {
                criteria: Default::default(),
                action: RuleActionConfig::Allow {
                    override_address: None,
                    client_chains: NoneOrSome::One(ClientChain::default()),
                },
            }),
        }),
        Config::ClientConfigGroup(ClientConfigGroup {
            group_type: Default::default(),
            default: None,
            client_group: "test-group".to_string(),
            client_chains: OneOrSome::One(ConfigSelection::Config(ClientConfig::default()).into()),
        }),
    ];

    assert!(validate_configs_test(configs).await.is_ok());
}

#[test]
fn hop_dependencies_preserve_pool_order_and_duplicates() {
    use serde_json::json;

    let member = ConfigSelection::GroupName("member".to_owned());
    for hop in [
        ClientChainHop::Single(member.clone()),
        ClientChainHop::Pool(OneOrSome::One(member)),
    ] {
        let mut dependencies = Vec::new();
        collect_hop_dependencies(&hop, &mut dependencies);
        assert_eq!(dependencies, ["member"]);
    }


    let hop = serde_json::from_value(json!({"pool":["head", "inner", "inner", "tail", "head"]})).unwrap();
    let mut dependencies = Vec::new();
    collect_hop_dependencies(&hop, &mut dependencies);
    assert_eq!(dependencies, ["head", "inner", "inner", "tail", "head"]);
}

#[tokio::test]
async fn test_topological_sort_simple() {
    use crate::config::types::ClientConfigGroup;

    // group-b has no dependencies, group-a references group-b
    let configs = vec![
        Config::ClientConfigGroup(ClientConfigGroup {
            group_type: Default::default(),
            default: None,
            client_group: "group-a".to_string(),
            client_chains: OneOrSome::One(ConfigSelection::GroupName("group-b".to_string()).into()),
        }),
        Config::ClientConfigGroup(ClientConfigGroup {
            group_type: Default::default(),
            default: None,
            client_group: "group-b".to_string(),
            client_chains: OneOrSome::One(ConfigSelection::Config(ClientConfig::default()).into()),
        }),
    ];

    assert!(validate_configs_test(configs).await.is_ok());
}

#[tokio::test]
async fn test_topological_sort_cycle_detected() {
    use crate::config::types::ClientConfigGroup;

    let configs = vec![
        Config::ClientConfigGroup(ClientConfigGroup {
            group_type: Default::default(),
            default: None,
            client_group: "group-a".to_string(),
            client_chains: OneOrSome::One(ConfigSelection::GroupName("group-b".to_string()).into()),
        }),
        Config::ClientConfigGroup(ClientConfigGroup {
            group_type: Default::default(),
            default: None,
            client_group: "group-b".to_string(),
            client_chains: OneOrSome::One(ConfigSelection::GroupName("group-a".to_string()).into()),
        }),
    ];

    let result = validate_configs_test(configs).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("Circular dependency"),
        "Error should mention circular dependency: {err}"
    );
}

#[tokio::test]
async fn test_topological_sort_unknown_group() {
    use crate::config::types::ClientConfigGroup;

    let configs = vec![Config::ClientConfigGroup(ClientConfigGroup {
        group_type: Default::default(),
        default: None,
        client_group: "group-a".to_string(),
        client_chains: OneOrSome::One(ConfigSelection::GroupName("nonexistent".to_string()).into()),
    })];

    let result = validate_configs_test(configs).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("unknown group") || err.contains("Unknown"),
        "Error should mention unknown group: {err}"
    );
}

#[tokio::test]
async fn test_topological_sort_diamond() {
    use crate::config::types::ClientConfigGroup;

    // Diamond: a -> b, a -> c, b -> d, c -> d
    let configs = vec![
        Config::ClientConfigGroup(ClientConfigGroup {
            group_type: Default::default(),
            default: None,
            client_group: "group-d".to_string(),
            client_chains: OneOrSome::One(ConfigSelection::Config(ClientConfig::default()).into()),
        }),
        Config::ClientConfigGroup(ClientConfigGroup {
            group_type: Default::default(),
            default: None,
            client_group: "group-c".to_string(),
            client_chains: OneOrSome::One(ConfigSelection::GroupName("group-d".to_string()).into()),
        }),
        Config::ClientConfigGroup(ClientConfigGroup {
            group_type: Default::default(),
            default: None,
            client_group: "group-b".to_string(),
            client_chains: OneOrSome::One(ConfigSelection::GroupName("group-d".to_string()).into()),
        }),
        Config::ClientConfigGroup(ClientConfigGroup {
            group_type: Default::default(),
            default: None,
            client_group: "group-a".to_string(),
            client_chains: OneOrSome::Some(vec![
                ConfigSelection::GroupName("group-b".to_string()).into(),
                ConfigSelection::GroupName("group-c".to_string()).into(),
            ]),
        }),
    ];

    assert!(validate_configs_test(configs).await.is_ok());
}

#[tokio::test]
async fn test_nested_groups_resolve() {
    use crate::config::types::ClientConfigGroup;

    let configs = vec![
        Config::ClientConfigGroup(ClientConfigGroup {
            group_type: Default::default(),
            default: None,
            client_group: "us-proxies".to_string(),
            client_chains: OneOrSome::One(ConfigSelection::Config(ClientConfig::default()).into()),
        }),
        Config::ClientConfigGroup(ClientConfigGroup {
            group_type: Default::default(),
            default: None,
            client_group: "eu-proxies".to_string(),
            client_chains: OneOrSome::One(ConfigSelection::Config(ClientConfig::default()).into()),
        }),
        Config::ClientConfigGroup(ClientConfigGroup {
            group_type: Default::default(),
            default: None,
            client_group: "all-proxies".to_string(),
            client_chains: OneOrSome::Some(vec![
                ConfigSelection::GroupName("us-proxies".to_string()).into(),
                ConfigSelection::GroupName("eu-proxies".to_string()).into(),
            ]),
        }),
    ];

    assert!(validate_configs_test(configs).await.is_ok());
}

#[tokio::test]
async fn test_empty_config() {
    let original: Vec<Config> = vec![];
    let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
    let deserialized: Vec<Config> = serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");

    assert_eq!(deserialized.len(), 0);
    assert!(validate_configs_test(deserialized).await.is_ok());
}

#[tokio::test]
async fn test_named_pem_duplicate_names() {
    let configs = vec![
        Config::NamedPem(super::super::types::NamedPem {
            pem: "duplicate-name".to_string(),
            source: PemSource::Data("pem1".to_string()),
        }),
        Config::NamedPem(super::super::types::NamedPem {
            pem: "duplicate-name".to_string(),
            source: PemSource::Data("pem2".to_string()),
        }),
    ];

    let result = validate_configs_test(configs).await;
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("named pem already exists: duplicate-name")
    );
}



#[test]
fn test_direct_connector_at_hop_0_allowed() {
    // Single direct connector at hop 0 should be allowed
    let hops = OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(
        ClientConfig::default(), // default is direct
    )));

    assert!(
        composition::validate(&crate::config::test_support::chain(ClientChain { hops }).hops)
            .is_ok()
    );
}

fn http_proxy_config() -> ClientProxyConfig {
    ClientProxyConfig::Http {
        settings: Default::default(),
        username: None,
        password: None,
        resolve_hostname: false,
        http_version: Default::default(),
    }
}

fn socks_proxy_config() -> ClientProxyConfig {
    ClientProxyConfig::Socks {
        username: None,
        password: None,
    }
}

#[test]
fn test_direct_then_proxy_allowed() {
    // Direct at hop 0, proxy at hop 1 - should be allowed
    let hops = OneOrSome::Some(vec![
        ClientChainHop::Single(ConfigSelection::Config(ClientConfig::default())),
        ClientChainHop::Single(ConfigSelection::Config(ClientConfig {
            protocol: http_proxy_config(),
            ..Default::default()
        })),
    ]);

    assert!(
        composition::validate(&crate::config::test_support::chain(ClientChain { hops }).hops)
            .is_ok()
    );
}

#[test]
fn test_proxy_then_proxy_allowed() {
    // Proxy at hop 0, proxy at hop 1 - should be allowed
    let hops = OneOrSome::Some(vec![
        ClientChainHop::Single(ConfigSelection::Config(ClientConfig {
            protocol: http_proxy_config(),
            ..Default::default()
        })),
        ClientChainHop::Single(ConfigSelection::Config(ClientConfig {
            protocol: socks_proxy_config(),
            ..Default::default()
        })),
    ]);

    assert!(
        composition::validate(&crate::config::test_support::chain(ClientChain { hops }).hops)
            .is_ok()
    );
}

#[test]
fn test_direct_at_hop_1_rejected() {
    // Direct at hop 1 should be rejected
    let hops = OneOrSome::Some(vec![
        ClientChainHop::Single(ConfigSelection::Config(ClientConfig {
            protocol: http_proxy_config(),
            ..Default::default()
        })),
        ClientChainHop::Single(ConfigSelection::Config(ClientConfig::default())), // direct
    ]);

    let result =
        composition::validate(&crate::config::test_support::chain(ClientChain { hops }).hops);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("hop 1"));
}

#[test]
fn test_direct_in_middle_of_chain_rejected() {
    // Direct in the middle of a 3-hop chain should be rejected
    let hops = OneOrSome::Some(vec![
        ClientChainHop::Single(ConfigSelection::Config(ClientConfig {
            protocol: http_proxy_config(),
            ..Default::default()
        })),
        ClientChainHop::Single(ConfigSelection::Config(ClientConfig::default())), // direct
        ClientChainHop::Single(ConfigSelection::Config(ClientConfig {
            protocol: socks_proxy_config(),
            ..Default::default()
        })),
    ]);

    let result =
        composition::validate(&crate::config::test_support::chain(ClientChain { hops }).hops);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("hop 1"));
}

#[test]
fn test_direct_in_pool_at_hop_0_allowed() {
    // Mixed pool at hop 0 with direct - should be allowed
    let hops = OneOrSome::One(ClientChainHop::Pool(OneOrSome::Some(vec![
        ConfigSelection::Config(ClientConfig::default()), // direct
        ConfigSelection::Config(ClientConfig {
            protocol: http_proxy_config(),
            ..Default::default()
        }),
    ])));

    assert!(
        composition::validate(&crate::config::test_support::chain(ClientChain { hops }).hops)
            .is_ok()
    );
}

#[test]
fn test_direct_in_pool_at_hop_1_rejected() {
    // Mixed pool at hop 1 with direct - should be rejected
    let hops = OneOrSome::Some(vec![
        ClientChainHop::Single(ConfigSelection::Config(ClientConfig {
            protocol: http_proxy_config(),
            ..Default::default()
        })),
        ClientChainHop::Pool(OneOrSome::Some(vec![
            ConfigSelection::Config(ClientConfig::default()), // direct
            ConfigSelection::Config(ClientConfig {
                protocol: socks_proxy_config(),
                ..Default::default()
            }),
        ])),
    ]);

    let result =
        composition::validate(&crate::config::test_support::chain(ClientChain { hops }).hops);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("hop 1"));
}

#[test]
fn test_three_hop_direct_first_then_proxies_allowed() {
    // Direct at hop 0, two proxies following - should be allowed
    let hops = OneOrSome::Some(vec![
        ClientChainHop::Single(ConfigSelection::Config(ClientConfig::default())), // direct
        ClientChainHop::Single(ConfigSelection::Config(ClientConfig {
            protocol: http_proxy_config(),
            ..Default::default()
        })),
        ClientChainHop::Single(ConfigSelection::Config(ClientConfig {
            protocol: socks_proxy_config(),
            ..Default::default()
        })),
    ]);

    assert!(
        composition::validate(&crate::config::test_support::chain(ClientChain { hops }).hops)
            .is_ok()
    );
}

#[tokio::test]
async fn test_tun_config_parsing() {
    let yaml = r#"
- device_name: "tun0"
  address: "10.0.0.1"
  netmask: "255.255.255.0"
  mtu: 1400
  tcp_enabled: true
  udp_enabled: true
  icmp_enabled: false
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        - protocol:
            type: direct
"#;
    let configs: Vec<Config> = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(configs.len(), 1);

    match &configs[0] {
        Config::TunServer(tun) => {
            assert_eq!(tun.device_name, Some("tun0".to_string()));
            assert_eq!(tun.address, Some("10.0.0.1".parse().unwrap()));
            assert_eq!(tun.netmask, Some("255.255.255.0".parse().unwrap()));
            assert_eq!(tun.mtu, 1400);
            assert!(tun.tcp_enabled);
            assert!(tun.udp_enabled);
            assert!(!tun.icmp_enabled);
        }
        _ => panic!("Expected TunServer config"),
    }

    // Validate the config
    let result = validate_configs_test(configs).await;
    assert!(result.is_ok(), "TUN config validation failed: {:?}", result);
}

#[test]
fn tun_dns_interception_override_roundtrips() {
    for value in [None, Some(false), Some(true)] {
        let mut yaml = serde_json::json!({"device_fd":42});
        if let Some(value) = value {
            yaml["dns_hijack"] = value.into();
        }
        let tun: TunConfig = serde_json::from_value(yaml).unwrap();
        assert_eq!(tun.dns_hijack, value);
        let restored: TunConfig =
            serde_yaml::from_str(&serde_yaml::to_string(&tun).unwrap()).unwrap();
        assert_eq!(restored.dns_hijack, value);
    }
}

#[test]
fn tun_managed_options_distinguish_absent_and_disabled_settings() {
    let manual = serde_json::json!({
        "device_fd": 42,
        "auto_route": false,
        "auto_redirect": false,
        "dns_hijack": true,
    });
    let tun: TunConfig = serde_json::from_value(manual.clone()).unwrap();
    assert!(!tun.has_managed_options());
    for (field, value) in [
        ("auto_route", serde_json::json!(true)),
        ("auto_redirect", serde_json::json!(true)),
        ("auto_dns", serde_json::json!(false)),
        ("linux", serde_json::json!({})),
        ("bootstrap_dns", serde_json::json!(["192.0.2.53:53"])),
        ("route_address", serde_json::json!(["0.0.0.0/0"])),
        ("route_exclude_address", serde_json::json!(["192.0.2.0/24"])),
    ] {
        let mut config = manual.clone();
        config[field] = value;
        let tun: TunConfig = serde_json::from_value(config).unwrap();
        assert!(tun.has_managed_options(), "{field}");
    }
    let mut borrowed = manual.clone();
    borrowed["addresses"] = serde_json::json!(["10.233.0.1/30", "fd77::1/126"]);
    let tun: TunConfig = serde_json::from_value(borrowed.clone()).unwrap();
    assert!(
        !tun.has_managed_options(),
        "borrowed FD addresses describe existing TUN"
    );
    borrowed.as_object_mut().unwrap().remove("device_fd");
    let tun: TunConfig = serde_json::from_value(borrowed).unwrap();
    assert!(
        tun.has_managed_options(),
        "creating a TUN still requires address management"
    );
}

#[test]
fn tun_adjacent_dns_addresses_preserve_family_and_check_overflow() {
    for (address, next) in [
        ("10.233.0.1", Some("10.233.0.2")),
        ("fd73::1", Some("fd73::2")),
        ("255.255.255.255", None),
        ("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", None),
    ] {
        assert_eq!(
            crate::config::tun::next_ip_address(address.parse().unwrap()),
            next.map(|address| address.parse().unwrap()),
        );
    }
}

#[tokio::test]
async fn test_tun_config_with_device_fd() {
    let yaml = r#"
- device_fd: 42
  mtu: 1500
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        - protocol:
            type: direct
"#;
    let configs: Vec<Config> = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(configs.len(), 1);

    match &configs[0] {
        Config::TunServer(tun) => {
            assert_eq!(tun.device_fd, Some(42));
            assert_eq!(tun.device_name, None);
            assert_eq!(tun.mtu, 1500);
        }
        _ => panic!("Expected TunServer config"),
    }
}

#[tokio::test]
async fn test_tun_config_defaults() {
    let yaml = r#"
- device_name: "tun0"
  address: "10.0.0.1"
"#;
    let configs: Vec<Config> = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(configs.len(), 1);

    match &configs[0] {
        Config::TunServer(tun) => {
            // Check defaults
            assert_eq!(tun.mtu, 1500); // default
            assert!(tun.tcp_enabled); // default true
            assert!(tun.udp_enabled); // default true
            assert!(tun.icmp_enabled); // default true
        }
        _ => panic!("Expected TunServer config"),
    }
}

#[tokio::test]
async fn test_tun_icmp_requires_tcp() {
    // ICMP requires TCP to be enabled
    let tun_config = TunConfig {
        auto_route: false,
        auto_redirect: false,
        auto_dns: None,
        addresses: Vec::new(),
        route_address: Vec::new(),
        route_exclude_address: Vec::new(),
        bootstrap_dns: Vec::new(),
        linux: None,
        dns_hijack: None,
        name: None,
        sniff: false,
        segmentation_offload: None,
        resource_limits: Default::default(),
        packet_information: None,
        device_name: Some("tun0".to_string()),
        device_fd: None,
        address: Some("10.0.0.1".parse().unwrap()),
        netmask: None,
        destination: None,
        mtu: 1500,
        tcp_enabled: false, // TCP disabled
        udp_enabled: true,
        icmp_enabled: true, // but ICMP enabled - should fail
        rules: NoneOrSome::Unspecified,
        dns: None,
    };

    let configs = vec![Config::TunServer(tun_config)];
    let result = validate_configs_test(configs).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("TCP must be enabled for ICMP"),
        "Expected ICMP/TCP error, got: {err}"
    );
}

#[tokio::test]
async fn test_dns_system_with_client_chain_rejected() {
    let configs = vec![Config::DnsConfigGroup(DnsConfigGroup {
        routing: None,
        hosts: Default::default(),
        fake_ip: None,
        dns_group: "test-dns".to_string(),
        dns_servers: NoneOrSome::One(DnsServerSpec::WithOptions {
            url: "system".to_string(),
            client_chain: NoneOrSome::One(ClientChain::default()),
            bootstrap_url: None,
            server_name: None,
            ip_strategy: IpStrategy::default(),
            timeout_secs: 10,
            connect_timeout_secs: 5,
            attempts: 1,
            native_cache_secs: None,
        }),
    })];

    let result = validate_configs_test(configs).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("client_chain is not supported for system DNS"),
        "Expected system DNS client_chain error, got: {err}"
    );
}

#[test]
fn dns_chain_aliases_expand_sequential_groups_in_order() {
    use serde_json::json;
    for field in ["client_chain", "client_chains"] {
        for chain in [
            json!(["a", "b"]),
            json!({"chain": ["a", "b"]}),
            json!([{"chain": ["a", "b"]}]),
        ] {
            let configs = serde_json::from_value(json!([
            {"client_group":"a", "client_chain":{"address":"192.0.2.1:1080", "protocol":{"type":"socks"}}},
            {"client_group":"b", "client_chain":{"address":"192.0.2.2:1080", "protocol":{"type":"socks"}}},
            {"dns_group":"dns", "dns_servers":[{"url":"tcp://192.0.2.53", field:chain}]}
        ])).unwrap();
            let validated = crate::config::create_server_configs(configs).unwrap();
            let chains = &validated.dns_groups[0].specs[0].client_chains;
            assert_eq!(chains.len(), 1);
            let addresses: Vec<_> = chains[0]
                .hops
                .iter()
                .map(|hop| {
                    let ResolvedClientHop::Single(client) = hop else {
                        panic!("expected a fixed hop")
                    };
                    client.address.to_string()
                })
                .collect();
            assert_eq!(addresses, ["192.0.2.1:1080", "192.0.2.2:1080"]);
        }
    }
}

#[test]
fn test_dns_native_cache_only_accepts_system_specs() {
    for url in [
        "system",
        "udp://192.0.2.1",
        "tcp://192.0.2.1",
        "tls://192.0.2.1",
        "https://192.0.2.1/dns-query",
        "h3://192.0.2.1/dns-query",
    ] {
        for seconds in [0, 7] {
            let yaml = format!(
                "- dns_group: native\n  dns_servers: [{{url: '{url}', native_cache_secs: {seconds}}}]\n- dns_group: composed\n  dns_servers: native\n"
            );
            let result = create_server_configs(serde_yaml::from_str(&yaml).unwrap());
            if url == "system" {
                let config = result.unwrap();
                assert_eq!(config.dns_groups.len(), 2);
                for group in config.dns_groups {
                    assert_eq!(group.specs[0].native_cache_secs, seconds);
                }
            } else {
                let error = result.err().expect("non-system cache option must fail");
                assert!(
                    error
                        .to_string()
                        .contains("native_cache_secs is only supported for system")
                );
            }
        }
    }
}

#[test]
fn test_dns_tuning_example_validates() {
    create_server_configs(
        serde_yaml::from_str(include_str!("../../../examples/dns_tuning.yaml")).unwrap(),
    )
    .unwrap();
}

#[tokio::test]
async fn test_dns_udp_requires_udp_capable_proxy_chain() {
    use crate::config::types::{ClientConfigGroup, ClientProxyConfig};

    // SOCKS5 carries datagrams; an HTTP CONNECT chain cannot.
    let socks_config = ClientConfig {
        protocol: ClientProxyConfig::Socks {
            username: None,
            password: None,
        },
        ..Default::default()
    };

    let mut configs = vec![
        Config::ClientConfigGroup(ClientConfigGroup {
            group_type: Default::default(),
            default: None,
            client_group: "test-proxy".to_string(),
            client_chains: OneOrSome::One(ConfigSelection::Config(socks_config).into()),
        }),
        Config::DnsConfigGroup(DnsConfigGroup {
            routing: None,
            hosts: Default::default(),
            fake_ip: None,
            dns_group: "test-dns".to_string(),
            dns_servers: NoneOrSome::One(DnsServerSpec::WithOptions {
                url: "udp://8.8.8.8".to_string(),
                client_chain: NoneOrSome::One(ClientChain {
                    hops: OneOrSome::One(ClientChainHop::Single(ConfigSelection::GroupName(
                        "test-proxy".to_string(),
                    ))),
                }),
                bootstrap_url: None,
                server_name: None,
                ip_strategy: IpStrategy::default(),
                timeout_secs: 10,
                connect_timeout_secs: 5,
                attempts: 1,
                native_cache_secs: None,
            }),
        }),
    ];

    validate_configs_test(configs.clone()).await.unwrap();
    let Config::ClientConfigGroup(group) = &mut configs[0] else {
        unreachable!()
    };
    group.client_chains = OneOrSome::One(
        ConfigSelection::Config(ClientConfig {
            protocol: http_proxy_config(),
            ..Default::default()
        })
        .into(),
    );
    let result = validate_configs_test(configs).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("UDP/QUIC DNS requires a UDP-capable client chain"),
        "Expected UDP DNS client_chain error, got: {err}"
    );
}

#[tokio::test]
async fn test_dns_udp_with_direct_chain_allowed() {
    use crate::config::types::ClientConfigGroup;

    // Create a direct chain - should be allowed for UDP (for bind_interface).
    let configs = vec![
        Config::ClientConfigGroup(ClientConfigGroup {
            group_type: Default::default(),
            default: None,
            client_group: "direct-chain".to_string(),
            client_chains: OneOrSome::One(ConfigSelection::Config(ClientConfig::default()).into()),
        }),
        Config::DnsConfigGroup(DnsConfigGroup {
            routing: None,
            hosts: Default::default(),
            fake_ip: None,
            dns_group: "test-dns".to_string(),
            dns_servers: NoneOrSome::One(DnsServerSpec::WithOptions {
                url: "udp://8.8.8.8".to_string(),
                client_chain: NoneOrSome::One(ClientChain {
                    hops: OneOrSome::One(ClientChainHop::Single(ConfigSelection::GroupName(
                        "direct-chain".to_string(),
                    ))),
                }),
                bootstrap_url: None,
                server_name: None,
                ip_strategy: IpStrategy::default(),
                timeout_secs: 10,
                connect_timeout_secs: 5,
                attempts: 1,
                native_cache_secs: None,
            }),
        }),
    ];

    assert!(validate_configs_test(configs).await.is_ok());
}

#[tokio::test]
async fn test_dns_h3_requires_udp_capable_proxy_chain() {
    use crate::config::types::{ClientConfigGroup, ClientProxyConfig};

    // HTTP/3 DNS can use SOCKS5 UDP but cannot use an HTTP CONNECT chain.
    let socks_config = ClientConfig {
        protocol: ClientProxyConfig::Socks {
            username: None,
            password: None,
        },
        ..Default::default()
    };

    let mut configs = vec![
        Config::ClientConfigGroup(ClientConfigGroup {
            group_type: Default::default(),
            default: None,
            client_group: "test-proxy".to_string(),
            client_chains: OneOrSome::One(ConfigSelection::Config(socks_config).into()),
        }),
        Config::DnsConfigGroup(DnsConfigGroup {
            routing: None,
            hosts: Default::default(),
            fake_ip: None,
            dns_group: "test-dns".to_string(),
            dns_servers: NoneOrSome::One(DnsServerSpec::WithOptions {
                url: "h3://1.1.1.1/dns-query".to_string(),
                client_chain: NoneOrSome::One(ClientChain {
                    hops: OneOrSome::One(ClientChainHop::Single(ConfigSelection::GroupName(
                        "test-proxy".to_string(),
                    ))),
                }),
                bootstrap_url: None,
                server_name: None,
                ip_strategy: IpStrategy::default(),
                timeout_secs: 10,
                connect_timeout_secs: 5,
                attempts: 1,
                native_cache_secs: None,
            }),
        }),
    ];

    validate_configs_test(configs.clone()).await.unwrap();
    let Config::ClientConfigGroup(group) = &mut configs[0] else {
        unreachable!()
    };
    group.client_chains = OneOrSome::One(
        ConfigSelection::Config(ClientConfig {
            protocol: http_proxy_config(),
            ..Default::default()
        })
        .into(),
    );
    let result = validate_configs_test(configs).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("UDP/QUIC DNS requires a UDP-capable client chain"),
        "Expected H3 DNS client_chain error, got: {err}"
    );
}

#[tokio::test]
async fn test_dns_h3_with_direct_chain_allowed() {
    use crate::config::types::ClientConfigGroup;

    // Create a direct chain - should be allowed for H3 (for bind_interface).
    let configs = vec![
        Config::ClientConfigGroup(ClientConfigGroup {
            group_type: Default::default(),
            default: None,
            client_group: "direct-chain".to_string(),
            client_chains: OneOrSome::One(ConfigSelection::Config(ClientConfig::default()).into()),
        }),
        Config::DnsConfigGroup(DnsConfigGroup {
            routing: None,
            hosts: Default::default(),
            fake_ip: None,
            dns_group: "test-dns".to_string(),
            dns_servers: NoneOrSome::One(DnsServerSpec::WithOptions {
                url: "h3://1.1.1.1/dns-query".to_string(),
                client_chain: NoneOrSome::One(ClientChain {
                    hops: OneOrSome::One(ClientChainHop::Single(ConfigSelection::GroupName(
                        "direct-chain".to_string(),
                    ))),
                }),
                bootstrap_url: None,
                server_name: None,
                ip_strategy: IpStrategy::default(),
                timeout_secs: 10,
                connect_timeout_secs: 5,
                attempts: 1,
                native_cache_secs: None,
            }),
        }),
    ];

    assert!(validate_configs_test(configs).await.is_ok());
}

#[tokio::test]
async fn test_dns_tcp_with_client_chain_allowed() {
    use crate::config::types::ClientConfigGroup;

    let configs = vec![
        Config::ClientConfigGroup(ClientConfigGroup {
            group_type: Default::default(),
            default: None,
            client_group: "test-proxy".to_string(),
            client_chains: OneOrSome::One(ConfigSelection::Config(ClientConfig::default()).into()),
        }),
        Config::DnsConfigGroup(DnsConfigGroup {
            routing: None,
            hosts: Default::default(),
            fake_ip: None,
            dns_group: "test-dns".to_string(),
            dns_servers: NoneOrSome::One(DnsServerSpec::WithOptions {
                url: "tcp://8.8.8.8".to_string(),
                client_chain: NoneOrSome::One(ClientChain {
                    hops: OneOrSome::One(ClientChainHop::Single(ConfigSelection::GroupName(
                        "test-proxy".to_string(),
                    ))),
                }),
                bootstrap_url: None,
                server_name: None,
                ip_strategy: IpStrategy::default(),
                timeout_secs: 10,
                connect_timeout_secs: 5,
                attempts: 1,
                native_cache_secs: None,
            }),
        }),
    ];

    // TCP with client_chain should be allowed
    assert!(validate_configs_test(configs).await.is_ok());
}

#[tokio::test]
async fn test_dns_tls_with_client_chain_allowed() {
    use crate::config::types::ClientConfigGroup;

    let configs = vec![
        Config::ClientConfigGroup(ClientConfigGroup {
            group_type: Default::default(),
            default: None,
            client_group: "test-proxy".to_string(),
            client_chains: OneOrSome::One(ConfigSelection::Config(ClientConfig::default()).into()),
        }),
        Config::DnsConfigGroup(DnsConfigGroup {
            routing: None,
            hosts: Default::default(),
            fake_ip: None,
            dns_group: "test-dns".to_string(),
            dns_servers: NoneOrSome::One(DnsServerSpec::WithOptions {
                url: "tls://1.1.1.1".to_string(),
                client_chain: NoneOrSome::One(ClientChain {
                    hops: OneOrSome::One(ClientChainHop::Single(ConfigSelection::GroupName(
                        "test-proxy".to_string(),
                    ))),
                }),
                bootstrap_url: None,
                server_name: None,
                ip_strategy: IpStrategy::default(),
                timeout_secs: 10,
                connect_timeout_secs: 5,
                attempts: 1,
                native_cache_secs: None,
            }),
        }),
    ];

    // TLS with client_chain should be allowed
    assert!(validate_configs_test(configs).await.is_ok());
}

#[tokio::test]
async fn test_dns_https_with_client_chain_allowed() {
    use crate::config::types::ClientConfigGroup;

    let configs = vec![
        Config::ClientConfigGroup(ClientConfigGroup {
            group_type: Default::default(),
            default: None,
            client_group: "test-proxy".to_string(),
            client_chains: OneOrSome::One(ConfigSelection::Config(ClientConfig::default()).into()),
        }),
        Config::DnsConfigGroup(DnsConfigGroup {
            routing: None,
            hosts: Default::default(),
            fake_ip: None,
            dns_group: "test-dns".to_string(),
            dns_servers: NoneOrSome::One(DnsServerSpec::WithOptions {
                url: "https://1.1.1.1/dns-query".to_string(),
                client_chain: NoneOrSome::One(ClientChain {
                    hops: OneOrSome::One(ClientChainHop::Single(ConfigSelection::GroupName(
                        "test-proxy".to_string(),
                    ))),
                }),
                bootstrap_url: None,
                server_name: None,
                ip_strategy: IpStrategy::default(),
                timeout_secs: 10,
                connect_timeout_secs: 5,
                attempts: 1,
                native_cache_secs: None,
            }),
        }),
    ];

    // HTTPS with client_chain should be allowed
    assert!(validate_configs_test(configs).await.is_ok());
}

#[tokio::test]
async fn test_dns_group_composition_basic() {
    // Group full-dns includes base-dns
    let configs = vec![
        Config::DnsConfigGroup(DnsConfigGroup {
            routing: None,
            hosts: Default::default(),
            fake_ip: None,
            dns_group: "base-dns".to_string(),
            dns_servers: NoneOrSome::Some(vec![
                DnsServerSpec::Simple("udp://8.8.8.8".to_string()),
                DnsServerSpec::Simple("udp://8.8.4.4".to_string()),
            ]),
        }),
        Config::DnsConfigGroup(DnsConfigGroup {
            routing: None,
            hosts: Default::default(),
            fake_ip: None,
            dns_group: "full-dns".to_string(),
            dns_servers: NoneOrSome::Some(vec![
                DnsServerSpec::Simple("base-dns".to_string()), // Group reference
                DnsServerSpec::Simple("tls://1.1.1.1".to_string()),
            ]),
        }),
    ];

    let result = validate_configs_test(configs).await;
    assert!(
        result.is_ok(),
        "composition should work: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn test_dns_group_composition_multi_level() {
    // C includes B, B includes A
    let configs = vec![
        Config::DnsConfigGroup(DnsConfigGroup {
            routing: None,
            hosts: Default::default(),
            fake_ip: None,
            dns_group: "level-a".to_string(),
            dns_servers: NoneOrSome::One(DnsServerSpec::Simple("udp://8.8.8.8".to_string())),
        }),
        Config::DnsConfigGroup(DnsConfigGroup {
            routing: None,
            hosts: Default::default(),
            fake_ip: None,
            dns_group: "level-b".to_string(),
            dns_servers: NoneOrSome::Some(vec![
                DnsServerSpec::Simple("level-a".to_string()),
                DnsServerSpec::Simple("udp://1.1.1.1".to_string()),
            ]),
        }),
        Config::DnsConfigGroup(DnsConfigGroup {
            routing: None,
            hosts: Default::default(),
            fake_ip: None,
            dns_group: "level-c".to_string(),
            dns_servers: NoneOrSome::Some(vec![
                DnsServerSpec::Simple("level-b".to_string()),
                DnsServerSpec::Simple("system".to_string()),
            ]),
        }),
    ];

    let result = validate_configs_test(configs).await;
    assert!(
        result.is_ok(),
        "multi-level composition should work: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn test_dns_group_composition_cycle_detected() {
    // A includes B, B includes A - cycle!
    let configs = vec![
        Config::DnsConfigGroup(DnsConfigGroup {
            routing: None,
            hosts: Default::default(),
            fake_ip: None,
            dns_group: "group-a".to_string(),
            dns_servers: NoneOrSome::One(DnsServerSpec::Simple("group-b".to_string())),
        }),
        Config::DnsConfigGroup(DnsConfigGroup {
            routing: None,
            hosts: Default::default(),
            fake_ip: None,
            dns_group: "group-b".to_string(),
            dns_servers: NoneOrSome::One(DnsServerSpec::Simple("group-a".to_string())),
        }),
    ];

    let result = validate_configs_test(configs).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("Circular dependency") || err.contains("cycle"),
        "Expected cycle error, got: {err}"
    );
}

#[tokio::test]
async fn test_dns_group_composition_unknown_ref() {
    // Reference to non-existent group
    let configs = vec![Config::DnsConfigGroup(DnsConfigGroup {
        routing: None,
        hosts: Default::default(),
        fake_ip: None,
        dns_group: "my-dns".to_string(),
        dns_servers: NoneOrSome::One(DnsServerSpec::Simple("nonexistent".to_string())),
    })];

    let result = validate_configs_test(configs).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("unknown group") || err.contains("nonexistent"),
        "Expected unknown group error, got: {err}"
    );
}

#[tokio::test]
async fn test_dns_group_composition_with_bootstrap() {
    // Composition and bootstrap work together
    // Note: Using IP-based URLs to avoid network calls during tests
    let configs = vec![
        Config::DnsConfigGroup(DnsConfigGroup {
            routing: None,
            hosts: Default::default(),
            fake_ip: None,
            dns_group: "bootstrap-dns".to_string(),
            dns_servers: NoneOrSome::One(DnsServerSpec::Simple("udp://8.8.8.8".to_string())),
        }),
        Config::DnsConfigGroup(DnsConfigGroup {
            routing: None,
            hosts: Default::default(),
            fake_ip: None,
            dns_group: "base-dns".to_string(),
            dns_servers: NoneOrSome::One(DnsServerSpec::Simple("tls://1.1.1.1".to_string())),
        }),
        Config::DnsConfigGroup(DnsConfigGroup {
            routing: None,
            hosts: Default::default(),
            fake_ip: None,
            dns_group: "full-dns".to_string(),
            dns_servers: NoneOrSome::Some(vec![
                DnsServerSpec::Simple("base-dns".to_string()), // Composition reference
                DnsServerSpec::WithOptions {
                    url: "tls://8.8.4.4".to_string(), // IP-based, no resolution needed
                    client_chain: NoneOrSome::None,
                    bootstrap_url: Some("bootstrap-dns".to_string()), // Bootstrap reference (not used since URL is IP)
                    server_name: Some("dns.google".to_string()),      // SNI override
                    ip_strategy: IpStrategy::default(),
                    timeout_secs: 10,
                    connect_timeout_secs: 5,
                    attempts: 1,
                    native_cache_secs: None,
                },
            ]),
        }),
    ];

    let result = validate_configs_test(configs).await;
    assert!(
        result.is_ok(),
        "composition with bootstrap should work: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn test_empty_dns_lists_use_default_resolver() {
    use serde_json::json;

    let configs = serde_json::from_value(json!([
        {"address": "127.0.0.1:1080", "protocol": {"type": "socks"}, "dns": {"servers": []}},
        {"device_fd": 42, "dns": {"servers": []}},
    ]))
    .unwrap();
    let configs = validate_configs_test(configs).await.unwrap();
    assert_eq!(configs.len(), 2);
    for config in configs {
        let dns = match config {
            ResolvedConfig::Server(server) => server.dns.unwrap(),
            ResolvedConfig::TunServer(tun) => tun.dns.unwrap(),
        };
        assert_eq!(dns.resolved_group(), None);
    }
}

#[tokio::test]
async fn test_server_dns_with_group_ref() {
    use crate::address::NetLocationPortRange;
    use crate::config::types::dns::DnsConfig;
    use crate::config::types::transport::BindLocation;

    // Server config references an existing dns_group
    let configs = vec![
        Config::DnsConfigGroup(DnsConfigGroup {
            routing: None,
            hosts: Default::default(),
            fake_ip: None,
            dns_group: "my-dns".to_string(),
            dns_servers: NoneOrSome::One(DnsServerSpec::Simple("udp://8.8.8.8".to_string())),
        }),
        Config::Server(ServerConfig {
            name: None,
            sniff: false,
            dns_hijack: false,
            bind_location: BindLocation::Address(OneOrSome::One(
                NetLocationPortRange::new(
                    crate::address::Address::Ipv4(std::net::Ipv4Addr::LOCALHOST),
                    vec![1234],
                )
                .unwrap(),
            )),
            protocol: ServerProxyConfig::Http {
                username: None,
                password: None,
            },
            transport: Transport::Tcp,
            tcp_settings: None,
            quic_settings: None,
            rules: direct_allow_rule(),
            dns: Some(DnsConfig {
                hosts: Default::default(),
                fake_ip: None,
                servers: NoneOrSome::One(DnsServerSpec::Simple("my-dns".to_string())),
            }),
        }),
    ];

    let result = validate_configs_test(configs).await;
    assert!(
        result.is_ok(),
        "server with dns group ref should work: {:?}",
        result.err()
    );

    // Verify servers is still the group name (not expanded)
    let validated = result.unwrap();
    if let ResolvedConfig::Server(s) = &validated[0] {
        assert_eq!(s.dns.as_ref().unwrap().resolved_group(), Some("my-dns"));
    }
}

#[tokio::test]
async fn test_server_dns_with_mixed_group_and_url() {
    use crate::address::NetLocationPortRange;
    use crate::config::types::dns::DnsConfig;
    use crate::config::types::transport::BindLocation;

    // Server config with both group ref and URL in servers
    let configs = vec![
        Config::DnsConfigGroup(DnsConfigGroup {
            routing: None,
            hosts: Default::default(),
            fake_ip: None,
            dns_group: "base-dns".to_string(),
            dns_servers: NoneOrSome::One(DnsServerSpec::Simple("udp://8.8.8.8".to_string())),
        }),
        Config::Server(ServerConfig {
            name: None,
            sniff: false,
            dns_hijack: false,
            bind_location: BindLocation::Address(OneOrSome::One(
                NetLocationPortRange::new(
                    crate::address::Address::Ipv4(std::net::Ipv4Addr::LOCALHOST),
                    vec![1234],
                )
                .unwrap(),
            )),
            protocol: ServerProxyConfig::Http {
                username: None,
                password: None,
            },
            transport: Transport::Tcp,
            tcp_settings: None,
            quic_settings: None,
            rules: direct_allow_rule(),
            dns: Some(DnsConfig {
                hosts: Default::default(),
                fake_ip: None,
                servers: NoneOrSome::Some(vec![
                    DnsServerSpec::Simple("base-dns".to_string()), // group ref
                    DnsServerSpec::Simple("udp://1.1.1.1".to_string()), // URL
                ]),
            }),
        }),
    ];

    let result = validate_configs_test(configs).await;
    assert!(
        result.is_ok(),
        "server with mixed dns should work: {:?}",
        result.err()
    );

    // Verify servers was expanded to an inline group name
    let validated = result.unwrap();
    if let ResolvedConfig::Server(s) = &validated[0] {
        let group = s.dns.as_ref().unwrap().resolved_group().unwrap();
        assert!(
            group.starts_with("__inline_dns_"),
            "should be inline group: {}",
            group
        );
    }
}

#[tokio::test]
async fn test_server_dns_with_multiple_group_refs() {
    use crate::address::NetLocationPortRange;
    use crate::config::types::dns::DnsConfig;
    use crate::config::types::transport::BindLocation;

    // Server config with multiple group refs that need expansion
    let configs = vec![
        Config::DnsConfigGroup(DnsConfigGroup {
            routing: None,
            hosts: Default::default(),
            fake_ip: None,
            dns_group: "fast-dns".to_string(),
            dns_servers: NoneOrSome::One(DnsServerSpec::Simple("udp://8.8.8.8".to_string())),
        }),
        Config::DnsConfigGroup(DnsConfigGroup {
            routing: None,
            hosts: Default::default(),
            fake_ip: None,
            dns_group: "secure-dns".to_string(),
            dns_servers: NoneOrSome::One(DnsServerSpec::Simple("tcp://1.1.1.1".to_string())),
        }),
        Config::Server(ServerConfig {
            name: None,
            sniff: false,
            dns_hijack: false,
            bind_location: BindLocation::Address(OneOrSome::One(
                NetLocationPortRange::new(
                    crate::address::Address::Ipv4(std::net::Ipv4Addr::LOCALHOST),
                    vec![1234],
                )
                .unwrap(),
            )),
            protocol: ServerProxyConfig::Http {
                username: None,
                password: None,
            },
            transport: Transport::Tcp,
            tcp_settings: None,
            quic_settings: None,
            rules: direct_allow_rule(),
            dns: Some(DnsConfig {
                hosts: Default::default(),
                fake_ip: None,
                servers: NoneOrSome::Some(vec![
                    DnsServerSpec::Simple("fast-dns".to_string()),
                    DnsServerSpec::Simple("secure-dns".to_string()),
                ]),
            }),
        }),
    ];

    let result = validate_configs_test(configs).await;
    assert!(
        result.is_ok(),
        "server with multiple group refs should work: {:?}",
        result.err()
    );

    // Verify servers was expanded to an inline group name
    let validated = result.unwrap();
    if let ResolvedConfig::Server(s) = &validated[0] {
        let group = s.dns.as_ref().unwrap().resolved_group().unwrap();
        assert!(
            group.starts_with("__inline_dns_"),
            "should be inline group: {}",
            group
        );
    }
}

#[tokio::test]
async fn test_server_dns_unknown_group_ref() {
    use crate::address::NetLocationPortRange;
    use crate::config::types::dns::DnsConfig;
    use crate::config::types::transport::BindLocation;

    // Server config references non-existent dns_group
    let configs = vec![Config::Server(ServerConfig {
        name: None,
        sniff: false,
        dns_hijack: false,
        bind_location: BindLocation::Address(OneOrSome::One(
            NetLocationPortRange::new(
                crate::address::Address::Ipv4(std::net::Ipv4Addr::LOCALHOST),
                vec![1234],
            )
            .unwrap(),
        )),
        protocol: ServerProxyConfig::Http {
            username: None,
            password: None,
        },
        transport: Transport::Tcp,
        tcp_settings: None,
        quic_settings: None,
        rules: direct_allow_rule(),
        dns: Some(DnsConfig {
            hosts: Default::default(),
            fake_ip: None,
            servers: NoneOrSome::One(DnsServerSpec::Simple("nonexistent-dns".to_string())),
        }),
    })];

    let result = validate_configs_test(configs).await;
    assert!(result.is_err(), "unknown dns group should fail");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("nonexistent-dns"),
        "error should mention group name: {}",
        err
    );
}
