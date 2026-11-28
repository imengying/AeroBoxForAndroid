use super::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

#[test]
fn sniff_config_defaults_and_round_trips() {
    fn check<T: serde::de::DeserializeOwned + serde::Serialize>(base: &str) {
        let config: T = serde_yaml::from_str(base).unwrap();
        let value = serde_yaml::to_value(config).unwrap();
        assert!(value.get("sniff").is_none());
        for enabled in [false, true] {
            let yaml = format!("{base}\nsniff: {enabled}\n");
            let config: T = serde_yaml::from_str(&yaml).unwrap();
            let value = serde_yaml::to_value(config).unwrap();
            assert_eq!(
                value.get("sniff").and_then(|v| v.as_bool()),
                enabled.then_some(true)
            );
            let round_trip: T = serde_yaml::from_value(value).unwrap();
            assert_eq!(
                serde_yaml::to_value(round_trip)
                    .unwrap()
                    .get("sniff")
                    .and_then(|v| v.as_bool()),
                enabled.then_some(true)
            );
        }
        for value in ["null", "1", "{}", "[tls]", "'true'"] {
            assert!(serde_yaml::from_str::<T>(&format!("{base}\nsniff: {value}\n")).is_err());
        }
        assert!(serde_yaml::from_str::<T>(&format!("{base}\nsnif: true\n")).is_err());
    }
    check::<ServerConfig>("address: '127.0.0.1:1080'\nprotocol: {type: socks}");
    check::<super::super::tun::TunConfig>("mtu: 1500");
    crate::config::create_server_configs(
        serde_yaml::from_str(include_str!("../../../../examples/sni_sniffing.yaml")).unwrap(),
    )
    .unwrap();
    crate::config::create_server_configs(
        serde_yaml::from_str(include_str!("../../../../examples/http_host_sniffing.yaml")).unwrap(),
    )
    .unwrap();
}

fn create_test_server_config_http() -> ServerConfig {
    ServerConfig {
        name: None,
        sniff: false,
        dns_hijack: false,
        bind_location: NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080)
            .into(),
        protocol: ServerProxyConfig::Http {
            username: Some("user".to_string()),
            password: Some("pass".to_string()),
        },
        transport: Transport::Tcp,
        tcp_settings: Some(TcpConfig { no_delay: true }),
        quic_settings: None,
        rules: NoneOrSome::None,
        dns: None,
    }
}

fn create_test_server_config_socks() -> ServerConfig {
    ServerConfig {
        name: None,
        sniff: false,
        dns_hijack: false,
        bind_location: NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 1080)
            .into(),
        protocol: ServerProxyConfig::Socks {
            username: None,
            password: None,
            udp_enabled: false,
        },
        transport: Transport::Tcp,
        tcp_settings: None,
        quic_settings: None,
        rules: NoneOrSome::None,
        dns: None,
    }
}

fn create_test_server_config_shadowsocks() -> ServerConfig {
    ServerConfig {
        name: None,
        sniff: false,
        dns_hijack: false,
        bind_location: BindLocation::Path(PathBuf::from("/tmp/ss.sock")),
        protocol: ServerProxyConfig::Shadowsocks {
            config: ShadowsocksConfig::Legacy {
                cipher: "aes-256-gcm".try_into().unwrap(),
                password: "secret123".to_string(),
            },
            udp_enabled: true,
        },
        transport: Transport::Tcp,
        tcp_settings: None,
        quic_settings: None,
        rules: NoneOrSome::None,
        dns: None,
    }
}

fn create_test_server_config_vless() -> ServerConfig {
    ServerConfig {
        name: None,
        sniff: false,
        dns_hijack: false,
        bind_location: NetLocation::from_ip_addr(
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            443,
        )
        .into(),
        protocol: ServerProxyConfig::Vless {
            user_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            decryption: Default::default(),
            _invalid_encryption: (),
            vision: false,
            encryption_limits: None,
            udp_enabled: true,
            fallback: None,
        },
        transport: Transport::Quic,
        tcp_settings: None,
        quic_settings: Some(ServerQuicConfig {
            certificate_source: None,
            certificate_binding: None,
            key_exchange_groups: Default::default(),
            cert: "server.crt".to_string(),
            key: "server.key".to_string(),
            alpn_protocols: NoneOrSome::Some(vec!["h3".to_string()]),
            client_ca_certs: NoneOrSome::None,
            client_fingerprints: NoneOrSome::None,
            num_endpoints: 1,
        }),
        rules: NoneOrSome::None,
        dns: None,
    }
}

fn create_test_server_config_trojan() -> ServerConfig {
    ServerConfig {
        name: None,
        sniff: false,
        dns_hijack: false,
        bind_location: NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 443)
            .into(),
        protocol: ServerProxyConfig::Trojan {
            password: "trojan_password".to_string(),
            shadowsocks: Some(ShadowsocksConfig::Legacy {
                cipher: "chacha20-poly1305".try_into().unwrap(),
                password: "ss_password".to_string(),
            }),
        },
        transport: Transport::Tcp,
        tcp_settings: None,
        quic_settings: None,
        rules: NoneOrSome::None,
        dns: None,
    }
}

fn create_test_server_config_tls() -> ServerConfig {
    let mut tls_targets = HashMap::new();
    tls_targets.insert(
        "example.com".to_string(),
        TlsServerConfig {
            certificate_source: None,
            certificate_binding: None,
            key_exchange_groups: Default::default(),
            cert: "example.crt".to_string(),
            key: "example.key".to_string(),
            alpn_protocols: NoneOrSome::Some(vec!["h2".to_string(), "http/1.1".to_string()]),
            client_ca_certs: NoneOrSome::One("ca.crt".to_string()),
            client_fingerprints: NoneOrSome::One("abc123".to_string()),
            vision: false,
            protocol: ServerProxyConfig::Http {
                username: None,
                password: None,
            },
            override_rules: NoneOrSome::None,
        },
    );

    ServerConfig {
        bind_location: NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8443)
            .into(),
        name: None,
        sniff: false,
        dns_hijack: false,
        protocol: ServerProxyConfig::Tls {
            tls_targets,
            default_tls_target: Some(Box::new(TlsServerConfig {
                certificate_source: None,
                certificate_binding: None,
                key_exchange_groups: Default::default(),
                cert: "default.crt".to_string(),
                key: "default.key".to_string(),
                alpn_protocols: NoneOrSome::None,
                client_ca_certs: NoneOrSome::None,
                client_fingerprints: NoneOrSome::None,
                vision: false,
                protocol: ServerProxyConfig::Http {
                    username: None,
                    password: None,
                },
                override_rules: NoneOrSome::None,
            })),

            reality_targets: HashMap::new(),
            tls_buffer_size: Some(8192),
        },
        transport: Transport::Tcp,
        tcp_settings: None,
        quic_settings: None,
        rules: NoneOrSome::None,
        dns: None,
    }
}

fn create_test_server_config_vmess() -> ServerConfig {
    ServerConfig {
        name: None,
        sniff: false,
        dns_hijack: false,
        bind_location: NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)), 10086)
            .into(),
        protocol: ServerProxyConfig::Vmess {
            cipher: "aes-128-gcm".to_string(),
            user_id: "b831381d-6324-4d53-ad4f-8cda48b30811".to_string(),
            udp_enabled: false,
        },
        transport: Transport::Tcp,
        tcp_settings: None,
        quic_settings: None,
        rules: NoneOrSome::None,
        dns: None,
    }
}

fn create_test_server_config_websocket() -> ServerConfig {
    ServerConfig {
        name: None,
        sniff: false,
        dns_hijack: false,
        bind_location: NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080)
            .into(),
        protocol: ServerProxyConfig::Websocket {
            targets: Box::new(OneOrSome::One(WebsocketServerConfig {
                max_early_data: 0,
                early_data_header_name: None,
                matching_path: Some("/ws".to_string()),
                matching_headers: None,
                protocol: ServerProxyConfig::Http {
                    username: None,
                    password: None,
                },
                ping_type: WebsocketPingType::PingFrame,
                override_rules: NoneOrSome::None,
            })),
        },
        transport: Transport::Tcp,
        tcp_settings: None,
        quic_settings: None,
        rules: NoneOrSome::None,
        dns: None,
    }
}

fn create_test_server_config_port_forward() -> ServerConfig {
    ServerConfig {
        name: None,
        sniff: false,
        dns_hijack: false,
        bind_location: NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9090)
            .into(),
        protocol: ServerProxyConfig::PortForward {
            targets: OneOrSome::Some(vec![
                NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 80),
                NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 80),
            ]),
        },
        transport: Transport::Tcp,
        tcp_settings: None,
        quic_settings: None,
        rules: NoneOrSome::None,
        dns: None,
    }
}

fn create_test_server_config_hysteria2() -> ServerConfig {
    ServerConfig {
        name: None,
        sniff: false,
        dns_hijack: false,
        bind_location: NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443)
            .into(),
        protocol: ServerProxyConfig::Hysteria2 {
            password: "hysteria_pass".to_string(),
            udp_enabled: true,
        },
        transport: Transport::Quic,
        tcp_settings: None,
        quic_settings: Some(ServerQuicConfig {
            certificate_source: None,
            certificate_binding: None,
            key_exchange_groups: Default::default(),
            cert: "hysteria.crt".to_string(),
            key: "hysteria.key".to_string(),
            alpn_protocols: NoneOrSome::One("hysteria".to_string()),
            client_ca_certs: NoneOrSome::None,
            client_fingerprints: NoneOrSome::None,
            num_endpoints: 1,
        }),
        rules: NoneOrSome::None,
        dns: None,
    }
}

fn create_test_server_config_tuic() -> ServerConfig {
    ServerConfig {
        name: None,
        sniff: false,
        dns_hijack: false,
        bind_location: NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8443)
            .into(),
        protocol: ServerProxyConfig::TuicV5 {
            uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            password: "tuic_password".to_string(),
            zero_rtt_handshake: false,
        },
        transport: Transport::Quic,
        tcp_settings: None,
        quic_settings: Some(ServerQuicConfig {
            certificate_source: None,
            certificate_binding: None,
            key_exchange_groups: Default::default(),
            cert: "tuic.crt".to_string(),
            key: "tuic.key".to_string(),
            alpn_protocols: NoneOrSome::None,
            client_ca_certs: NoneOrSome::None,
            client_fingerprints: NoneOrSome::None,
            num_endpoints: 1,
        }),
        rules: NoneOrSome::None,
        dns: None,
    }
}

// Test individual server config variants
#[test]
fn test_server_config_http() {
    let original = create_test_server_config_http();
    let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
    println!("HTTP config YAML:\n{yaml_str}");
    let deserialized: ServerConfig =
        serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");
    assert!(matches!(
        deserialized.protocol,
        ServerProxyConfig::Http { .. }
    ));
}

#[test]
fn test_server_config_socks() {
    let original = create_test_server_config_socks();
    let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
    let deserialized: ServerConfig =
        serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");
    assert!(matches!(
        deserialized.protocol,
        ServerProxyConfig::Socks { .. }
    ));
}

#[test]
fn test_server_config_shadowsocks() {
    let original = create_test_server_config_shadowsocks();
    let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
    println!("Shadowsocks YAML: {yaml_str}");
    let deserialized: ServerConfig =
        serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");
    assert!(matches!(
        deserialized.protocol,
        ServerProxyConfig::Shadowsocks { .. }
    ));
}

#[test]
fn test_server_config_vless() {
    let original = create_test_server_config_vless();
    let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
    let deserialized: ServerConfig =
        serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");
    assert!(matches!(
        deserialized.protocol,
        ServerProxyConfig::Vless { .. }
    ));
}

#[test]
fn test_server_config_trojan() {
    let original = create_test_server_config_trojan();
    let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
    let deserialized: ServerConfig =
        serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");
    assert!(matches!(
        deserialized.protocol,
        ServerProxyConfig::Trojan { .. }
    ));
}

#[test]
fn test_server_config_tls() {
    let original = create_test_server_config_tls();
    let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
    let deserialized: ServerConfig =
        serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");
    assert!(matches!(
        deserialized.protocol,
        ServerProxyConfig::Tls { .. }
    ));
}

#[test]
fn test_server_config_vmess() {
    let original = create_test_server_config_vmess();
    let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
    let deserialized: ServerConfig =
        serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");
    assert!(matches!(
        deserialized.protocol,
        ServerProxyConfig::Vmess { .. }
    ));
}

#[test]
fn test_server_config_websocket() {
    let original = create_test_server_config_websocket();
    let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
    let deserialized: ServerConfig =
        serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");
    assert!(matches!(
        deserialized.protocol,
        ServerProxyConfig::Websocket { .. }
    ));
}

#[test]
fn test_server_config_port_forward() {
    let original = create_test_server_config_port_forward();
    let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
    let deserialized: ServerConfig =
        serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");
    assert!(matches!(
        deserialized.protocol,
        ServerProxyConfig::PortForward { .. }
    ));
}

#[test]
fn test_server_config_hysteria2() {
    let original = create_test_server_config_hysteria2();
    let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
    let deserialized: ServerConfig =
        serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");
    assert!(matches!(
        deserialized.protocol,
        ServerProxyConfig::Hysteria2 { .. }
    ));
}

#[test]
fn test_server_config_tuic() {
    let original = create_test_server_config_tuic();
    let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
    let deserialized: ServerConfig =
        serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");
    assert!(matches!(
        deserialized.protocol,
        ServerProxyConfig::TuicV5 { .. }
    ));
}

#[test]
fn test_rejects_invalid_upstream_field() {
    let yaml = r#"
address: "127.0.0.1:8080"
protocol:
  type: http
upstream:
  address: "127.0.0.1:443"
  protocol:
    type: vless
    user_id: "test-uuid"
"#;

    let result: Result<ServerConfig, _> = serde_yaml::from_str(yaml);
    assert!(
        result.is_err(),
        "Should reject config with invalid 'upstream' field"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("unknown field") && err.contains("upstream"),
        "Error should mention 'upstream' as unknown field, got: {err}"
    );
}

#[test]
fn test_rejects_typo_in_field_name() {
    let yaml = r#"
address: "127.0.0.1:8080"
protocl:
  type: http
"#;

    let result: Result<ServerConfig, _> = serde_yaml::from_str(yaml);
    assert!(result.is_err(), "Should reject config with typo 'protocl'");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("unknown field") && err.contains("protocl"),
        "Error should mention 'protocl' as unknown field, got: {err}"
    );
}

#[test]
fn test_accepts_valid_server_config() {
    let yaml = r#"
address: "127.0.0.1:8080"
protocol:
  type: http
rules:
  - mask: 0.0.0.0/0
    action: allow
"#;

    let result: Result<ServerConfig, _> = serde_yaml::from_str(yaml);
    assert!(
        result.is_ok(),
        "Should accept valid server config: {:?}",
        result.err()
    );
}

#[test]
fn test_scalar_bind_address_remains_scalar() {
    let yaml = r#"
address: "127.0.0.1:8080"
protocol:
  type: http
"#;

    let config: ServerConfig = serde_yaml::from_str(yaml).unwrap();
    assert!(matches!(
        &config.bind_location,
        BindLocation::Address(OneOrSome::One(_))
    ));

    let value = serde_yaml::to_value(&config).unwrap();
    let address = value
        .as_mapping()
        .unwrap()
        .get(serde_yaml::Value::String("address".to_string()))
        .unwrap();
    assert_eq!(address.as_str(), Some("127.0.0.1:8080"));
}

#[test]
fn test_accepts_multiple_bind_addresses() {
    let yaml = r#"
address:
  - "127.0.0.1:22223"
  - "172.17.0.1:22223-22225"
protocol:
  type: http
"#;

    let config: ServerConfig = serde_yaml::from_str(yaml).unwrap();
    let BindLocation::Address(addresses) = &config.bind_location else {
        panic!("expected address bind location");
    };
    let socket_addrs: Vec<String> = addresses
        .iter()
        .flat_map(|address| address.to_socket_addrs().unwrap())
        .map(|address| address.to_string())
        .collect();
    assert_eq!(
        socket_addrs,
        vec![
            "127.0.0.1:22223",
            "172.17.0.1:22223",
            "172.17.0.1:22224",
            "172.17.0.1:22225",
        ]
    );

    let serialized = serde_yaml::to_string(&config).unwrap();
    let round_tripped: ServerConfig = serde_yaml::from_str(&serialized).unwrap();
    assert_eq!(round_tripped.bind_location, config.bind_location);
}

#[test]
fn test_address_precedes_addresses_alias() {
    let yaml = r#"
address: "127.0.0.1:8080"
addresses:
  - "172.17.0.1:8080"
protocol:
  type: http
"#;

    let config: ServerConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(config.bind_location.to_string(), "127.0.0.1:8080");
}

#[test]
fn test_rejects_empty_bind_address_list() {
    let yaml = r#"
address: []
protocol:
  type: http
"#;

    assert!(serde_yaml::from_str::<ServerConfig>(yaml).is_err());
}

#[test]
fn test_accepts_valid_server_config_with_all_fields() {
    let yaml = r#"
address: "127.0.0.1:8080"
protocol:
  type: http
transport: tcp
tcp_settings:
  no_delay: true
rules:
  - mask: 0.0.0.0/0
    action: allow
"#;

    let result: Result<ServerConfig, _> = serde_yaml::from_str(yaml);
    assert!(
        result.is_ok(),
        "Should accept valid server config with all fields: {:?}",
        result.err()
    );
}

#[test]
fn test_rejects_unknown_field_in_vmess_server() {
    let yaml = r#"
address: "127.0.0.1:8080"
protocol:
  type: vmess
  cipher: aes-128-gcm
  user_id: "b0e80a62-8a51-47f0-91f1-f0f7faf8d9d4"
  typo_field: "should fail"
"#;
    let result: Result<ServerConfig, _> = serde_yaml::from_str(yaml);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("unknown field `typo_field`"),
        "Error should mention unknown field: {err}"
    );
}

// Note: This test was for reject unknown fields in Shadowsocks config.
// After adding udp_enabled with #[serde(flatten)] for ShadowsocksConfig,
// serde can no longer enforce deny_unknown_fields due to a serde limitation.
// See: https://github.com/serde-rs/serde/issues/1547
//
// The test is kept here but modified to verify that the known fields work correctly.
#[test]
fn test_shadowsocks_with_udp_enabled() {
    let yaml = r#"
address: "127.0.0.1:8080"
protocol:
  type: shadowsocks
  cipher: aes-256-gcm
  password: "secret"
  udp_enabled: false
"#;
    let result: Result<ServerConfig, _> = serde_yaml::from_str(yaml);
    assert!(result.is_ok(), "Valid Shadowsocks config should parse");
    let config = result.unwrap();
    if let ServerProxyConfig::Shadowsocks { udp_enabled, .. } = config.protocol {
        assert!(!udp_enabled, "udp_enabled should be false");
    } else {
        panic!("Expected Shadowsocks protocol");
    }
}


















