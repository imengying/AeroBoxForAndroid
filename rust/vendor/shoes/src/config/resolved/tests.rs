use super::*;
use crate::config::{
    ClientChain, ClientChainHop, ClientConfigGroup, ValidatedConfigs, create_server_configs,
};
use serde_json::{Value, json};

fn compile(configs: Value) -> std::io::Result<ValidatedConfigs> {
    create_server_configs(serde_json::from_value(configs).unwrap())
}

#[test]
fn resolved_routes_preserve_identity_serialization_shape() {
    let source = super::super::ClientChain::default();
    let resolved = ResolvedClientChain::default();
    assert_eq!(
        serde_json::to_value(source).unwrap(),
        serde_json::to_value(&resolved).unwrap()
    );
    let choice = HopPlan::Choice(Box::new(ChoicePlan {
        name: "out".into(),
        group_type: GroupType::RoundRobin,
        labels: vec!["direct".into()],
        members: vec![resolved],
    }));
    let value = serde_json::to_value(choice).unwrap();
    assert_eq!(value["name"], "out");
    assert_eq!(value["labels"], serde_json::json!(["direct"]));
    assert_eq!(value["members"][0]["chain"]["protocol"]["type"], "direct");
    assert!(value.get("Choice").is_none());
}

#[test]
fn resolved_client_protocol_serialization_matches_source_bytes() {
    use crate::config::test_support::Inline;

    for protocol in [
        json!({"type":"direct"}),
        json!({"type":"http"}),
        json!({"type":"socks5","username":"user","password":"secret"}),
        json!({"type":"ss","cipher":"aes-128-gcm","password":"secret"}),
        json!({"type":"vless","user_id":"test","vision":true,"udp_enabled":false,"h2mux":{}}),
        json!({"type":"trojan","password":"secret"}),
        json!({"type":"reality","public_key":"test","protocol":{"type":"socks"}}),
        json!({"type":"tls","protocol":{"type":"socks"}}),
        json!({"type":"vmess","cipher":"aes-128-gcm","user_id":"test"}),
        json!({"type":"ws","protocol":{"type":"socks"}}),
        json!({"type":"splithttp","protocol":{"type":"socks"}}),
        json!({"type":"noop"}),
        json!({"type":"anytls","password":"secret","udp_enabled":false}),
        json!({"type":"naive","username":"user","password":"secret","padding":false}),
    ] {
        let source: crate::config::ClientProxyConfig = serde_json::from_value(protocol).unwrap();
        let resolved = ResolvedClientProxyConfig::inline(source.clone());
        assert_eq!(
            serde_yaml::to_string(&source).unwrap(),
            serde_yaml::to_string(&resolved).unwrap()
        );
        assert_eq!(
            serde_json::to_string(&source).unwrap(),
            serde_json::to_string(&resolved).unwrap()
        );
    }
}

#[test]
fn resolved_server_protocol_serialization_matches_source_bytes() {
    use crate::config::test_support::Inline;

    for protocol in [
        json!({"type":"http"}),
        json!({"type":"socks5","udp_enabled":false}),
        json!({"type":"ss","cipher":"aes-128-gcm","password":"secret"}),
        json!({"type":"vless","user_id":"test","vision":true}),
        json!({"type":"trojan","password":"secret"}),
        json!({"type":"tls"}),
        json!({"type":"vmess","cipher":"aes-128-gcm","user_id":"test"}),
        json!({"type":"anytls","user":{"password":"secret"}}),
        json!({"type":"ws","target":{"protocol":{"type":"socks"}}}),
        json!({"type":"splithttp","protocol":{"type":"socks"}}),
        json!({"type":"forward","target":"127.0.0.1:443"}),
        json!({"type":"hysteria2","password":"secret"}),
        json!({"type":"tuic","uuid":"test","password":"secret"}),
        json!({"type":"http+socks"}),
        json!({"type":"naive","user":{"username":"user","password":"secret"}}),
    ] {
        let source: crate::config::ServerProxyConfig = serde_json::from_value(protocol).unwrap();
        let resolved = ResolvedServerProxyConfig::inline(source.clone());
        assert_eq!(
            serde_yaml::to_string(&source).unwrap(),
            serde_yaml::to_string(&resolved).unwrap()
        );
        assert_eq!(
            serde_json::to_string(&source).unwrap(),
            serde_json::to_string(&resolved).unwrap()
        );
    }
}

#[test]
fn resolved_choice_payloads_are_not_source_syntax() {
    let choice = json!({"name":"out","group_type":"round-robin","labels":["direct"],
        "members":[{"chain":{"protocol":{"type":"direct"}}}]});
    assert!(serde_json::from_value::<ClientChainHop>(choice.clone()).is_err());
    assert!(serde_json::from_value::<ClientChain>(json!({"chain":[choice]})).is_err());
    assert!(
        serde_json::from_value::<ClientConfigGroup>(
            json!({"client_group":"out","client_chains":[{"chain":[choice]}]})
        )
        .is_err()
    );
}

#[test]
fn lowering_preserves_defined_validation_precedence() {
    let invalid_client = json!({"address":"192.0.2.1:443",
        "protocol":{"type":"tls","protocol":{"type":"direct"}}});
    let server = |chain: Value| {
        json!({"address":"127.0.0.1:0","protocol":{"type":"socks"},
        "rules":[{"masks":"0.0.0.0/0","action":"allow","client_chain":chain}]})
    };
    for (configs, expected) in [
        (
            json!([server(json!([invalid_client, "missing"]))]),
            "direct cannot be used as an inner",
        ),
        (
            json!([server(json!(["missing", invalid_client]))]),
            "Unknown client group: missing",
        ),
        (
            json!([server(json!([{"pool":[invalid_client, "missing"]}]))]),
            "direct cannot be used as an inner",
        ),
        (
            json!([server(json!([{"pool":["missing", invalid_client]}]))]),
            "direct cannot be used as an inner",
        ),
        (
            json!([{"address":"127.0.0.1:0","protocol":{"type":"shadowsocks","cipher":"invalid","password":"secret"},
            "rules":[{"masks":"0.0.0.0/0","action":"allow","client_chain":"missing"}]}]),
            "Unknown client group: missing",
        ),
        (
            json!([
                {"clash_api_address":"127.0.0.1:0","secret":"test"},
                {"rule_group":"unused","rules":[{"masks":"0.0.0.0/0","action":"allow","client_chain":invalid_client}]},
                {"address":"127.0.0.1:0","protocol":{"type":"socks"},"dns":{"fake_ip":true},
                 "rules":[{"masks":"0.0.0.0/0","action":"allow","override_address":"198.18.0.2:443"}]}
            ]),
            "rule override overlaps",
        ),
    ] {
        let error = compile(configs).err().unwrap();
        assert!(
            error.to_string().contains(expected),
            "{error}, expected {expected}"
        );
    }
    let mut groups = vec![json!({"client_group":"g0","client_chains":invalid_client})];
    for index in 1..15 {
        let previous = format!("g{}", index - 1);
        groups.push(json!({"client_group":format!("g{index}"),
            "client_chains":[{"chain":[previous]},{"chain":[previous]}]}));
    }
    let error = compile(json!(groups)).err().unwrap();
    assert!(error.to_string().contains("16384 nodes"), "{error}");
}










