use aerobox_config::{convert_outbound, normalize_value};
use serde_json::{Value, json};

#[test]
fn network_policy_follows_route_order_without_restricting_dns_or_probes() {
    for (allowed, blocked) in [("udp", "tcp"), ("tcp", "udp")] {
        let node = json!({"type":"socks","tag":"proxy","server":"127.0.0.1","server_port":1080,"network":allowed});
        let document = json!({
            "outbounds":[node, {"type":"direct","tag":"direct"}],
            "dns":{"servers":[{"type":"udp","tag":"dns-remote","server":"203.0.113.53","detour":"proxy"}],"final":"dns-remote"},
            "inbounds":[{"type":"socks","listen_port":2080}],
            "route":{"final":"proxy","rules":[
                {"domain_suffix":["local.test"],"outbound":"direct"},
                {"domain_suffix":["proxy.test"],"outbound":"proxy"}
            ]}
        });
        let output = normalize_value(document.clone(), None).unwrap();
        let entries = output.as_array().unwrap();
        let inbound = entries
            .iter()
            .find(|v| v["protocol"]["type"] == "socks")
            .unwrap();
        let rules = inbound["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 5);
        assert_eq!(rules[0]["client_chain"], "__aerobox_direct");
        for (denial, route) in [(1, 2), (3, 4)] {
            assert_eq!(rules[denial]["action"], "block");
            assert_eq!(
                rules[denial]["conditions"]["all"][0],
                rules[route]["conditions"]
            );
            assert_eq!(
                rules[denial]["conditions"]["all"][1],
                json!({"network":[blocked]})
            );
            assert_eq!(rules[route]["client_chain"], "proxy");
        }
        let dns = entries
            .iter()
            .find(|v| v["dns_group"] == "dns-remote")
            .unwrap();
        assert_eq!(dns["dns_servers"][0]["client_chain"], "proxy");
        let mut probe = document;
        probe["inbounds"] = json!([]);
        assert!(normalize_value(probe, None).is_ok());
    }
}

#[test]
fn node_policy_preserves_protocol_capabilities_and_rejects_unknown_networks() {
    for network in ["tcp", "udp", "tcp,udp", "udp,tcp", ""] {
        let node = json!({"type":"vmess","tag":"proxy","server":"127.0.0.1","server_port":443,
            "uuid":"550e8400-e29b-41d4-a716-446655440000","network":network});
        let output = convert_outbound(node, "$.node").unwrap();
        assert_eq!(
            output["client_chains"][0]["chain"][0]["protocol"].get("udp_enabled"),
            None
        );
    }
    let invalid = json!({"type":"socks","tag":"proxy","server":"127.0.0.1","server_port":1080,"network":"udpp"});
    assert_eq!(
        convert_outbound(invalid, "$.node").unwrap_err().path,
        "$.node.network"
    );
}

#[test]
fn public_key_pins_are_the_trust_anchor_and_conflict_with_roots() {
    let mut node = json!({"type":"http","tag":"proxy","server":"127.0.0.1","server_port":443,
        "tls":{"enabled":true,"certificate_public_key_sha256":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}});
    let converted = convert_outbound(node.clone(), "$.node").unwrap();
    let tls = &converted["client_chains"][0]["chain"][0]["protocol"];
    assert_eq!(tls["verify"], false);
    assert_eq!(
        tls["options"]["certificate_public_key_sha256"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    for field in ["certificate", "certificate_path"] {
        let mut conflict = node.clone();
        conflict["tls"][field] = "certificate-or-path".into();
        assert!(convert_outbound(conflict, "$.node").is_err());
    }
    node["tls"]["certificate_public_key_sha256"] = Value::Array(vec![]);
    let converted = convert_outbound(node, "$.node").unwrap();
    assert_eq!(
        converted["client_chains"][0]["chain"][0]["protocol"]["verify"],
        true
    );
}
