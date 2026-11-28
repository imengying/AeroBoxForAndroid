use aerobox_config::{convert_outbound, normalize_json};
use serde_json::{Value, json};

fn node() -> Value {
    json!({"type":"socks","tag":"proxy","server":"127.0.0.1","server_port":1080})
}

#[test]
fn network_policy_preserves_strategy_types_and_go_duration() {
    for strategy in ["default", "hybrid", "fallback"] {
        let mut value = node();
        value["network_strategy"] = strategy.into();
        value["network_type"] = "wifi".into();
        value["fallback_network_type"] = json!(["cellular", "ethernet", "cellular"]);
        value["fallback_delay"] = "250.5ms".into();
        let converted = convert_outbound(value, "$.outbounds[0]").unwrap();
        assert_eq!(
            converted["client_chains"][0]["chain"][0]["dial_options"],
            json!({
                "network_strategy":strategy, "network_type":["wifi"],
                "fallback_network_type":["cellular", "ethernet"], "fallback_delay":"250.5ms"
            })
        );
    }
}

#[test]
fn malformed_policy_and_conflicting_socket_bindings_fail_with_paths() {
    for (key, value) in [
        ("network_strategy", json!("parallel")),
        ("network_strategy", json!(3)),
        ("network_type", json!(["wifi", 3])),
        ("network_type", json!("bluetooth")),
        ("fallback_network_type", json!(true)),
        ("fallback_delay", json!("")),
    ] {
        let mut source = node();
        source[key] = value;
        let error = convert_outbound(source, "$.outbounds[0]").unwrap_err();
        assert_eq!(error.path, format!("$.outbounds[0].{key}"));
    }
    for (key, value) in [
        ("bind_interface", json!("wlan0")),
        ("tcp_fast_open", json!(true)),
    ] {
        let mut source = node();
        source["network_strategy"] = "default".into();
        source[key] = value;
        assert!(convert_outbound(source, "$.outbounds[0]").is_err());
    }
}

#[test]
fn physical_policy_requires_interface_monitoring_in_android_documents() {
    let mut source = node();
    source["network_strategy"] = "fallback".into();
    let mut document = json!({"outbounds":[source],"inbounds":[],"route":{"final":"proxy"}});
    assert!(
        normalize_json(&document.to_string(), None)
            .unwrap_err()
            .message
            .contains("auto_detect_interface")
    );
    document["route"]["auto_detect_interface"] = true.into();
    let value: Value =
        serde_json::from_str(&normalize_json(&document.to_string(), None).unwrap()).unwrap();
    assert_eq!(
        value[0]["client_chains"][0]["chain"][0]["dial_options"]["network_strategy"],
        "fallback"
    );
}
