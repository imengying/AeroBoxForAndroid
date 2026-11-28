use aerobox_config::convert_outbound;
use serde_json::{Value, json};

fn node(brutal: Value) -> Value {
    json!({"type":"trojan","tag":"proxy","server":"test.example","server_port":443,
        "password":"test-only","tls":{"enabled":true},
        "multiplex":{"enabled":true,"protocol":"smux","padding":true,"brutal":brutal}})
}

#[test]
fn brutal_preserves_full_rates_and_disabled_values() {
    for value in [
        json!({"enabled":true,"up_mbps":1,"down_mbps":1000}),
        json!({"enabled":false,"up_mbps":0,"down_mbps":0}),
    ] {
        let converted = convert_outbound(node(value.clone()), "$.node").unwrap();
        assert_eq!(
            converted["client_chains"][0]["chain"][0]["protocol"]["protocol"]["h2mux"]["brutal"],
            value
        );
    }
}

#[test]
fn brutal_rejects_missing_zero_negative_overflow_and_unknown_fields() {
    for (value, key) in [
        (json!({"enabled":true,"down_mbps":10}), "up_mbps"),
        (
            json!({"enabled":true,"up_mbps":0,"down_mbps":10}),
            "up_mbps",
        ),
        (
            json!({"enabled":true,"up_mbps":1,"down_mbps":-1}),
            "down_mbps",
        ),
        (
            json!({"enabled":true,"up_mbps":u64::MAX,"down_mbps":10}),
            "up_mbps",
        ),
        (
            json!({"enabled":true,"up_mbps":1,"down_mbps":1,"typo":true}),
            "typo",
        ),
    ] {
        let error = convert_outbound(node(value), "$.node").unwrap_err();
        assert_eq!(error.path, format!("$.node.multiplex.brutal.{key}"));
    }
}
