use aerobox_config::convert_outbound;
use serde_json::{Value, json};
fn node() -> Value {
    json!({"type":"trojan","tag":"p","server":"secret.test","server_port":443,"password":"test","tls":{"enabled":true,"ech":{"enabled":true,"query_server_name":"config.test"}}})
}
#[test]
fn dynamic_and_inline_ech_reach_tcp_and_quic_tls_policy() {
    for quic in [false, true] {
        let mut input = node();
        if quic {
            input["type"] = "hysteria2".into();
        }
        let out = convert_outbound(input, "$").unwrap();
        let node = &out["client_chains"][0]["chain"][0];
        let tls = if quic {
            &node["quic_settings"]
        } else {
            &node["protocol"]
        };
        assert_eq!(tls["options"]["ech"]["query_server_name"], "config.test");
    }
    let mut input = node();
    input["tls"]["ech"]["config"] = json!(["line1", "line2"]);
    input["tls"]["ech"]["config_path"] = "unused.pem".into();
    let out = convert_outbound(input, "$").unwrap();
    let ech = &out["client_chains"][0]["chain"][0]["protocol"]["options"]["ech"];
    assert_eq!(ech["config"], "line1\nline2");
    assert!(ech.get("config_path").is_none());
    let mut input = node();
    input["tls"]["ech"]["config_path"] = "ech.pem".into();
    assert_eq!(
        convert_outbound(input, "$").unwrap()["client_chains"][0]["chain"][0]["protocol"]["options"]
            ["ech"]["config_path"],
        "ech.pem"
    );
}
#[test]
fn incompatible_and_unknown_ech_options_are_rejected() {
    for (key, value) in [
        ("config", json!(123)),
        ("config", json!([123])),
        ("query_server_name", json!(123)),
        ("pq_signature_schemes_enabled", json!(true)),
        ("dynamic_record_sizing_disabled", json!(true)),
        ("typo", json!(true)),
    ] {
        let mut input = node();
        input["tls"]["ech"][key] = value;
        assert!(convert_outbound(input, "$").is_err(), "{key}");
    }
    let mut input = node();
    input["tls"]["disable_sni"] = true.into();
    assert!(convert_outbound(input, "$").is_err());
}
