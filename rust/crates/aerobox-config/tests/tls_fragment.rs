use aerobox_config::convert_outbound;
use serde_json::{Value, json};

fn node(vision: bool, reality: bool) -> Value {
    let mut value = json!({
        "type":"vless","tag":"proxy","server":"127.0.0.1","server_port":443,
        "uuid":"01010101-0101-0101-0101-010101010101",
        "tls":{"enabled":true,"server_name":"fragment.example.com","fragment":true,
            "record_fragment":true,"fragment_fallback_delay":"35ms"}
    });
    if vision {
        value["flow"] = "xtls-rprx-vision".into();
    }
    if reality {
        value["tls"]["reality"] = json!({
            "enabled":true,"public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "short_id":"0101010101010101"
        });
    }
    value
}

#[test]
fn fragment_options_reach_ordinary_and_reality_tls_with_optional_vision() {
    for vision in [false, true] {
        for reality in [false, true] {
            let converted = convert_outbound(node(vision, reality), "$.outbounds[0]").unwrap();
            let protocol = &converted["client_chains"][0]["chain"][0]["protocol"];
            assert_eq!(protocol["type"], if reality { "reality" } else { "tls" });
            assert_eq!(protocol["vision"].as_bool().unwrap_or_default(), vision);
            assert_eq!(
                protocol["fragmentation"],
                json!({
                    "fragment":true,"record_fragment":true,"fragment_fallback_delay":"35ms"
                })
            );
        }
    }
}

#[test]
fn quic_and_malformed_fragment_options_are_not_silently_ignored() {
    for key in ["fragment", "record_fragment"] {
        let mut value = json!({
            "type":"hysteria2","tag":"proxy","server":"127.0.0.1","server_port":443,
            "password":"test-only","tls":{"enabled":true}
        });
        value["tls"][key] = true.into();
        let error = convert_outbound(value, "$.outbounds[0]").unwrap_err();
        assert_eq!(error.path, "$.outbounds[0].tls");
        assert!(error.to_string().contains("stream transport"));
    }
    for (key, value) in [
        ("fragment", json!("true")),
        ("record_fragment", json!(1)),
        ("fragment_fallback_delay", json!(15)),
        ("fragment_fallback_delay", json!("")),
    ] {
        let mut input = node(false, false);
        input["tls"][key] = value;
        assert!(convert_outbound(input, "$").is_err(), "{key}");
    }
}

#[test]
fn fragment_duration_syntax_is_preserved_for_native_validation() {
    for duration in ["+0s", "0.0s", "0h0m0s", "1m2.5s"] {
        let mut value = node(false, false);
        value["tls"]["fragment_fallback_delay"] = duration.into();
        let converted = convert_outbound(value, "$").unwrap();
        assert_eq!(
            converted["client_chains"][0]["chain"][0]["protocol"]["fragmentation"]["fragment_fallback_delay"],
            duration
        );
    }
}
