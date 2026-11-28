use aerobox_config::convert_outbound;
use serde_json::{Value, json};

fn node(quic: bool, headers: Value) -> Value {
    json!({"type":"naive","tag":"proxy","server":"naive.example","server_port":443,
        "quic":quic,"extra_headers":headers,"tls":{"enabled":true,"server_name":"naive.example"}})
}
fn headers(quic: bool, value: Value) -> Value {
    let converted = convert_outbound(node(quic, value), "$.outbounds[2]").unwrap();
    let client = &converted["client_chains"][0]["chain"][0];
    if quic {
        client["protocol"]["settings"]["extra_headers"].clone()
    } else {
        client["protocol"]["protocol"]["settings"]["extra_headers"].clone()
    }
}

#[test]
fn naive_android_first_value_and_empty_array_match_fixed_sing_box() {
    for quic in [false, true] {
        assert_eq!(
            headers(
                quic,
                json!({"x-one":"one","x-many":["first","second"],"x-empty":[],"x-empty-value":[""]})
            ),
            json!({"x-one":"one","x-many":"first","x-empty-value":""})
        );
    }
}

#[test]
fn naive_android_invalid_later_values_are_not_hidden_by_first_value_selection() {
    for (input, suffix) in [
        (json!([]), ""),
        (json!({"x":23}), ".x"),
        (json!({"x":["first",23]}), ".x[1]"),
        (json!({"x":[null]}), ".x[0]"),
    ] {
        let error = convert_outbound(node(false, input), "$.outbounds[2]").unwrap_err();
        assert_eq!(error.path, format!("$.outbounds[2].extra_headers{suffix}"));
        assert!(error.message.starts_with("expected "));
    }
}
#[test]
fn naive_does_not_accept_tls_options_rejected_by_the_original_outbound() {
    for quic in [false, true] {
        for (key, value) in [
            ("insecure", json!(true)),
            ("disable_sni", json!(true)),
            ("min_version", json!("1.2")),
            ("max_version", json!("1.3")),
            ("cipher_suites", json!(["TLS_AES_128_GCM_SHA256"])),
            ("utls", json!({"enabled":true,"fingerprint":"chrome"})),
            ("alpn", json!(["h2"])),
            ("fragment", json!(true)),
            ("client_certificate", json!("certificate")),
        ] {
            let mut input = node(quic, json!({}));
            input["tls"][key] = value;
            assert!(convert_outbound(input, "$.outbounds[2]").is_err(), "{key}");
        }
    }
}
