use aerobox_config::convert_outbound;
use serde_json::{Value, json};
fn node() -> Value {
    json!({"type":"tuic","tag":"proxy","server":"127.0.0.1","server_port":443,"uuid":"d9ad4eab-f118-492b-a99b-e0e27332b4b2","password":"test-only","tls":{"enabled":true,"server_name":"localhost"}})
}
#[test]
fn tuic_udp_over_stream_is_not_native_quic_packet_relay() {
    for relay in [None, Some("")] {
        let mut input = node();
        input["udp_over_stream"] = true.into();
        if let Some(value) = relay {
            input["udp_relay_mode"] = value.into();
        }
        let result = convert_outbound(input, "$.outbounds[0]").unwrap();
        let client = &result["client_chains"][0]["chain"][0];
        assert_eq!(client["transport"], "quic");
        assert_eq!(client["protocol"]["type"], "tuic");
        assert_eq!(client["protocol"]["udp_over_stream"], true);
        assert!(client["protocol"].get("udp_relay_mode").is_none());
    }
    for relay in ["native", "quic"] {
        let mut input = node();
        input["udp_over_stream"] = true.into();
        input["udp_relay_mode"] = relay.into();
        let failure = convert_outbound(input, "$.outbounds[0]").unwrap_err();
        assert_eq!(failure.path, "$.outbounds[0].udp_over_stream");
        assert!(failure.message.contains("conflicts"));
    }
}
#[test]
fn tuic_relay_defaults_and_explicit_modes_stay_separate() {
    for relay in [None, Some(""), Some("native"), Some("quic")] {
        let mut input = node();
        input["udp_over_stream"] = false.into();
        if let Some(value) = relay {
            input["udp_relay_mode"] = value.into();
        }
        let result = convert_outbound(input, "$[0]").unwrap();
        let protocol = &result["client_chains"][0]["chain"][0]["protocol"];
        assert!(protocol.get("udp_over_stream").is_none());
        if let Some(mode) = relay.filter(|s| !s.is_empty()) {
            assert_eq!(protocol["udp_relay_mode"], mode);
        } else {
            assert!(protocol.get("udp_relay_mode").is_none());
        }
    }
    let mut invalid = node();
    invalid["udp_over_stream"] = "true".into();
    assert!(
        convert_outbound(invalid, "$[0]")
            .unwrap_err()
            .path
            .ends_with(".udp_over_stream")
    );
    let mut invalid = node();
    invalid["udp_relay_mode"] = "unknown".into();
    assert!(
        convert_outbound(invalid, "$[0]")
            .unwrap_err()
            .path
            .ends_with(".udp_relay_mode")
    );
}

#[test]
fn tuic_early_handshake_is_independent_of_udp_encoding_and_strictly_boolean() {
    for early in [false, true] {
        for uot in [false, true] {
            let mut input = node();
            input["zero_rtt_handshake"] = early.into();
            input["udp_over_stream"] = uot.into();
            let result = convert_outbound(input, "$[0]").unwrap();
            let protocol = &result["client_chains"][0]["chain"][0]["protocol"];
            assert_eq!(protocol["zero_rtt_handshake"], early);
            assert_eq!(
                protocol
                    .get("udp_over_stream")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                uot
            );
        }
    }
    let mut invalid = node();
    invalid["zero_rtt_handshake"] = "true".into();
    assert!(
        convert_outbound(invalid, "$[0]")
            .unwrap_err()
            .path
            .ends_with(".zero_rtt_handshake")
    );
}
