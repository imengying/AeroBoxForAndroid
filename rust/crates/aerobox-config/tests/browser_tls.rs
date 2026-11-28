use aerobox_config::convert_outbound;
use serde_json::{Value, json};
fn node() -> Value {
    json!({"type":"vless","tag":"proxy","server":"127.0.0.1","server_port":443,"uuid":"01010101-0101-0101-0101-010101010101","tls":{"enabled":true,"server_name":"cover.test"}})
}
#[test]
fn browser_aliases_reach_tls_reality_and_vision_without_losing_other_options() {
    for (alias, expected) in [
        ("", "chrome133"),
        ("chrome", "chrome133"),
        ("chrome_psk", "chrome133"),
        ("chrome_psk_shuffle", "chrome133"),
        ("chrome_padding_psk_shuffle", "chrome133"),
        ("chrome_pq", "chrome133"),
        ("chrome_pq_psk", "chrome133"),
        ("edge", "edge85"),
        ("qq", "qq11_1"),
        ("safari", "safari16"),
        ("ios", "ios14"),
        ("firefox", "firefox120"),
    ] {
        for reality in [false, true] {
            for vision in [false, true] {
                let mut input = node();
                input["tls"]["utls"] = json!({"enabled":true,"fingerprint":alias});
                input["tls"]["alpn"] = json!(["h2"]);
                input["tls"]["record_fragment"] = true.into();
                if vision {
                    input["flow"] = "xtls-rprx-vision".into();
                }
                if reality {
                    input["tls"]["reality"] = json!({"enabled":true,"public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","short_id":"0101010101010101"});
                }
                let out = convert_outbound(input, "$.node").unwrap();
                let p = &out["client_chains"][0]["chain"][0]["protocol"];
                assert_eq!(p["type"], if reality { "reality" } else { "tls" });
                assert_eq!(
                    if reality {
                        &p["fingerprint"]
                    } else {
                        &p["options"]["fingerprint"]
                    },
                    expected
                );
                assert_eq!(p["alpn_protocols"], json!(["h2"]));
                assert_eq!(p["fragmentation"]["record_fragment"], true);
                assert_eq!(p["vision"].as_bool().unwrap_or_default(), vision);
                assert!(!p["protocol"]["vision"].as_bool().unwrap_or_default());
            }
        }
    }
}
#[test]
fn absent_or_disabled_profile_does_not_enable_browser_tls() {
    for utls in [
        None,
        Some(json!({"enabled":false,"fingerprint":"chrome"})),
        Some(json!({"fingerprint":"firefox"})),
    ] {
        let mut input = node();
        if let Some(utls) = utls {
            input["tls"]["utls"] = utls;
        }
        let out = convert_outbound(input, "$").unwrap();
        assert!(
            out["client_chains"][0]["chain"][0]["protocol"]["options"]
                .get("fingerprint")
                .is_none()
        );
    }
}
#[test]
fn unsupported_profiles_quic_naive_and_malformed_fields_are_explicit_errors() {
    for value in [
        json!({"enabled":true,"fingerprint":"unimplemented"}),
        json!({"enabled":true,"fingerprint":"randomized_unknown"}),
        json!({"enabled":true,"fingerprint":3}),
        json!({"enabled":true,"fingerprint":"chrome","typo":true}),
    ] {
        let mut input = node();
        input["tls"]["utls"] = value;
        let error = convert_outbound(input, "$.node").unwrap_err();
        assert!(error.path.starts_with("$.node.tls.utls"));
    }
    for kind in ["naive", "hysteria2", "tuic"] {
        let mut input = node();
        input["type"] = kind.into();
        input["password"] = "test-only".into();
        if kind != "tuic" {
            input.as_object_mut().unwrap().remove("uuid");
        }
        input["tls"]["utls"] = json!({"enabled":true,"fingerprint":"chrome"});
        let error = convert_outbound(input, "$.node").unwrap_err();
        assert!(error.path.starts_with("$.node.tls.utls"), "{error}");
        assert!(
            error.to_string().contains(if kind == "naive" {
                "Naive"
            } else {
                "Chrome133"
            }),
            "{error}"
        );
    }
}

#[test]
fn fixed_profiles_reject_non_stream_transports_and_ech_without_silent_substitution() {
    for alias in ["edge", "qq", "safari", "ios", "firefox"] {
        let mut input = node();
        input["tls"]["utls"] = json!({"enabled":true,"fingerprint":alias});
        input["tls"]["ech"] = json!({"enabled":true,"query_server_name":"cover.test"});
        assert!(convert_outbound(input, "$.node").is_err());
        for kind in ["naive", "hysteria2", "tuic"] {
            let mut input = node();
            input["type"] = kind.into();
            input["password"] = "test-only".into();
            if kind != "tuic" {
                input.as_object_mut().unwrap().remove("uuid");
            }
            input["tls"]["utls"] = json!({"enabled":true,"fingerprint":alias});
            assert!(convert_outbound(input, "$.node").is_err());
        }
    }
}
