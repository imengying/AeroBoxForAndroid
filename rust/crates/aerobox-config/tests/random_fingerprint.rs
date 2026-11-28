use aerobox_config::convert_outbound;
use serde_json::{Value, json};

fn node() -> Value {
    json!({"type":"vless","tag":"proxy","server":"127.0.0.1","server_port":443,
        "uuid":"01010101-0101-4101-8101-010101010101",
        "tls":{"enabled":true,"server_name":"cover.test","utls":{"enabled":true,"fingerprint":"random"}}})
}

#[test]
fn random_conversion_shares_process_choice_across_tls_reality_vision_and_errors() {
    let expected = aerobox_fingerprint::random_profile().unwrap();
    for _ in 0..3 {
        for reality in [false, true] {
            for vision in [false, true] {
                let mut input = node();
                input["tls"]["alpn"] = json!(["h2"]);
                input["tls"]["record_fragment"] = true.into();
                if reality {
                    input["tls"]["reality"] = json!({"enabled":true,"public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","short_id":"0101010101010101"});
                }
                if vision {
                    input["flow"] = "xtls-rprx-vision".into();
                }
                let converted = convert_outbound(input, "$.node").unwrap();
                let protocol = &converted["client_chains"][0]["chain"][0]["protocol"];
                assert_eq!(
                    if reality {
                        &protocol["fingerprint"]
                    } else {
                        &protocol["options"]["fingerprint"]
                    },
                    expected.as_str()
                );
                assert_eq!(protocol["alpn_protocols"], json!(["h2"]));
                assert_eq!(protocol["fragmentation"]["record_fragment"], true);
                assert_eq!(protocol["vision"].as_bool().unwrap_or(false), vision);
            }
        }
        let mut invalid = node();
        invalid["tls"]["utls"]["typo"] = true.into();
        assert!(convert_outbound(invalid, "$.node").is_err());
        assert_eq!(aerobox_fingerprint::random_profile().unwrap(), expected);
    }
}

#[test]
fn random_ech_uses_the_selected_profile_and_never_reselects_on_conflict() {
    let expected = aerobox_fingerprint::random_profile().unwrap();
    let mut input = node();
    input["tls"]["ech"] = json!({"enabled":true,"query_server_name":"cover.test"});
    for _ in 0..3 {
        let result = convert_outbound(input.clone(), "$.node");
        if expected == aerobox_fingerprint::Profile::Chrome133 {
            let converted = result.unwrap();
            assert_eq!(
                converted["client_chains"][0]["chain"][0]["protocol"]["options"]["fingerprint"],
                "chrome133"
            );
        } else {
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("cannot negotiate ECH")
            );
        }
        assert_eq!(aerobox_fingerprint::random_profile().unwrap(), expected);
    }
    input["tls"]["reality"] = json!({"enabled":true,"public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","short_id":"0101010101010101"});
    assert!(
        convert_outbound(input, "$.node")
            .unwrap_err()
            .to_string()
            .contains("ECH cannot be combined with REALITY")
    );
}

#[test]
fn disabled_random_keeps_default_tls_and_unsupported_profiles_stay_rejected() {
    let mut input = node();
    input["tls"]["utls"]["enabled"] = false.into();
    let converted = convert_outbound(input, "$").unwrap();
    assert!(
        converted["client_chains"][0]["chain"][0]["protocol"]["options"]
            .get("fingerprint")
            .is_none()
    );
    for alias in ["randomized_unknown", "360_11"] {
        let mut input = node();
        input["tls"]["utls"]["fingerprint"] = alias.into();
        assert!(
            convert_outbound(input, "$")
                .unwrap_err()
                .to_string()
                .contains("not implemented")
        );
    }
    for kind in ["naive", "hysteria2", "tuic"] {
        let mut input = node();
        input["type"] = kind.into();
        input["password"] = "test-only".into();
        if kind != "tuic" {
            input.as_object_mut().unwrap().remove("uuid");
        }
        assert!(
            convert_outbound(input, "$")
                .unwrap_err()
                .to_string()
                .contains(if kind == "naive" { "Naive" } else { "QUIC" })
        );
    }
}
