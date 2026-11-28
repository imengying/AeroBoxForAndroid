use aerobox_config::convert_outbound;
use serde_json::{Value, json};

fn node(reality: bool, vision: bool) -> Value {
    let mut node = json!({"type":"vless","tag":"proxy","server":"127.0.0.1","server_port":9,
        "uuid":"01010101-0101-4101-8101-010101010101",
        "tls":{"enabled":true,"server_name":"cover.test","utls":{"enabled":true,"fingerprint":"randomized"}}});
    if reality {
        node["tls"]["reality"] = json!({"enabled":true,"public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","short_id":"0101010101010101"});
    }
    if vision {
        node["flow"] = "xtls-rprx-vision".into();
    }
    node
}
fn protocol(converted: &Value) -> &Value {
    &converted["client_chains"][0]["chain"][0]["protocol"]
}

#[test]
fn randomized_conversion_preserves_one_plan_across_stream_reality_and_vision() {
    let original = aerobox_fingerprint::randomized::process_plan().unwrap();
    for _ in 0..3 {
        for reality in [false, true] {
            for vision in [false, true] {
                let result = convert_outbound(node(reality, vision), "$.node");
                match original.for_stream(reality) {
                    Err(expected) => assert!(
                        result
                            .unwrap_err()
                            .to_string()
                            .contains(&expected.to_string())
                    ),
                    Ok(plan) if vision && plan.maximum() != 0x0304 => assert!(
                        result
                            .unwrap_err()
                            .to_string()
                            .contains("no TLS1.3 for Vision")
                    ),
                    Ok(_) => {
                        let converted = result.unwrap();
                        let protocol = protocol(&converted);
                        assert_eq!(
                            if reality {
                                &protocol["fingerprint"]
                            } else {
                                &protocol["options"]["fingerprint"]
                            },
                            "randomized"
                        );
                        assert_eq!(protocol["vision"].as_bool().unwrap_or(false), vision);
                    }
                }
                assert!(std::ptr::eq(
                    original,
                    aerobox_fingerprint::randomized::process_plan().unwrap()
                ));
            }
        }
    }
}

#[test]
fn randomized_explicit_alpn_requires_its_original_extension_and_failures_do_not_reseed() {
    let original = aerobox_fingerprint::randomized::process_plan().unwrap();
    for reality in [false, true] {
        let mut input = node(reality, false);
        input["tls"]["alpn"] = json!(["http/1.1"]);
        let first = convert_outbound(input.clone(), "$.node");
        for _ in 0..3 {
            let result = convert_outbound(input.clone(), "$.node");
            match original.for_stream(reality) {
                Err(expected) => assert!(
                    result
                        .unwrap_err()
                        .to_string()
                        .contains(&expected.to_string())
                ),
                Ok(plan) if !plan.extensions().contains(&16) => assert!(
                    result
                        .unwrap_err()
                        .to_string()
                        .contains("did not select ALPN")
                ),
                Ok(_) => assert_eq!(
                    protocol(&result.unwrap())["alpn_protocols"],
                    json!(["http/1.1"])
                ),
            }
            assert!(std::ptr::eq(
                original,
                aerobox_fingerprint::randomized::process_plan().unwrap()
            ));
        }
        if let Err(expected) = first {
            assert_eq!(
                convert_outbound(input, "$.node").unwrap_err().to_string(),
                expected.to_string()
            );
        }
    }
    let mut ech = node(false, false);
    ech["tls"]["ech"] = json!({"enabled":true,"query_server_name":"cover.test"});
    let error = convert_outbound(ech, "$.node").unwrap_err().to_string();
    if let Err(expected) = original.for_stream(false) {
        assert!(error.contains(&expected.to_string()));
    } else {
        assert!(error.contains("cannot negotiate ECH"));
    }
    assert!(std::ptr::eq(
        original,
        aerobox_fingerprint::randomized::process_plan().unwrap()
    ));
}

#[test]
fn randomized_disabled_is_ordinary_and_quic_naive_are_rejected() {
    let mut disabled = node(false, false);
    disabled["tls"]["utls"]["enabled"] = false.into();
    let converted = convert_outbound(disabled, "$.node").unwrap();
    assert!(protocol(&converted)["options"].get("fingerprint").is_none());
    for kind in ["naive", "hysteria2", "tuic"] {
        let mut input = node(false, false);
        input["type"] = kind.into();
        input["password"] = "test-only".into();
        if kind != "tuic" {
            input.as_object_mut().unwrap().remove("uuid");
        }
        assert!(
            convert_outbound(input, "$.node")
                .unwrap_err()
                .to_string()
                .contains(if kind == "naive" { "Naive" } else { "QUIC" })
        );
    }
    // Existing random remains the independent five-template resolver.
    let fixed = aerobox_fingerprint::random_profile().unwrap();
    let mut input = node(false, false);
    input["tls"]["utls"]["fingerprint"] = "random".into();
    assert_eq!(
        protocol(&convert_outbound(input, "$.node").unwrap())["options"]["fingerprint"],
        fixed.as_str()
    );
}
