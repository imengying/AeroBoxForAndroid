//! Exercise host JNI/runtime boundaries without exposing a public seed override.
use serde_json::{Value, json};
use shoes::config::tls::{TlsClientFingerprint, TlsClientOptions};

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
fn document(node: Value) -> Value {
    // check() compiles the rule's outbound but does not bind this listener.
    json!({"outbounds":[node],"route":{"final":"proxy"},
        "inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":2080}]})
}
fn converted(node: Value) -> Result<Value, String> {
    aerobox_config::convert_outbound(node, "$.node").map_err(|e| e.to_string())
}

#[test]
fn host_randomized_check_matches_conversion_and_native_token_without_retry() {
    let runtime = aerobox::AndroidRuntime::new().unwrap();
    for reality in [false, true] {
        for vision in [false, true] {
            let input = node(reality, vision);
            let expected = converted(input.clone());
            for _ in 0..3 {
                let options: TlsClientOptions =
                    serde_json::from_value(json!({"fingerprint":"randomized"})).unwrap();
                assert_eq!(options.fingerprint, Some(TlsClientFingerprint::Randomized));
                assert_eq!(
                    serde_json::to_value(options).unwrap()["fingerprint"],
                    "randomized"
                );
                assert_eq!(converted(input.clone()), expected);
                let check = runtime.check(&document(input.clone()).to_string());
                match &expected {
                    Ok(value) => {
                        let protocol = &value["client_chains"][0]["chain"][0]["protocol"];
                        assert_eq!(
                            if reality {
                                &protocol["fingerprint"]
                            } else {
                                &protocol["options"]["fingerprint"]
                            },
                            "randomized"
                        );
                        check.unwrap();
                    }
                    Err(_) => assert!(check.unwrap_err().to_string().contains("randomized")),
                }
                assert!(!runtime.is_running());
            }
        }
    }
    for reality in [false, true] {
        let mut explicit = node(reality, false);
        explicit["tls"]["alpn"] = json!(["http/1.1"]);
        let expected = converted(explicit.clone());
        for _ in 0..2 {
            assert_eq!(converted(explicit.clone()), expected);
            assert_eq!(
                runtime
                    .check(&document(explicit.clone()).to_string())
                    .is_ok(),
                expected.is_ok()
            );
        }
    }
    let mut disabled = node(false, false);
    disabled["tls"]["utls"]["enabled"] = false.into();
    let disabled = document(disabled);
    assert!(
        !aerobox_config::normalize_json(&disabled.to_string(), None)
            .unwrap()
            .contains("fingerprint")
    );
    runtime.check(&disabled.to_string()).unwrap();
    let mut ech = node(false, false);
    ech["tls"]["ech"] = json!({"enabled":true,"query_server_name":"cover.test"});
    assert!(runtime.check(&document(ech).to_string()).is_err());
}

#[test]
fn host_randomized_start_stop_retains_success_or_the_fixed_structure_error() {
    // Include REALITY too: removing a missing hybrid share can make that path
    // valid even when the same process's ordinary TLS plan must be rejected.
    for reality in [false, true] {
        let source = node(reality, false);
        let expected = converted(source.clone());
        for _ in 0..2 {
            let runtime = aerobox::AndroidRuntime::new().unwrap();
            if expected.is_err() {
                let input = document(source.clone()).to_string();
                let first = runtime.check(&input).unwrap_err().to_string();
                assert_eq!(runtime.check(&input).unwrap_err().to_string(), first);
                assert!(runtime.start(&input, None, None).is_err());
                assert!(!runtime.is_running());
            } else {
                let mut input = document(source.clone());
                let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                input["inbounds"][0]["listen_port"] = listener.local_addr().unwrap().port().into();
                drop(listener);
                runtime.start(&input.to_string(), None, None).unwrap();
                assert!(runtime.is_running());
                assert_eq!(converted(source.clone()), expected);
                runtime.stop().unwrap();
                assert!(!runtime.is_running());
            }
            assert_eq!(converted(source.clone()), expected);
        }
    }
}
