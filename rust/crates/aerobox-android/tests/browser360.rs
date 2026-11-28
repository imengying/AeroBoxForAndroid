use serde_json::{Value, json};

fn document(kind: &str) -> Value {
    let mut node = json!({"type":kind,"tag":"proxy","server":"127.0.0.1","server_port":9,
        "tls":{"enabled":true,"server_name":"localhost","utls":{"enabled":true,"fingerprint":"360"}}});
    match kind {
        "vmess" => {
            node["uuid"] = "test-only-name".into();
            node["security"] = "auto".into();
        }
        "vless" => node["uuid"] = "test-only-name".into(),
        "trojan" => node["password"] = "test-only".into(),
        _ => unreachable!(),
    }
    json!({"outbounds":[node],"route":{"final":"proxy"},
        "inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":2080}]})
}

#[test]
fn public_360_check_accepts_only_complete_compatible_stream_policy() {
    let runtime = aerobox::AndroidRuntime::new().unwrap();
    for kind in ["vmess", "vless", "trojan"] {
        let base = document(kind);
        for insecure in [false, true] {
            for fragment in [false, true] {
                let mut doc = base.clone();
                doc["outbounds"][0]["tls"]["insecure"] = insecure.into();
                doc["outbounds"][0]["tls"]["record_fragment"] = fragment.into();
                runtime
                    .check(&doc.to_string())
                    .unwrap_or_else(|e| panic!("{kind}/{insecure}/{fragment}: {e}"));
                assert!(!runtime.is_running());
            }
        }
        for mutation in [
            json!({"min_version":"1.2"}),
            json!({"max_version":"1.3"}),
            json!({"curve_preferences":["SecP521r1"]}),
            json!({"cipher_suites":["TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"]}),
            json!({"ech":{"enabled":true,"query_server_name":"localhost"}}),
            json!({"reality":{"enabled":true,"public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","short_id":"0101010101010101"}}),
        ] {
            let mut doc = base.clone();
            doc["outbounds"][0]["tls"]
                .as_object_mut()
                .unwrap()
                .extend(mutation.as_object().unwrap().clone());
            assert!(
                runtime.check(&doc.to_string()).is_err(),
                "{kind}/{mutation}"
            );
            assert!(!runtime.is_running());
        }
    }
    let mut vision = document("vless");
    vision["outbounds"][0]["flow"] = "xtls-rprx-vision".into();
    assert!(runtime.check(&vision.to_string()).is_err());
    let mut overridden = document("trojan");
    overridden["outbounds"][0]["tls"]["alpn"] = json!(["h2", "http/1.1"]);
    runtime.check(&overridden.to_string()).unwrap();
    let mut explicit = document("vless");
    explicit["outbounds"][0]["tls"]["min_version"] = "1.0".into();
    explicit["outbounds"][0]["tls"]["max_version"] = "1.2".into();
    runtime.check(&explicit.to_string()).unwrap();
    explicit["outbounds"][0]["tls"]["utls"]["enabled"] = false.into();
    assert!(runtime.check(&explicit.to_string()).is_err());
}
