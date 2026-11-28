use serde_json::json;

#[test]
fn android_single_curve_matches_array_in_public_runtime_check() {
    let runtime = aerobox::AndroidRuntime::new().unwrap();
    for kind in ["vless", "trojan", "hysteria2", "tuic"] {
        let mut proxy = json!({"type":kind,"tag":"proxy","server":"127.0.0.1","server_port":443,
            "tls":{"enabled":true,"server_name":"proxy.test"}});
        if matches!(kind, "vless" | "tuic") {
            proxy["uuid"] = "01010101-0101-4101-8101-010101010101".into();
        }
        if kind != "vless" {
            proxy["password"] = "test-only".into();
        }
        let mut doc = json!({"outbounds":[proxy],"route":{"final":"proxy"},
            "inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":2080}]});
        for group in ["X25519", "SecP256r1", "SecP384r1", "SecP521r1"] {
            let mut native_forms = Vec::new();
            for value in [json!(group), json!([group])] {
                doc["outbounds"][0]["tls"]["curve_preferences"] = value;
                let source = doc.to_string();
                native_forms.push(aerobox_config::normalize_json(&source, None).unwrap());
                runtime
                    .check(&source)
                    .unwrap_or_else(|error| panic!("{kind}/{group}: {error}"));
                assert!(!runtime.is_running());
            }
            assert_eq!(native_forms[0], native_forms[1]);
        }
        for invalid in [
            json!(""),
            json!("invalid"),
            json!([]),
            json!(["X25519", "X25519"]),
            json!(42),
        ] {
            doc["outbounds"][0]["tls"]["curve_preferences"] = invalid;
            assert!(runtime.check(&doc.to_string()).is_err(), "{kind}");
            assert!(!runtime.is_running());
        }
    }
}
