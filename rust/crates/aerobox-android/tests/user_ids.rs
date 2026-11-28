use serde_json::json;

#[test]
fn android_outbound_user_ids_reach_vmess_vless_and_both_vision_factories() {
    let runtime = aerobox::AndroidRuntime::new().unwrap();
    for (kind, tls, reality, vision) in [
        ("vmess", false, false, false),
        ("vmess", true, false, false),
        ("vless", false, false, false),
        ("vless", true, false, false),
        ("vless", true, false, true),
        ("vless", true, true, true),
    ] {
        for id in [
            "",
            "test-user",
            "用户",
            "550e8400-e29b-11d4-a716-446655440000",
            "00000000-0000-0000-0000-000000000000",
        ] {
            let mut proxy =
                json!({"type":kind,"tag":"proxy","server":"127.0.0.1","server_port":443,"uuid":id});
            if tls {
                proxy["tls"] = json!({"enabled":true,"server_name":"proxy.test","utls":{"enabled":true,"fingerprint":"chrome"}});
            }
            if reality {
                proxy["tls"]["reality"] = json!({"enabled":true,"public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","short_id":"0101010101010101"});
            }
            if vision {
                proxy["flow"] = "xtls-rprx-vision".into();
            }
            let doc = json!({"outbounds":[proxy],"route":{"final":"proxy"},
                "inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":2080}]});
            runtime.check(&doc.to_string()).unwrap_or_else(|error| {
                panic!("{kind} tls={tls} reality={reality} vision={vision}: {error}")
            });
            assert!(!runtime.is_running());
        }
    }
}
