use serde_json::{Value, json};
fn node(kind: &str) -> Value {
    let mut node = json!({"type":kind,"tag":"p","server":"localhost","server_port":443,
        "tls":{"enabled":true,"utls":{"enabled":true,"fingerprint":"360"}}});
    if kind == "trojan" {
        node["password"] = "test-only".into();
    } else {
        node["uuid"] = "test-only-name".into();
    }
    if kind == "vmess" {
        node["security"] = "auto".into();
    }
    node
}
#[test]
fn fixed_360_alias_maps_and_disabled_360_does_not_activate_legacy_tls() {
    for kind in ["vmess", "vless", "trojan"] {
        let base = node(kind);
        let native = aerobox_config::convert_outbound(base.clone(), "$.node").unwrap();
        assert_eq!(
            native["client_chains"][0]["chain"][0]["protocol"]["options"]["fingerprint"],
            "360_7_5"
        );
        let mut disabled = base.clone();
        disabled["tls"]["utls"]["enabled"] = false.into();
        let native = aerobox_config::convert_outbound(disabled, "$.node").unwrap();
        assert!(
            native["client_chains"][0]["chain"][0]["protocol"]["options"]["fingerprint"].is_null()
        );
        for field in ["ech", "reality"] {
            let mut rejected = base.clone();
            rejected["tls"][field] = if field == "ech" {
                json!({"enabled":true})
            } else {
                json!({"enabled":true,"public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","short_id":"0101010101010101"})
            };
            assert!(aerobox_config::convert_outbound(rejected, "$.node").is_err());
        }
    }
    let mut vision = node("vless");
    vision["flow"] = "xtls-rprx-vision".into();
    assert!(aerobox_config::convert_outbound(vision, "$.node").is_err());
    for kind in ["naive", "hysteria2", "tuic"] {
        let mut rejected = node(kind);
        rejected["password"] = "test-only".into();
        if kind == "tuic" {
            rejected["uuid"] = "01010101-0101-4101-8101-010101010101".into();
        }
        assert!(aerobox_config::convert_outbound(rejected, "$.node").is_err());
    }
}
