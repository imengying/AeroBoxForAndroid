use serde_json::json;

#[test]
fn android_fingerprint_maps_to_version_pinned_native_profile_and_rejects_invalid_carriers() {
    for kind in ["vmess", "vless", "trojan"] {
        let mut node = json!({"type":kind,"tag":"p","server":"localhost","server_port":443,
            "tls":{"enabled":true,"utls":{"enabled":true,"fingerprint":"android"}}});
        if kind == "trojan" {
            node["password"] = "test-only".into();
        } else {
            node["uuid"] = "test-only-name".into();
        }
        if kind == "vmess" {
            node["security"] = "auto".into();
        }
        let result = aerobox_config::convert_outbound(node.clone(), "$.node").unwrap();
        assert_eq!(
            result["client_chains"][0]["chain"][0]["protocol"]["options"]["fingerprint"],
            "android11"
        );
        node["tls"]["ech"] = json!({"enabled":true});
        assert!(aerobox_config::convert_outbound(node, "$.node").is_err());
    }
    for kind in ["naive", "hysteria2", "tuic"] {
        let mut node = json!({"type":kind,"tag":"p","server":"localhost","server_port":443,"password":"test-only",
            "tls":{"enabled":true,"utls":{"enabled":true,"fingerprint":"android"}}});
        if kind == "tuic" {
            node["uuid"] = "01010101-0101-4101-8101-010101010101".into();
        }
        assert!(aerobox_config::convert_outbound(node, "$.node").is_err());
    }
}
