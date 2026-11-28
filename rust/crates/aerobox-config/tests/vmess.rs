use aerobox_config::convert_outbound;
use serde_json::json;

#[test]
fn vmess_legacy_fields_are_preserved_without_changing_cipher() {
    for cipher in [
        "aes-128-cfb",
        "none",
        "zero",
        "aes-128-gcm",
        "chacha20-poly1305",
    ] {
        for alter_id in [0, 1, 64, 65535] {
            let converted=convert_outbound(json!({"type":"vmess","tag":"legacy","server":"127.0.0.1","server_port":443,"uuid":"d9ad4eab-f118-492b-a99b-e0e27332b4b2","security":cipher,"alter_id":alter_id}),"$.outbounds[0]").unwrap();
            let protocol = &converted["client_chains"][0]["chain"][0]["protocol"];
            assert_eq!(protocol["alter_id"], alter_id);
            assert_eq!(protocol["cipher"], cipher);
        }
    }
    for invalid in [json!(-1), json!(65536), json!(1.5), json!("64")] {
        let error=convert_outbound(json!({"type":"vmess","tag":"legacy","server":"127.0.0.1","server_port":443,"uuid":"d9ad4eab-f118-492b-a99b-e0e27332b4b2","alter_id":invalid}),"$.outbounds[0]").unwrap_err();
        assert_eq!(error.path, "$.outbounds[0].alter_id");
    }
}
