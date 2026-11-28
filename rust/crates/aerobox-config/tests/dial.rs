use aerobox_config::convert_outbound;
use serde_json::json;

#[test]
fn dial_options_preserve_values_for_runtime_validation_and_execution() {
    let converted = convert_outbound(json!({
        "type":"socks","tag":"proxy","server":"127.0.0.1","server_port":1080,
        "connect_timeout":"1m2.5s","tcp_keep_alive":"300s","tcp_keep_alive_interval":"75000ms",
        "disable_tcp_keep_alive":false,"tcp_fast_open":true,"tcp_multi_path":true,"udp_fragment":false
    }),"$.outbounds[0]").unwrap();
    assert_eq!(
        converted["client_chains"][0]["chain"][0]["dial_options"],
        json!({
            "connect_timeout":"1m2.5s","tcp_keep_alive":"300s","tcp_keep_alive_interval":"75000ms",
            "disable_tcp_keep_alive":false,"tcp_fast_open":true,"tcp_multi_path":true,"udp_fragment":false
        })
    );
}

#[test]
fn tcp_options_are_rejected_when_the_transport_cannot_apply_them() {
    for key in ["tcp_fast_open", "tcp_multi_path", "disable_tcp_keep_alive"] {
        let mut value = json!({"type":"tuic","tag":"proxy","server":"127.0.0.1","server_port":443,
            "uuid":"550e8400-e29b-41d4-a716-446655440000","password":"test","tls":{"enabled":true}});
        value[key] = true.into();
        let error = convert_outbound(value, "$.outbounds[0]").unwrap_err();
        assert_eq!(error.path, format!("$.outbounds[0].{key}"));
    }
    let error = convert_outbound(
        json!({"type":"anytls","tag":"proxy","server":"127.0.0.1","server_port":443,
        "password":"test","tls":{"enabled":true},"tcp_fast_open":true}),
        "$.outbounds[0]",
    )
    .unwrap_err();
    assert_eq!(error.path, "$.outbounds[0].tcp_fast_open");
}

#[test]
fn direct_preserves_its_fragmentation_default_and_explicit_override() {
    for (configured, expected) in [(None, true), (Some(false), false), (Some(true), true)] {
        let mut value = json!({"type":"direct","tag":"plain"});
        if let Some(value_configured) = configured {
            value["udp_fragment"] = value_configured.into();
        }
        let converted = convert_outbound(value, "$.outbounds[0]").unwrap();
        assert_eq!(
            converted["client_chains"][0]["chain"][0]["dial_options"]["udp_fragment"],
            json!(expected)
        );
    }
    let converted = convert_outbound(
        json!({
            "type":"socks","tag":"proxy","server":"127.0.0.1","server_port":1080
        }),
        "$.outbounds[0]",
    )
    .unwrap();
    assert!(
        converted["client_chains"][0]["chain"][0]
            .get("dial_options")
            .is_none()
    );
}
