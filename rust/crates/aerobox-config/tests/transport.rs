use aerobox_config::convert_outbound;
use serde_json::{Value, json};

fn converted(transport: Value) -> Value {
    convert_outbound(
        json!({
            "type": "vmess", "tag": "proxy", "server": "127.0.0.1", "server_port": 443,
            "uuid": "00112233-4455-6677-8899-aabbccddeeff", "tls": {"enabled": true},
            "transport": transport
        }),
        "$.node",
    )
    .unwrap()["client_chains"][0]["chain"][0]["protocol"]["protocol"]
        .clone()
}

#[test]
fn android_http_and_grpc_keepalive_options_reach_the_transport() {
    for kind in ["grpc", "http"] {
        let protocol =
            converted(json!({"type": kind, "idle_timeout": "1m30.5s", "ping_timeout": "250ms"}));
        assert_eq!(protocol["idle_timeout"], "1m30.5s");
        assert_eq!(protocol["ping_timeout"], "250ms");
        assert_eq!(
            protocol["kind"],
            if kind == "grpc" { "grpc" } else { "http2" }
        );
    }
}

#[test]
fn grpc_lite_accepts_the_original_apps_unused_permit_flag() {
    let plain = converted(json!({"type":"grpc", "service_name":"GunService"}));
    for permit in [false, true] {
        assert_eq!(
            converted(
                json!({"type":"grpc", "service_name":"GunService", "permit_without_stream":permit})
            ),
            plain
        );
    }
}

#[test]
fn http_host_candidates_are_preserved_for_each_connection() {
    for hosts in [
        json!("one.example"),
        json!(["one.example", "two.example"]),
        json!([]),
    ] {
        let protocol = converted(json!({"type":"http", "host":hosts}));
        assert_eq!(protocol["host"], hosts);
    }
}

#[test]
fn repeated_transport_headers_retain_values_for_http_and_upgrade() {
    for kind in ["http", "httpupgrade"] {
        let headers = json!({"X-Route":["one", "two"], "X-Label":"fixture"});
        let protocol = converted(json!({"type":kind, "headers":headers}));
        assert_eq!(protocol["headers"], headers);
    }
}

#[test]
fn hysteria_debug_flag_does_not_reject_an_existing_android_node() {
    let node = json!({"type":"hysteria2", "tag":"proxy", "server":"127.0.0.1", "server_port":443,
        "password":"test-only", "up_mbps":100, "down_mbps":200, "tls":{"enabled":true}});
    let plain = convert_outbound(node.clone(), "$.node").unwrap();
    for enabled in [false, true] {
        let mut value = node.clone();
        value["brutal_debug"] = enabled.into();
        assert_eq!(convert_outbound(value, "$.node").unwrap(), plain);
    }
    let mut invalid = node;
    invalid["brutal_debug"] = "yes".into();
    assert!(
        convert_outbound(invalid, "$.node")
            .unwrap_err()
            .path
            .ends_with(".brutal_debug")
    );
}

#[test]
fn websocket_repeated_headers_reach_the_runtime() {
    let headers = json!({"Host":"edge.example", "X-Route":["one", "two"]});
    let protocol = converted(
        json!({"type":"ws", "path":"/tunnel", "headers":headers, "max_early_data":1024, "early_data_header_name":"Sec-WebSocket-Protocol"}),
    );
    assert_eq!(protocol["matching_headers"], headers);
    assert_eq!(protocol["max_early_data"], 1024);
}
