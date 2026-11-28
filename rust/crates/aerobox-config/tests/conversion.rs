use aerobox_config::{convert_outbound, normalize_json};
use serde_json::{Value,json};
const UUID:&str="00112233-4455-6677-8899-aabbccddeeff";
fn node(kind:&str)->Value {
    let mut node=json!({"type":kind,"tag":"proxy","server":"127.0.0.1","server_port":443});
    match kind {
        "shadowsocks"=>{ node["method"]="aes-128-gcm".into();node["password"]="test-only".into(); },
        "vmess"|"vless"=>node["uuid"]=UUID.into(),
        "trojan"|"anytls"|"hysteria2"|"tuic"=>node["password"]="test-only".into(),
        _=>{}
    }
    if kind=="tuic" {node["uuid"]=UUID.into();}
    if ["trojan","anytls","hysteria2","tuic","naive"].contains(&kind) {node["tls"]=json!({"enabled":true,"server_name":"test.example"});}
    node
}
#[test]
fn all_android_protocol_families_convert() {
    for kind in ["shadowsocks","vmess","vless","trojan","anytls","hysteria2","tuic","naive","socks","http"] {
        let converted=convert_outbound(node(kind),"$.node").unwrap();
        assert_eq!(converted["client_group"],"proxy");
    }
    let mut ss2022=node("shadowsocks");ss2022["method"]="2022-blake3-aes-128-gcm".into();ss2022["password"]="AAAAAAAAAAAAAAAAAAAAAA==".into();
    assert!(convert_outbound(ss2022,"$.node").is_ok());
}
#[test]
fn security_and_transport_options_cannot_be_silently_ignored() {
    for change in [json!({"tls":{"enabled":true,"insecure":false,"unrecognized_security_flag":true}}),json!({"alter_id":-1}),json!({"transport":{"type":"grpc","typo":true}}),json!({"multiplex":{"enabled":true,"typo":true}})] {
        let mut value=node("vmess");value.as_object_mut().unwrap().extend(change.as_object().unwrap().clone());
        let error=convert_outbound(value,"$.outbounds[3]").unwrap_err();
        assert!(error.path.starts_with("$.outbounds[3]."));assert!(!error.to_string().contains("test-only"));
    }
}
#[test]
fn vision_and_transport_layers_preserve_order() {
    let mut vless=node("vless");vless["flow"]="xtls-rprx-vision".into();vless["tls"]=json!({"enabled":true,"server_name":"example.org","reality":{"enabled":true,"public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","short_id":"12345678"}});
    let result=convert_outbound(vless,"$").unwrap();let p=&result["client_chains"][0]["chain"][0]["protocol"];
    assert_eq!(p["type"],"reality");assert_eq!(p["vision"],true);assert_eq!(p["protocol"]["type"],"vless");
    let mut vmess=node("vmess");vmess["tls"]=json!({"enabled":true});vmess["transport"]=json!({"type":"grpc","service_name":"proxy"});
    let result=convert_outbound(vmess,"$").unwrap();let p=&result["client_chains"][0]["chain"][0]["protocol"];
    assert_eq!(p["type"],"tls");assert_eq!(p["alpn_protocols"],json!(["h2"]));assert_eq!(p["protocol"]["kind"],"grpc");assert_eq!(p["protocol"]["protocol"]["type"],"vmess");
}
#[test]
fn android_document_has_explicit_fail_closed_routing() {
    // Native runtime arrays must not bypass the App's supported protocol policy.
    let native=json!([{"address":"127.0.0.1:1080","protocol":{"type":"socks"}}]);
    assert!(normalize_json(&native.to_string(),None).is_err());
    let value=json!({"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct","rules":[{"domain_suffix":["blocked.example"],"action":"reject"}]},"inbounds":[{"type":"socks","listen_port":1080}]});
    let output:Value=serde_json::from_str(&normalize_json(&value.to_string(),None).unwrap()).unwrap();
    assert_eq!(output[1]["rules"][0]["action"],"block");assert_eq!(output[1]["rules"][1]["client_chain"],"__aerobox_direct");
    let mut missing=value.clone();missing["route"].as_object_mut().unwrap().remove("final");assert!(normalize_json(&missing.to_string(),None).is_err());
    let mut unknown=value;unknown["outbounds"][0]["tcp_fast_opne"]=true.into();assert!(normalize_json(&unknown.to_string(),None).is_err());
}
#[test]
fn tun_fd_is_passed_as_a_borrowed_number_and_never_opened_by_conversion() {
    let value=json!({"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"},"inbounds":[{"type":"tun","mtu":9000,"dns_hijack":true}]});
    assert!(normalize_json(&value.to_string(),None).is_err());
    let mut named=value.clone();named["inbounds"][0]["interface_name"]="tun0".into();
    assert!(normalize_json(&named.to_string(),None).is_err());
    let output:Value=serde_json::from_str(&normalize_json(&value.to_string(),Some(12345)).unwrap()).unwrap();
    assert_eq!(output[1]["device_fd"],12345);assert!(normalize_json(&value.to_string(),Some(-1)).is_err());
}

#[test]
fn naive_http3_options_and_uot_remain_on_native_quic_connector() {
    let mut value=node("naive");
    value.as_object_mut().unwrap().extend(json!({"quic":true,"quic_congestion_control":"bbr","stream_receive_window":"512 KiB","quic_session_receive_window":"2 MiB","insecure_concurrency":2,"extra_headers":{"x-label":["a","b"]},"udp_over_tcp":{"enabled":true,"version":2}}).as_object().unwrap().clone());
    let converted=convert_outbound(value,"$").unwrap();let client=&converted["client_chains"][0]["chain"][0];
    assert_eq!(client["transport"],"quic");assert_eq!(client["quic_settings"]["alpn_protocols"],json!(["h3"]));
    assert_eq!(client["protocol"]["type"],"naiveproxy");
    assert_eq!(client["protocol"]["settings"]["stream_receive_window"],524288);
    assert_eq!(client["protocol"]["settings"]["session_receive_window"],2097152);
    assert_eq!(client["protocol"]["settings"]["udp_over_tcp"],2);
}


#[test]
fn vmess_authenticated_length_and_global_padding_reach_the_runtime() {
    let mut value=node("vmess");
    value["global_padding"]=true.into();
    value["authenticated_length"]=true.into();
    let converted=convert_outbound(value,"$").unwrap();
    let protocol=&converted["client_chains"][0]["chain"][0]["protocol"];
    assert_eq!(protocol["global_padding"],true);
    assert_eq!(protocol["authenticated_length"],true);
}


#[test]
fn udp_encodings_preserve_explicit_choices_and_protocol_defaults() {
    for kind in ["vmess", "vless"] {
        for encoding in ["none", "xudp", "packetaddr"] {
            let mut value=node(kind);value["packet_encoding"]=encoding.into();
            let converted=convert_outbound(value,"$").unwrap();
            assert_eq!(converted["client_chains"][0]["chain"][0]["protocol"]["packet_encoding"],encoding);
        }
        let converted=convert_outbound(node(kind),"$").unwrap();
        assert_eq!(converted["client_chains"][0]["chain"][0]["protocol"]["packet_encoding"],if kind=="vless" {"xudp"} else {"none"});
        let mut value=node(kind);value["packet_encoding"]="typo".into();
        assert!(convert_outbound(value,"$").unwrap_err().path.ends_with(".packet_encoding"));
    }
}
