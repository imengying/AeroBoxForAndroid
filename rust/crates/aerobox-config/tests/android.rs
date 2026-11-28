use aerobox_config::normalize_json;
use serde_json::{Value, json};
fn generated() -> Value {
    json!({
        "log":{"level":"error","timestamp":true},
        "dns":{"servers":[
            {"type":"https","tag":"dns-remote","server":"cloudflare-dns.com","server_port":443,"path":"/dns-query","detour":"proxy","domain_resolver":{"server":"dns-direct","strategy":"prefer_ipv4"}},
            {"type":"https","tag":"dns-direct","server":"dns.alidns.com","server_port":443,"path":"/dns-query","domain_resolver":{"server":"dns-local","strategy":"prefer_ipv4"}},
            {"type":"local","tag":"dns-local"},
            {"type":"fakeip","tag":"dns-fake","inet4_range":"198.18.0.0/15","inet6_range":"fc00::/18"}
        ],"final":"dns-remote","strategy":"prefer_ipv6","rules":[
            {"domain":["proxy.example"],"action":"route","server":"dns-direct"},
            {"rule_set":["geosite-cn"],"action":"route","server":"dns-direct"},
            {"domain_suffix":[".lan",".local",".home.arpa"],"action":"route","server":"dns-direct"},
            {"inbound":["tun-in"],"query_type":["A","AAAA"],"action":"route","server":"dns-fake"},
            {"inbound":["tun-in"],"query_type":["HTTPS","SVCB"],"action":"predefined","rcode":"NOERROR"}
        ]},
        "outbounds":[{"type":"socks","tag":"proxy","server":"proxy.example","server_port":1080,"domain_resolver":{"server":"dns-direct","strategy":"prefer_ipv4"}},{"type":"direct","tag":"direct"}],
        "inbounds":[{"type":"tun","tag":"tun-in","interface_name":"tun0","address":["172.19.0.1/28","fdfe:dcba:9876::1/126"],"mtu":9000,"auto_route":true,"stack":"mixed"},{"type":"socks","tag":"socks-in","listen":"127.0.0.1","listen_port":2080}],
        "route":{"auto_detect_interface":true,"final":"proxy","rule_set":[{"type":"local","tag":"geosite-cn","format":"binary","path":"/data/user/0/com.aerobox/files/geosite-cn.srs"}],"rules":[
            {"action":"sniff"},{"action":"resolve","strategy":"prefer_ipv6"},
            {"port":[53],"action":"hijack-dns"},{"protocol":"dns","action":"hijack-dns"},
            {"ip_cidr":["224.0.0.0/3","ff00::/8"],"action":"reject"},{"source_ip_cidr":["224.0.0.0/3","ff00::/8"],"action":"reject"},
            {"network":["udp"],"port":[443],"action":"reject"},{"rule_set":["geosite-cn"],"action":"route","outbound":"direct"}
        ]},
        "experimental":{"cache_file":{"enabled":true,"store_fakeip":true,"path":"/data/user/0/com.aerobox/files/rust-core/cache"}}
    })
}
#[test]
fn android_document_preserves_dns_split_bootstrap_fakeip_and_tun_ownership() {
    let output: Vec<Value> =
        serde_json::from_str(&normalize_json(&generated().to_string(), Some(31)).unwrap()).unwrap();
    let named = |key: &str, value: &str| output.iter().find(|entry| entry[key] == value).unwrap();
    let tun = named("name", "tun-in");
    assert_eq!(tun["device_fd"], 31);
    assert_eq!(tun["auto_route"], false);
    assert_eq!(tun["dns_hijack"], true);
    assert_eq!(tun["addresses"].as_array().unwrap().len(), 2);
    let policy = named("dns_group", tun["dns"]["servers"].as_str().unwrap());
    assert_eq!(
        policy["routing"]["rules"][1]["conditions"]["rule_source_group"],
        "geosite-cn"
    );
    assert_eq!(policy["routing"]["rules"][3]["fake_ip"], true);
    assert_eq!(
        policy["fake_ip"]["state_file"],
        "/data/user/0/com.aerobox/files/rust-core/cache.fakeip"
    );
    let socks = named("name", "socks-in");
    let socks_dns = named("dns_group", socks["dns"]["servers"].as_str().unwrap());
    assert!(socks_dns.get("fake_ip").is_none());
    assert_eq!(socks_dns["routing"]["rules"].as_array().unwrap().len(), 3);
    assert_eq!(
        named("dns_group", "dns-remote")["dns_servers"][0]["client_chain"],
        "proxy"
    );
    assert_eq!(
        named("dns_group", "dns-direct")["dns_servers"][0]["bootstrap_url"],
        "dns-local"
    );
    assert_eq!(
        named("rule_source_group", "geosite-cn")["rules"][0]["format"],
        "srs"
    );
    assert_eq!(
        named("client_group", "proxy")["client_chains"][0]["chain"][0]["domain_resolver"],
        json!({"server":"dns-direct","ip_strategy":"ipv4_then_ipv6"})
    );
}
#[test]
fn arbitrary_source_rule_and_unknown_dns_options_fail_with_field_paths() {
    let mut config = generated();
    config["route"]["rules"][5]["source_ip_cidr"] = json!(["10.0.0.0/8"]);
    assert!(
        normalize_json(&config.to_string(), Some(31))
            .unwrap_err()
            .path
            .starts_with("$.route.rules[5]")
    );
    let mut config = generated();
    config["dns"]["servers"][0]["tls"] = json!({"insecure":true});
    assert!(
        normalize_json(&config.to_string(), Some(31))
            .unwrap_err()
            .path
            .starts_with("$.dns.servers[0]")
    );
    for (field, value) in [
        ("schema_version", json!(2)),
        ("native", json!([])),
        (
            "experimental",
            json!({"v2ray_api":{"listen":"127.0.0.1:10085"}}),
        ),
        ("dns", json!({"servers":"system"})),
    ] {
        let mut config = generated();
        config[field] = value;
        assert!(
            normalize_json(&config.to_string(), Some(31)).is_err(),
            "obsolete configuration accepted: {field}"
        );
    }
}
#[test]
fn urltest_document_accepts_no_inbounds_and_preserves_named_resolvers() {
    let mut config = generated();
    config["inbounds"] = json!([]);
    config.as_object_mut().unwrap().remove("experimental");
    assert!(normalize_json(&config.to_string(), None).is_ok());
}
