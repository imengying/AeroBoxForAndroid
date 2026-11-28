use serde_json::{Value, json};
use shoes::config::tls::{TlsClientFingerprint, TlsClientOptions};

fn outbound(reality: bool, vision: bool) -> Value {
    let mut node = json!({"type":"vless","tag":"proxy","server":"127.0.0.1","server_port":9,
        "uuid":"01010101-0101-4101-8101-010101010101",
        "tls":{"enabled":true,"server_name":"cover.test","utls":{"enabled":true,"fingerprint":"random"}}});
    if reality {
        node["tls"]["reality"] = json!({"enabled":true,"public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","short_id":"0101010101010101"});
    }
    if vision {
        node["flow"] = "xtls-rprx-vision".into();
    }
    node
}

fn document(node: Value) -> Value {
    // Check never binds this socket. A listener rule ensures the outbound is
    // compiled rather than merely preserving an unused client group.
    json!({"outbounds":[node],"route":{"final":"proxy"},
        "inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":2080}]})
}

fn converted_profile(node: Value, reality: bool) -> String {
    let converted = aerobox_config::convert_outbound(node, "$node").unwrap();
    let protocol = &converted["client_chains"][0]["chain"][0]["protocol"];
    if reality {
        &protocol["fingerprint"]
    } else {
        &protocol["options"]["fingerprint"]
    }
    .as_str()
    .unwrap()
    .to_owned()
}

#[test]
fn host_check_and_native_parser_share_random_across_all_transports_and_errors() {
    let expected = converted_profile(outbound(false, false), false);
    let fixed: TlsClientFingerprint = serde_json::from_value(json!(expected)).unwrap();
    let runtime = aerobox::AndroidRuntime::new().unwrap();
    for _ in 0..2 {
        let native: TlsClientOptions =
            serde_json::from_value(json!({"fingerprint":"random"})).unwrap();
        assert_eq!(native.fingerprint, Some(fixed));
        for reality in [false, true] {
            for vision in [false, true] {
                let node = outbound(reality, vision);
                assert_eq!(converted_profile(node.clone(), reality), expected);
                runtime.check(&document(node.clone()).to_string()).unwrap();
                assert!(!runtime.is_running());
                let mut invalid = node;
                invalid["tls"]["cipher_suites"] = json!(["TLS_AES_128_GCM_SHA256"]);
                assert!(runtime.check(&document(invalid).to_string()).is_err());
                assert_eq!(
                    converted_profile(outbound(reality, vision), reality),
                    expected
                );
            }
        }
        let mut ech = outbound(false, false);
        ech["tls"]["ech"] = json!({"enabled":true,"query_server_name":"cover.test"});
        assert_eq!(
            runtime.check(&document(ech).to_string()).is_ok(),
            expected == "chrome133"
        );
        let mut disabled = outbound(false, false);
        disabled["tls"]["utls"]["enabled"] = false.into();
        let normalized =
            aerobox_config::normalize_json(&document(disabled.clone()).to_string(), None).unwrap();
        assert!(!normalized.contains("fingerprint"));
        runtime.check(&document(disabled).to_string()).unwrap();
    }
}

#[test]
fn host_random_survives_start_stop_and_new_runtime_in_same_process() {
    let original = document(outbound(false, false));
    let expected = converted_profile(outbound(false, false), false);
    for _ in 0..2 {
        let runtime = aerobox::AndroidRuntime::new().unwrap();
        runtime.check(&original.to_string()).unwrap();
        let mut input = original.clone();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        input["inbounds"][0]["listen_port"] = listener.local_addr().unwrap().port().into();
        drop(listener);
        runtime.start(&input.to_string(), None, None).unwrap();
        assert!(runtime.is_running());
        assert_eq!(converted_profile(outbound(false, false), false), expected);
        runtime.stop().unwrap();
        assert!(!runtime.is_running());
        let options: TlsClientOptions =
            serde_json::from_value(json!({"fingerprint":"random"})).unwrap();
        assert_eq!(
            serde_json::to_value(options).unwrap()["fingerprint"],
            expected
        );
    }
}
