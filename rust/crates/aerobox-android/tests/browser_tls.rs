//! The public host check path must carry Android JSON through conversion,
//! semantic validation and runtime construction without opening proxy sockets.
use serde_json::json;
#[test]
fn android_check_accepts_chrome_tls_reality_and_vision_and_reports_conflicts() {
    let runtime = aerobox::AndroidRuntime::new().unwrap();
    for chrome in [false, true] {
        for reality in [false, true] {
            for vision in [false, true] {
                let mut proxy = json!({"type":"vless","tag":"proxy","server":"127.0.0.1","server_port":9,
                "uuid":"01010101-0101-4101-8101-010101010101",
                "tls":{"enabled":true,"server_name":"cover.test","utls":{"enabled":true,"fingerprint":"chrome"},"alpn":["h2"],"record_fragment":true}});
                proxy["tls"]["utls"]["enabled"] = chrome.into();
                if vision {
                    proxy["flow"] = "xtls-rprx-vision".into();
                }
                if reality {
                    proxy["tls"]["reality"] = json!({"enabled":true,"public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","short_id":"0101010101010101"});
                }
                let document = json!({"outbounds":[proxy],"route":{"final":"proxy"},"inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":2080}]});
                let report = runtime.check_details(&document.to_string()).unwrap();
                assert_eq!(report["requiresTunDescriptor"], false);
                assert!(!runtime.is_running());
                if !chrome {
                    continue;
                }
                for mutation in [
                    json!({"utls":{"enabled":true,"fingerprint":"unimplemented"}}),
                    json!({"max_version":"1.2"}),
                    json!({"cipher_suites":["TLS_AES_128_GCM_SHA256"]}),
                ] {
                    let mut invalid = document.clone();
                    invalid["outbounds"][0]["tls"]
                        .as_object_mut()
                        .unwrap()
                        .extend(mutation.as_object().unwrap().clone());
                    assert!(runtime.check_details(&invalid.to_string()).is_err());
                    assert!(!runtime.is_running());
                }
            }
        }
    }
}
