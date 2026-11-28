//! Public Android JSON -> converter -> native config validation.
//! Runtime.check never starts listeners, dials a peer, or claims a handshake.
use serde_json::{Value, json};

const CIPHERS: [&str; 15] = [
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
];

fn document(kind: &str, profile: &str) -> Value {
    let mut node = json!({
        "type":kind, "tag":"proxy", "server":"127.0.0.1", "server_port":9,
        "tls":{"enabled":true,"server_name":"cover.test",
            "utls":{"enabled":true,"fingerprint":profile}}
    });
    match kind {
        "vmess" => {
            node["uuid"] = "test-only-name".into();
            node["security"] = "auto".into();
        }
        "vless" | "tuic" => node["uuid"] = "01010101-0101-4101-8101-010101010101".into(),
        "trojan" | "hysteria2" => {}
        "naive" => node["username"] = "test-only".into(),
        _ => unreachable!(),
    }
    if matches!(kind, "trojan" | "tuic" | "hysteria2" | "naive") {
        node["password"] = "test-only".into();
    }
    json!({"outbounds":[node],"route":{"final":"proxy"},
        "inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":2080}]})
}

fn tls(doc: &mut Value) -> &mut Value {
    &mut doc["outbounds"][0]["tls"]
}

fn reality(doc: &mut Value) {
    tls(doc)["reality"] = json!({"enabled":true,
        "public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "short_id":"0101010101010101"});
}

fn accept(runtime: &aerobox::AndroidRuntime, doc: &Value, label: &str) {
    let report = runtime
        .check_details(&doc.to_string())
        .unwrap_or_else(|error| panic!("{label}: {error}"));
    assert_eq!(report["requiresTunDescriptor"], false, "{label}");
    assert!(!runtime.is_running(), "{label}");
}

fn reject(runtime: &aerobox::AndroidRuntime, doc: &Value, label: &str) {
    assert!(runtime.check(&doc.to_string()).is_err(), "accepted {label}");
    assert!(!runtime.is_running(), "{label}");
}

#[test]
fn public_edge_qq_accept_complete_stream_profiles_and_preserve_local_check() {
    let runtime = aerobox::AndroidRuntime::new().unwrap();
    for profile in ["edge", "qq"] {
        for kind in ["vmess", "vless", "trojan"] {
            for insecure in [false, true] {
                for fragment in [false, true] {
                    let mut doc = document(kind, profile);
                    tls(&mut doc)["insecure"] = insecure.into();
                    tls(&mut doc)["record_fragment"] = fragment.into();
                    accept(
                        &runtime,
                        &doc,
                        &format!("{profile}/{kind}/{insecure}/{fragment}"),
                    );
                }
            }
            // These are the exact explicit policy lists; subsets/reordering below fail.
            let mut explicit = document(kind, profile);
            tls(&mut explicit)["min_version"] = "1.0".into();
            tls(&mut explicit)["max_version"] = "1.3".into();
            tls(&mut explicit)["curve_preferences"] = json!(["X25519", "SecP256r1", "SecP384r1"]);
            tls(&mut explicit)["cipher_suites"] = json!(CIPHERS);
            accept(
                &runtime,
                &explicit,
                &format!("{profile}/{kind}/explicit-complete"),
            );
            for alpn in [json!(["h2"]), json!(["http/1.1"]), json!(["audit-custom"])] {
                let mut doc = document(kind, profile);
                tls(&mut doc)["alpn"] = alpn.clone();
                accept(&runtime, &doc, &format!("{profile}/{kind}/alpn={alpn}"));
            }
        }
    }
}

#[test]
fn public_edge_qq_reject_conflicting_versions_curves_ciphers_and_ech() {
    let runtime = aerobox::AndroidRuntime::new().unwrap();
    for profile in ["edge", "qq"] {
        for kind in ["vmess", "vless", "trojan"] {
            for mutation in [
                json!({"min_version":"1.2"}),
                json!({"max_version":"1.2"}),
                json!({"curve_preferences":"SecP521r1"}),
                json!({"curve_preferences":["X25519"]}),
                json!({"curve_preferences":["X25519MLKEM768","X25519","SecP256r1","SecP384r1"]}),
                json!({"curve_preferences":["SecP256r1","X25519","SecP384r1"]}),
                json!({"cipher_suites":["TLS_AES_128_GCM_SHA256"]}),
                json!({"ech":{"enabled":true,"query_server_name":"cover.test"}}),
            ] {
                let mut doc = document(kind, profile);
                tls(&mut doc)
                    .as_object_mut()
                    .unwrap()
                    .extend(mutation.as_object().unwrap().clone());
                reject(&runtime, &doc, &format!("{profile}/{kind}/{mutation}"));
            }
            let mut order = CIPHERS;
            order.swap(0, 1);
            let mut doc = document(kind, profile);
            tls(&mut doc)["cipher_suites"] = json!(order);
            reject(
                &runtime,
                &doc,
                &format!("{profile}/{kind}/reordered-ciphers"),
            );
        }
    }
}

#[test]
fn public_edge_qq_accept_reality_and_vless_vision_without_profile_substitution() {
    let runtime = aerobox::AndroidRuntime::new().unwrap();
    for profile in ["edge", "qq"] {
        for kind in ["vmess", "vless", "trojan"] {
            let mut doc = document(kind, profile);
            reality(&mut doc);
            tls(&mut doc)["alpn"] = json!(["h2"]);
            tls(&mut doc)["record_fragment"] = true.into();
            accept(&runtime, &doc, &format!("{profile}/{kind}/reality"));
        }
        for use_reality in [false, true] {
            let mut doc = document("vless", profile);
            doc["outbounds"][0]["flow"] = "xtls-rprx-vision".into();
            if use_reality {
                reality(&mut doc);
            }
            tls(&mut doc)["alpn"] = json!(["h2"]);
            tls(&mut doc)["record_fragment"] = true.into();
            accept(
                &runtime,
                &doc,
                &format!("{profile}/vision/reality={use_reality}"),
            );
            // Public acceptance alone does not prove TLS version policy or wire
            // identity; the rustls/native handshake tests check both separately.
            for mutation in [
                json!({"max_version":"1.2"}),
                json!({"curve_preferences":["SecP521r1"]}),
                json!({"cipher_suites":["TLS_AES_128_GCM_SHA256"]}),
                json!({"ech":{"enabled":true,"query_server_name":"cover.test"}}),
            ] {
                let mut invalid = doc.clone();
                tls(&mut invalid)
                    .as_object_mut()
                    .unwrap()
                    .extend(mutation.as_object().unwrap().clone());
                reject(
                    &runtime,
                    &invalid,
                    &format!("{profile}/vision/reality={use_reality}/{mutation}"),
                );
            }
        }
    }
}

#[test]
fn public_edge_qq_reality_does_not_drop_conflicting_curve_policy() {
    let runtime = aerobox::AndroidRuntime::new().unwrap();
    for profile in ["edge", "qq"] {
        for kind in ["vmess", "vless", "trojan"] {
            let mut doc = document(kind, profile);
            reality(&mut doc);
            for curves in [
                json!("SecP521r1"),
                json!(["X25519MLKEM768"]),
                json!(["X25519"]),
                json!(["X25519", "SecP256r1", "SecP384r1"]),
            ] {
                tls(&mut doc)["curve_preferences"] = curves.clone();
                reject(
                    &runtime,
                    &doc,
                    &format!("{profile}/{kind}/reality-curves={curves}"),
                );
            }
        }
    }
}

#[test]
fn public_tls_rejects_invalid_alpn_before_starting_connections() {
    let runtime = aerobox::AndroidRuntime::new().unwrap();
    for profile in [None, Some("edge"), Some("qq")] {
        for kind in ["vmess", "vless", "trojan"] {
            for case in 0..4 {
                let mut doc = document(kind, profile.unwrap_or("edge"));
                if profile.is_none() {
                    tls(&mut doc).as_object_mut().unwrap().remove("utls");
                }
                let alpn = match case {
                    0 => vec![String::new()],
                    1 => vec!["a".repeat(256)],
                    2 => vec!["a".repeat(255); 256],
                    3 => {
                        let mut values = vec!["a".repeat(255); 255];
                        values.push("a".repeat(249));
                        values
                    }
                    _ => unreachable!(),
                };
                tls(&mut doc)["alpn"] = json!(alpn);
                reject(
                    &runtime,
                    &doc,
                    &format!("{profile:?}/{kind}/invalid-alpn-{case}"),
                );
            }
        }
    }
}

#[test]
fn public_edge_qq_reject_quic_and_naive_browser_wrappers() {
    let runtime = aerobox::AndroidRuntime::new().unwrap();
    for profile in ["edge", "qq"] {
        for kind in ["tuic", "hysteria2", "naive"] {
            let mut doc = document(kind, profile);
            reject(&runtime, &doc, &format!("{profile}/{kind}"));
            if kind == "naive" {
                doc["outbounds"][0]["quic"] = true.into();
                reject(&runtime, &doc, &format!("{profile}/naive-quic"));
            }
        }
    }
}

#[test]
fn public_old_tls_stays_disabled_without_an_enabled_compatible_profile() {
    let runtime = aerobox::AndroidRuntime::new().unwrap();
    for kind in ["vmess", "vless", "trojan"] {
        for profile in ["edge", "qq"] {
            for version in ["1.0", "1.1"] {
                let mut doc = document(kind, profile);
                tls(&mut doc)["min_version"] = version.into();
                tls(&mut doc)["max_version"] = "1.3".into();
                tls(&mut doc)["utls"]["enabled"] = false.into();
                reject(
                    &runtime,
                    &doc,
                    &format!("{kind}/{profile}/disabled/{version}"),
                );
                tls(&mut doc).as_object_mut().unwrap().remove("utls");
                reject(&runtime, &doc, &format!("{kind}/ordinary/{version}"));
            }
        }
    }
}
