//! Independent Firefox120 first-flight byte comparisons, including SNI and ALPN.
#[path = "support/firefox.rs"]
mod support;
use rustls::ClientConnection;
use std::{path::PathBuf, sync::Arc};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
#[ignore = "requires AEROBOX_FIREFOX_REFERENCE_CAPTURE and AEROBOX_FIREFOX_RUST_CAPTURE"]
fn firefox_first_flights_for_all_reference_sni_alpn_cases() {
    let input = PathBuf::from(std::env::var_os("AEROBOX_FIREFOX_REFERENCE_CAPTURE").unwrap());
    let output = PathBuf::from(std::env::var_os("AEROBOX_FIREFOX_RUST_CAPTURE").unwrap());
    let cases: Vec<serde_json::Value> =
        serde_json::from_slice(&std::fs::read(input).unwrap()).unwrap();
    let mut captures = vec![];
    for case in cases {
        if case["name"] != "firefox" {
            continue;
        }
        if case.get("skipped_reason").is_some() {
            continue;
        }
        assert_eq!(case["build_error"], "");
        assert_eq!(case["handshake_complete"], false);
        assert!(case.get("panic").is_none());
        assert!(case.get("validation_error").is_none());
        let mut cfg = support::config(false, false);
        if let Some(alpn) = case["requested_alpn"].as_array().filter(|a| !a.is_empty()) {
            cfg.alpn_protocols = alpn
                .iter()
                .map(|p| p.as_str().unwrap().as_bytes().to_vec())
                .collect();
        }
        let name = case["server_name"].as_str().unwrap();
        cfg.enable_sni = !name.is_empty();
        let name = if name.is_empty() {
            "browser-profile.example"
        } else {
            name
        };
        let mut client =
            ClientConnection::new(Arc::new(cfg), name.to_owned().try_into().unwrap()).unwrap();
        let mut wire = vec![];
        while client.wants_write() {
            client.write_tls(&mut wire).unwrap();
        }
        assert!(client.is_handshaking());
        captures.push(serde_json::json!({
            "name": case["name"], "case": case["case"], "profile": case["profile"], "wire_hex": hex(&wire),
        }));
    }
    assert!(captures.len() >= 10, "missing Firefox reference cases");
    std::fs::write(output, serde_json::to_vec_pretty(&captures).unwrap()).unwrap();
}

#[test]
fn firefox_refuses_missing_or_conflicting_capabilities_before_sending() {
    for tls13_only in [false, true] {
        for change in 0..10 {
            let mut config = support::config(false, tls13_only);
            match change {
                0 => config.initial_key_share_groups.pop().map(|_| ()).unwrap(),
                1 => config.initial_key_share_groups.reverse(),
                2 => config.cert_decompressors = vec![rustls::compress::BROTLI_DECOMPRESSOR],
                3 => config.enable_tls12_renegotiation = !config.enable_tls12_renegotiation,
                4 => config.enable_early_data = true,
                5 => config.advertise_record_size_limit = false,
                6 => config.enable_delegated_credentials = false,
                7 => config.alpn_protocols.clear(),
                8 => config.enable_secret_extraction = true,
                9 => {
                    config.application_settings = Some(
                        rustls::client::ApplicationSettings::new(
                            rustls::client::ApplicationSettingsCodepoint::Chrome,
                            vec![(b"h2".to_vec(), vec![])],
                        )
                        .unwrap(),
                    )
                }
                _ => unreachable!(),
            }
            assert!(
                ClientConnection::new(Arc::new(config), "localhost".try_into().unwrap()).is_err(),
                "TLS1.3 only={tls13_only}, conflict={change}"
            );
        }
    }
}
