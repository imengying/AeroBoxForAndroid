//! Complete first flights, including SNI/ALPN and BoringSSL padding boundaries.
#[path = "support/android_browser.rs"]
mod support;
use rustls::{ClientConnection, client::ClientHelloLayout};
use std::{path::PathBuf, sync::Arc};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
#[ignore = "requires AEROBOX_ANDROID_BROWSER_REFERENCE_CAPTURE and AEROBOX_ANDROID_BROWSER_RUST_CAPTURE"]
fn android_browser_first_flights_for_all_reference_sni_alpn_and_padding_cases() {
    let input =
        PathBuf::from(std::env::var_os("AEROBOX_ANDROID_BROWSER_REFERENCE_CAPTURE").unwrap());
    let output = PathBuf::from(std::env::var_os("AEROBOX_ANDROID_BROWSER_RUST_CAPTURE").unwrap());
    let cases: Vec<serde_json::Value> =
        serde_json::from_slice(&std::fs::read(input).unwrap()).unwrap();
    let mut captures = vec![];
    for case in cases {
        let profile = match case["name"].as_str().unwrap() {
            "safari" => ClientHelloLayout::Safari16,
            "ios" => ClientHelloLayout::Ios14,
            _ => continue,
        };
        if case.get("skipped_reason").is_some() {
            continue;
        }
        assert_eq!(case["build_error"], "");
        assert_eq!(case["handshake_complete"], false);
        assert!(case.get("panic").is_none());
        assert!(case.get("validation_error").is_none());
        let mut cfg = support::config(profile, false);
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
    assert!(captures.len() >= 24, "missing reference padding boundaries");
    std::fs::write(output, serde_json::to_vec_pretty(&captures).unwrap()).unwrap();
}

#[test]
fn android_browser_reject_conflicting_layout_capabilities_before_sending() {
    for profile in [ClientHelloLayout::Safari16, ClientHelloLayout::Ios14] {
        for change in 0..8 {
            let mut cfg = support::config(profile, false);
            match change {
                0 => cfg.initial_key_share_groups.clear(),
                1 => cfg
                    .initial_key_share_groups
                    .push(rustls::NamedGroup::secp256r1),
                2 => cfg.cert_decompressors = vec![rustls::compress::BROTLI_DECOMPRESSOR],
                3 => cfg.enable_tls12_renegotiation = false,
                4 => cfg.enable_early_data = true,
                5 => cfg.resumption = rustls::client::Resumption::default(),
                6 => cfg.alpn_protocols.clear(),
                7 => {
                    cfg.application_settings = Some(
                        rustls::client::ApplicationSettings::new(
                            rustls::client::ApplicationSettingsCodepoint::Legacy,
                            vec![(b"h2".to_vec(), vec![])],
                        )
                        .unwrap(),
                    );
                }
                _ => unreachable!(),
            }
            assert!(
                ClientConnection::new(Arc::new(cfg), "localhost".try_into().unwrap()).is_err(),
                "{profile:?}, conflict {change}"
            );
        }
    }
}

#[test]
fn ordinary_and_browser_alpn_lengths_fail_without_panicking_or_truncating() {
    for profile in [
        None,
        Some(ClientHelloLayout::Safari16),
        Some(ClientHelloLayout::Ios14),
    ] {
        for case in 0..4 {
            let mut cfg = if let Some(profile) = profile {
                support::config(profile, false)
            } else {
                rustls::ClientConfig::builder_with_provider(aerobox_crypto::shared_provider())
                    .with_safe_default_protocol_versions()
                    .unwrap()
                    .with_root_certificates(rustls::RootCertStore::empty())
                    .with_no_client_auth()
            };
            let alpn = match case {
                0 => vec![vec![]],
                1 => vec![vec![42; 256]],
                2 => vec![vec![42; 255]; 256],
                3 => {
                    let mut values = vec![vec![42; 255]; 255];
                    values.push(vec![42; 249]);
                    values
                }
                _ => unreachable!(),
            };
            cfg.alpn_protocols = alpn.clone();
            let cfg = Arc::new(cfg);
            let name = "localhost".try_into().unwrap();
            assert!(
                ClientConnection::new(cfg.clone(), name).is_err(),
                "{profile:?}/{case}"
            );
            assert!(
                ClientConnection::new_with_alpn(cfg, "localhost".try_into().unwrap(), alpn)
                    .is_err()
            );
        }
    }
}

#[test]
fn browser_tls13_only_policy_rejects_old_server_selection() {
    for profile in [ClientHelloLayout::Safari16, ClientHelloLayout::Ios14] {
        for version in [0x0301u16, 0x0302, 0x0303] {
            let mut client = ClientConnection::new(
                Arc::new(support::with_version_policy(profile, false, true)),
                "localhost".try_into().unwrap(),
            )
            .unwrap();
            client.write_tls(&mut Vec::new()).unwrap();
            let mut body = version.to_be_bytes().to_vec();
            body.extend([42; 32]);
            body.extend([0, 0xc0, 0x13, 0, 0, 0]);
            let mut handshake = vec![2, 0, 0, body.len() as u8];
            handshake.extend(body);
            let mut record = vec![22, 3, 1, 0, handshake.len() as u8];
            record.extend(handshake);
            client.read_tls(&mut record.as_slice()).unwrap();
            assert!(
                client.process_new_packets().is_err(),
                "{profile:?}/{version:04x}"
            );
        }
    }
}
