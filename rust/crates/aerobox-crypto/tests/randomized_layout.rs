//! Dynamic structure compared with independently captured pinned uTLS records.
#[path = "support/randomized.rs"]
mod support;
use std::io::{BufRead, BufReader};
use support::*;
#[test]
fn invalid_structure_never_becomes_a_partial_or_fallback_plan() {
    for field in ["suites", "signatures", "groups", "shares", "extensions"] {
        let mut bad = plan();
        let array = bad[field].as_array_mut().unwrap();
        array.push(array[0].clone());
        assert!(structure(&bad).is_err(), "duplicate {field}");
        let mut bad = plan();
        bad[field][0] = serde_json::json!(65535);
        assert!(structure(&bad).is_err(), "unknown {field}");
    }
    let mut bad = plan();
    bad["shares"] = serde_json::json!([4588, 29]);
    assert!(structure(&bad).is_err());
    let mut bad = plan();
    bad["maximum"] = serde_json::json!(771);
    assert!(structure(&bad).is_err());
    let mut bad = plan();
    bad["suites"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!(5));
    assert!(structure(&bad).is_err());
}
#[test]
fn explicit_policy_conflicts_fail_before_emitting_a_hello() {
    for modern_only in [false, true] {
        assert!(start(config(&plan(), modern_only).unwrap(), "localhost").is_ok());
        for which in 0..11 {
            let mut cfg = config(&plan(), modern_only).unwrap();
            match which {
                0 => cfg.initial_key_share_groups.reverse(),
                1 => cfg.randomized_client_hello = None,
                2 => cfg.client_hello_layout = None,
                3 => cfg.enable_early_data = true,
                4 => cfg.require_ems = true,
                5 => cfg.enable_tls12_renegotiation = !cfg.enable_tls12_renegotiation,
                6 => cfg.cert_decompressors = vec![rustls::compress::BROTLI_DECOMPRESSOR],
                7 => cfg.application_settings = None,
                8 => cfg.alpn_protocols.clear(),
                9 => cfg.check_selected_alpn = false,
                10 => cfg.enable_secret_extraction = true,
                _ => unreachable!(),
            }
            assert!(
                start(cfg, "localhost").is_err(),
                "policy {which}, tls13-only {modern_only}"
            );
        }
    }
}
#[test]
#[ignore = "requires AEROBOX_RANDOMIZED_TLS_CASES and AEROBOX_RANDOMIZED_TLS_OUTPUT"]
fn independent_first_flights_and_hrr_captures() {
    let input =
        std::fs::File::open(std::env::var_os("AEROBOX_RANDOMIZED_TLS_CASES").unwrap()).unwrap();
    let output = std::env::var_os("AEROBOX_RANDOMIZED_TLS_OUTPUT").unwrap();
    let mut rows = vec![];
    for line in BufReader::new(input).lines() {
        let row: serde_json::Value = serde_json::from_str(&line.unwrap()).unwrap();
        let value = &row["plan"];
        let mut cfg = match config(value, false) {
            Ok(c) => c,
            Err(e) => {
                assert!(
                    ids(value, "shares")
                        .iter()
                        .any(|g| !ids(value, "groups").contains(g)),
                    "unexpected error {e}"
                );
                rows.push(serde_json::json!({"id":row["id"],"rejected":true}));
                continue;
            }
        };
        let reference = &row["reference"];
        let name = reference["server_name"].as_str().unwrap();
        cfg.enable_sni = !name.is_empty();
        if ids(value, "extensions").contains(&16) {
            if let Some(alpn) = reference["requested_alpn"]
                .as_array()
                .filter(|a| !a.is_empty())
            {
                cfg.alpn_protocols = alpn
                    .iter()
                    .map(|v| v.as_str().unwrap().as_bytes().to_vec())
                    .collect();
            }
        }
        let (mut client, mut wire) = start(
            cfg,
            if name.is_empty() {
                "browser-profile.example"
            } else {
                name
            },
        )
        .unwrap();
        let first = wire.clone();
        let mut error = None;
        if let Some(hrr) = reference["hrr_hex"].as_str().filter(|h| !h.is_empty()) {
            // Reference HRR stores a handshake message for its own session.
            // Echo this connection's real ID, then place it in a TLS record.
            let mut handshake = unhex(hrr);
            assert_eq!(first[5 + 38], 32);
            assert_eq!(handshake[38], 32);
            handshake[39..71].copy_from_slice(&first[5 + 39..5 + 71]);
            let mut bytes = vec![22, 3, 3];
            bytes.extend((handshake.len() as u16).to_be_bytes());
            bytes.extend(handshake);
            client.read_tls(&mut &bytes[..]).unwrap();
            error = client.process_new_packets().err().map(|e| e.to_string());
            while client.wants_write() {
                client.write_tls(&mut wire).unwrap();
            }
        }
        rows.push(serde_json::json!({"id":row["id"],"first_hex":hex(&first),"wire_hex":hex(&wire),"error":error}));
    }
    assert!(rows.len() >= 64);
    std::fs::write(output, serde_json::to_vec_pretty(&rows).unwrap()).unwrap();
}
