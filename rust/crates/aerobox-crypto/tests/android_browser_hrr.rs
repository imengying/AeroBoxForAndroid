//! Reproduce the independent uTLS HRR inputs, rebinding only the session ID.
#[path = "support/android_browser.rs"]
mod support;
use rustls::{ClientConnection, client::ClientHelloLayout};
use std::{path::PathBuf, sync::Arc};

fn decode(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn flight(wire: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut i = 0;
    let mut records = vec![];
    let mut handshake = vec![];
    while i < wire.len() {
        let n = u16::from_be_bytes(wire[i + 3..i + 5].try_into().unwrap()) as usize;
        if wire[i] == 22 {
            records.extend_from_slice(&wire[i..i + 5 + n]);
            handshake.extend_from_slice(&wire[i + 5..i + 5 + n]);
        } else {
            assert_eq!(&wire[i..i + 5 + n], &[20, 3, 3, 0, 1, 1]);
        }
        i += 5 + n;
    }
    assert_eq!(i, wire.len());
    assert_eq!(handshake[0], 1);
    (records, handshake)
}

#[test]
#[ignore = "requires AEROBOX_ANDROID_BROWSER_HRR_REFERENCE and AEROBOX_ANDROID_BROWSER_HRR_RUST_CAPTURE"]
fn android_browser_cookie_retry_and_group_retry_preserve_exact_layout_rules() {
    let input = PathBuf::from(std::env::var_os("AEROBOX_ANDROID_BROWSER_HRR_REFERENCE").unwrap());
    let output =
        PathBuf::from(std::env::var_os("AEROBOX_ANDROID_BROWSER_HRR_RUST_CAPTURE").unwrap());
    let cases: Vec<serde_json::Value> =
        serde_json::from_slice(&std::fs::read(input).unwrap()).unwrap();
    let mut results = vec![];
    for case in cases {
        if case.get("skipped_reason").is_some() {
            continue;
        }
        let profile = match case["name"].as_str().unwrap() {
            "safari" => ClientHelloLayout::Safari16,
            "ios" => ClientHelloLayout::Ios14,
            _ => continue,
        };
        assert_eq!(case["build_error"], "");
        assert_eq!(case["expected_eof"], true);
        let mut cfg = support::config(profile, false);
        if let Some(alpn) = case["requested_alpn"].as_array().filter(|v| !v.is_empty()) {
            cfg.alpn_protocols = alpn
                .iter()
                .map(|v| v.as_str().unwrap().as_bytes().to_vec())
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
        let mut first = vec![];
        while client.wants_write() {
            client.write_tls(&mut first).unwrap();
        }
        let (_, ch1) = flight(&first);
        let mut hrr = decode(case["hrr_handshake_hex"].as_str().unwrap());
        let n = usize::from(ch1[38]);
        assert_eq!(usize::from(hrr[38]), n);
        hrr[39..39 + n].copy_from_slice(&ch1[39..39 + n]);
        let mut record = vec![22, 3, 3, (hrr.len() >> 8) as u8, hrr.len() as u8];
        record.extend_from_slice(&hrr);
        for fragment in record.chunks(7) {
            client.read_tls(&mut fragment.as_ref()).unwrap();
            client.process_new_packets().unwrap();
        }
        assert!(client.is_handshaking());
        let mut second = vec![];
        while client.wants_write() {
            client.write_tls(&mut second).unwrap();
        }
        let (ch2records, ch2) = flight(&second);
        let mut outbound = first.clone();
        outbound.extend_from_slice(&second);
        results.push(serde_json::json!({
            "name":case["name"],"profile":case["profile"],"mode":case["mode"],"case":case["case"],"sample":case["sample"],
            "server_name":case["server_name"],"requested_alpn":case["requested_alpn"],
            "cookie_hex":case["cookie_hex"],"hrr_handshake_hex":hex(&hrr),"hrr_record_hex":hex(&record),
            "client_hellos_hex":[hex(&ch1),hex(&ch2)],"client_hello_records_hex":[hex(&first),hex(&ch2records)],
            "outbound_wire_hex":hex(&outbound),"handshake_complete":false,
        }));
    }
    assert!(results.len() >= 100);
    std::fs::write(output, serde_json::to_vec_pretty(&results).unwrap()).unwrap();
}
