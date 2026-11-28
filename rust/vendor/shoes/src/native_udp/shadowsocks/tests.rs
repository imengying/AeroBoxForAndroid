use super::*;

fn hex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
fn target() -> NetLocation {
    NetLocation::from_str("1.2.3.4:443", None).unwrap()
}
fn vectors() -> Vec<serde_json::Value> {
    serde_json::from_str(include_str!(
        "../../../tests/fixtures/native-udp-vectors/vectors.json"
    ))
    .unwrap()
}
fn configured(vector: &serde_json::Value) -> Session {
    let config = ShadowsocksConfig::from_client_fields(
        vector["method"].as_str().unwrap(),
        vector["password"].as_str().unwrap(),
    )
    .unwrap();
    let mut session = Client::new(config).unwrap().session().unwrap();
    session.id = [1, 2, 3, 4, 5, 6, 7, 8];
    session
}

#[test]
fn independent_go_vectors_cover_aead_ss2022_and_identity_chains() {
    for vector in vectors() {
        let mut session = configured(&vector);
        let request = session
            .encode_at(&target(), b"udp-vector", 1_700_000_000, |bytes| {
                bytes.fill(0x44);
                Ok(())
            })
            .unwrap();
        assert_eq!(
            request,
            hex(vector["request"].as_str().unwrap()),
            "{}",
            vector["method"]
        );
        for invalid in [
            "wrong_client",
            "old_time",
            "future_time",
            "wrong_type",
            "bad_padding",
        ] {
            if let Some(packet) = vector[invalid].as_str() {
                assert!(
                    session
                        .decode_at(&target(), &mut hex(packet), 1_700_000_000)
                        .is_err(),
                    "{invalid}"
                );
            }
        }
        let response = hex(vector["response"].as_str().unwrap());
        let mut tampered = response.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(
            session
                .decode_at(&target(), &mut tampered, 1_700_000_000)
                .is_err()
        );
        assert_eq!(
            session
                .decode_at(&target(), &mut response.clone(), 1_700_000_000)
                .unwrap(),
            b"udp-vector"
        );
        assert!(
            session
                .decode_at(&target(), &mut response.clone(), 1_700_000_000)
                .is_err(),
            "replay accepted"
        );
        if let Some(late) = vector["late_packet"].as_str() {
            assert_eq!(
                session
                    .decode_at(&target(), &mut hex(late), 1_700_000_000)
                    .unwrap(),
                b"udp-vector"
            );
            assert!(
                session
                    .decode_at(&target(), &mut hex(late), 1_700_000_000)
                    .is_err()
            );
        } else {
            // Original AEAD lacks directional headers; outgoing salts are also
            // recorded to prevent reflecting the client's own packets.
            assert!(
                session
                    .decode_at(&target(), &mut request.clone(), 1_700_000_000)
                    .is_err()
            );
        }
    }
}

#[test]
fn packet_parser_rejects_every_truncation_without_advancing_replay_state() {
    for vector in vectors() {
        let mut session = configured(&vector);
        let response = hex(vector["response"].as_str().unwrap());
        for end in 0..response.len() {
            assert!(
                session
                    .decode_at(&target(), &mut response[..end].to_vec(), 1_700_000_000)
                    .is_err()
            );
        }
        assert!(
            session
                .decode_at(
                    &NetLocation::from_str("1.2.3.5:443", None).unwrap(),
                    &mut response.clone(),
                    1_700_000_000
                )
                .is_err()
        );
        assert_eq!(
            session
                .decode_at(&target(), &mut response.clone(), 1_700_000_000)
                .unwrap(),
            b"udp-vector"
        );
    }
}

#[test]
fn replay_window_accepts_reordering_but_rejects_duplicates_and_old_packets() {
    let mut window = ReplayWindow::default();
    for number in [0, 1, 63, 64, 65, 127, 128, 2, 1023, 1024, 10_000, u64::MAX] {
        assert!(window.insert(number), "{number}");
        assert!(!window.insert(number), "{number} duplicate");
    }
    assert!(!window.insert(u64::MAX - 1024));
    assert!(window.insert(u64::MAX - 1023));
    assert!(!window.insert(u64::MAX - 1023));
    assert!(window.insert(u64::MAX - 1));
    // Compare the bit window with a straightforward set over irregular jumps.
    let mut window = ReplayWindow::default();
    let mut seen = HashSet::new();
    let mut highest = 0;
    for index in 0_u64..10_000 {
        let number = (index * 137) % 8_192;
        highest = highest.max(number);
        let expected = highest - number < 1024 && seen.insert(number);
        assert_eq!(window.insert(number), expected, "{number}");
    }
}

#[test]
fn short_domain_and_empty_payload_remain_valid_datagrams() {
    let body = [3, 1, b'a', 0, 53];
    let (source, payload) = parse_address(&body).unwrap();
    assert_eq!(source, NetLocation::from_str("a:53", None).unwrap());
    assert!(payload.is_empty());
    assert!(parse_address(&[3, 0, 0, 53, 0]).is_err());
}
