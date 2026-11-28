use aerobox_crypto::hpke::ALL_SUPPORTED_SUITES;
use rustls::crypto::hpke::{EncapsulatedSecret, HpkePrivateKey};

fn hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|v| u8::from_str_radix(std::str::from_utf8(v).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn rfc9180_base_vectors_include_257_sequential_messages_per_suite() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/rfc9180-base.json")).unwrap();
    let vectors = vectors.as_array().unwrap();
    assert_eq!(vectors.len(), 9);
    for vector in vectors {
        let suite = ALL_SUPPORTED_SUITES
            .iter()
            .find(|s| {
                let s = s.suite();
                u16::from(s.kem) as u64 == vector["kem_id"].as_u64().unwrap()
                    && u16::from(s.sym.kdf_id) as u64 == vector["kdf_id"].as_u64().unwrap()
                    && u16::from(s.sym.aead_id) as u64 == vector["aead_id"].as_u64().unwrap()
            })
            .unwrap();
        let read = |key: &str| hex(vector[key].as_str().unwrap());
        let private: HpkePrivateKey = read("skRm").into();
        let enc = EncapsulatedSecret(read("enc"));
        let info = read("info");
        let mut receiver = suite.setup_opener(&enc, &info, &private).unwrap();
        for message in vector["encryptions"].as_array().unwrap() {
            let read = |key: &str| hex(message[key].as_str().unwrap());
            let plaintext = receiver.open(&read("aad"), &read("ct")).unwrap();
            assert_eq!(plaintext, read("pt"), "{:?}", suite.suite());
        }
        let first = &vector["encryptions"][0];
        let read = |key: &str| hex(first[key].as_str().unwrap());
        assert!(
            suite
                .open(&enc, b"wrong info", &read("aad"), &read("ct"), &private)
                .is_err()
        );
        assert!(
            suite
                .open(&enc, &info, b"wrong aad", &read("ct"), &private)
                .is_err()
        );
        let mut ciphertext = read("ct");
        ciphertext[0] ^= 1;
        assert!(
            suite
                .open(&enc, &info, &read("aad"), &ciphertext, &private)
                .is_err()
        );
    }
}

#[test]
fn all_hpke_suites_roundtrip_sequence_and_reject_invalid_keys_and_tags() {
    assert_eq!(ALL_SUPPORTED_SUITES.len(), 12);
    for suite in ALL_SUPPORTED_SUITES {
        let (public, private) = suite.generate_key_pair().unwrap();
        let (enc, mut sender) = suite.setup_sealer(b"ECH configuration", &public).unwrap();
        let mut receiver = suite
            .setup_opener(&enc, b"ECH configuration", &private)
            .unwrap();
        for payload in [vec![], vec![42; 32], vec![17; 16384]] {
            let ciphertext = sender.seal(b"ClientHelloOuter", &payload).unwrap();
            assert_eq!(
                receiver.open(b"ClientHelloOuter", &ciphertext).unwrap(),
                payload
            );
            assert!(
                receiver.open(b"ClientHelloOuter", &ciphertext).is_err(),
                "replay must fail"
            );
        }
        let (enc, ciphertext) = suite.seal(b"info", b"aad", b"plaintext", &public).unwrap();
        assert_eq!(
            suite
                .open(&enc, b"info", b"aad", &ciphertext, &private)
                .unwrap(),
            b"plaintext"
        );
        for size in [0, 1, 15] {
            assert!(
                suite
                    .setup_sealer(b"info", &rustls::crypto::hpke::HpkePublicKey(vec![0; size]))
                    .is_err()
            );
            assert!(
                suite
                    .setup_opener(&EncapsulatedSecret(vec![0; size]), b"info", &private)
                    .is_err()
            );
            assert!(
                suite
                    .open(
                        &enc,
                        b"info",
                        b"aad",
                        &ciphertext[..size.min(ciphertext.len())],
                        &private
                    )
                    .is_err()
            );
        }
        assert!(
            suite
                .setup_sealer(
                    b"info",
                    &rustls::crypto::hpke::HpkePublicKey(vec![0; public.0.len()])
                )
                .is_err()
        );
    }
}
