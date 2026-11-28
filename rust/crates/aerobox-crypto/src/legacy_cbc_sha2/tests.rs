use super::*;
use rustls::client::LegacyTlsProvider;

fn hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
fn fixtures() -> serde_json::Value {
    serde_json::from_str(include_str!("../../tests/fixtures/ios-cbc-sha2.json")).unwrap()
}
fn algorithm(group: &serde_json::Value) -> &'static Algorithm {
    match (
        group["key_hex"].as_str().unwrap().len(),
        group["digest"].as_str().unwrap(),
    ) {
        (32, "sha256") => &AES128_SHA256,
        (64, "sha256") => &AES256_SHA256,
        (64, "sha384") => &AES256_SHA384,
        _ => panic!("unexpected vector algorithm"),
    }
}
fn cipher(group: &serde_json::Value) -> Cipher {
    Cipher::new(
        algorithm(group),
        &hex(group["key_hex"].as_str().unwrap()),
        &[],
        &hex(group["mac_key_hex"].as_str().unwrap()),
    )
    .unwrap()
}
fn decrypt<'a>(cipher: &mut Cipher, wire: &'a mut [u8], seq: u64) -> Result<&'a [u8], Error> {
    cipher
        .decrypt(
            InboundOpaqueMessage::new(
                rustls::ContentType::ApplicationData,
                ProtocolVersion::TLSv1_2,
                wire,
            ),
            seq,
        )
        .map(|message| message.payload)
}
fn encrypt(cipher: &mut Cipher, plain: &[u8], seq: u64) -> Result<Vec<u8>, Error> {
    cipher
        .encrypt(
            OutboundPlainMessage {
                typ: rustls::ContentType::ApplicationData,
                version: ProtocolVersion::TLSv1_2,
                payload: plain.into(),
            },
            seq,
        )
        .map(|message| message.payload.as_ref().to_vec())
}

#[test]
fn independently_generated_records_cover_every_padding_value_mac_width_and_key_size() {
    let data = fixtures();
    let mut checked = 0;
    for group in data["groups"].as_array().unwrap() {
        let mut accepted_pads = std::collections::BTreeSet::new();
        for vector in group["vectors"].as_array().unwrap() {
            if vector["valid"] != true {
                continue;
            }
            let mut decoder = cipher(group);
            let plain = hex(vector["plaintext_hex"].as_str().unwrap());
            let mut wire = hex(vector["wire_hex"].as_str().unwrap());
            assert_eq!(
                decrypt(
                    &mut decoder,
                    &mut wire,
                    vector["sequence"].as_u64().unwrap()
                )
                .unwrap(),
                plain,
                "{}",
                vector["name"]
            );
            assert!(!decoder.failed);
            if vector["name"].as_str().unwrap().starts_with("padding-") {
                accepted_pads.insert(vector["padding"].as_u64().unwrap());
            }
            checked += 1;
        }
        assert_eq!(accepted_pads, (1..=256).collect());
    }
    assert_eq!(checked, 3 * (256 + 8 + 7));
}

#[test]
fn encryption_and_cross_record_sequence_boundaries_match_independent_known_answers() {
    let data = fixtures();
    for group in data["groups"].as_array().unwrap() {
        let mut seen = std::collections::BTreeMap::new();
        let mut epoch = std::collections::BTreeMap::new();
        for vector in group["vectors"].as_array().unwrap() {
            if vector["derived_iv"] != true {
                continue;
            }
            let plain = hex(vector["plaintext_hex"].as_str().unwrap());
            let sequence = vector["sequence"].as_u64().unwrap();
            // Each known answer is independent, including examples that happen
            // to use the same sequence with different plaintexts.
            let mut encoder = cipher(group);
            let wire = encrypt(&mut encoder, &plain, sequence).unwrap();
            assert_eq!(
                wire,
                hex(vector["wire_hex"].as_str().unwrap()),
                "{}",
                vector["name"]
            );
            assert_eq!(wire.len(), encoder.encrypted_payload_len(plain.len()));
            if let Some(previous) = seen.insert(sequence, wire[..BLOCK].to_vec()) {
                assert_eq!(previous, wire[..BLOCK]);
            }
            assert_eq!(
                decrypt(&mut cipher(group), &mut wire.clone(), sequence).unwrap(),
                plain
            );
            epoch.insert(sequence, (plain, wire));
        }
        let unique_ivs: std::collections::BTreeSet<_> = seen.values().collect();
        assert_eq!(unique_ivs.len(), seen.len());
        // Exercise one directional epoch in increasing sequence order without
        // reusing a sequence. Gaps allow the u32/u64 boundaries to remain small.
        let mut encoder = cipher(group);
        let mut decoder = cipher(group);
        for (sequence, (plain, wire)) in epoch {
            assert_eq!(encrypt(&mut encoder, &plain, sequence).unwrap(), wire);
            assert_eq!(
                decrypt(&mut decoder, &mut wire.clone(), sequence).unwrap(),
                plain
            );
        }
    }
}

#[test]
fn real_bad_mac_bad_padding_and_oversized_plaintext_are_erased_and_retire_the_epoch() {
    let data = fixtures();
    for group in data["groups"].as_array().unwrap() {
        let good = &group["vectors"][0];
        for vector in group["vectors"].as_array().unwrap() {
            if vector["valid"] == true {
                continue;
            }
            let mut decoder = cipher(group);
            let mut wire = hex(vector["wire_hex"].as_str().unwrap());
            assert!(
                matches!(
                    decrypt(
                        &mut decoder,
                        &mut wire,
                        vector["sequence"].as_u64().unwrap()
                    ),
                    Err(Error::DecryptError)
                ),
                "{}",
                vector["name"]
            );
            assert!(decoder.failed);
            // These fixtures have structurally valid, block-aligned ciphertext:
            // wrong MAC, wrong padding, or authenticated 16385-byte content.
            assert!(
                wire[BLOCK..].iter().all(|byte| *byte == 0),
                "{}",
                vector["name"]
            );
            assert!(matches!(
                decrypt(
                    &mut decoder,
                    &mut hex(good["wire_hex"].as_str().unwrap()),
                    good["sequence"].as_u64().unwrap()
                ),
                Err(Error::DecryptError)
            ));
        }
    }
}

#[test]
fn public_header_iv_and_ciphertext_tampering_never_yield_plaintext() {
    let data = fixtures();
    for group in data["groups"].as_array().unwrap() {
        let vector = group["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["name"] == "derived-255")
            .unwrap();
        let good = hex(vector["wire_hex"].as_str().unwrap());
        let seq = vector["sequence"].as_u64().unwrap();
        for index in [0, 15, 16, good.len() / 2, good.len() - 1] {
            let mut corrupted = good.clone();
            corrupted[index] ^= 0x80;
            assert!(decrypt(&mut cipher(group), &mut corrupted, seq).is_err());
        }
        assert!(decrypt(&mut cipher(group), &mut good.clone(), seq + 1).is_err());
        for (typ, version) in [
            (rustls::ContentType::Handshake, ProtocolVersion::TLSv1_2),
            (
                rustls::ContentType::ApplicationData,
                ProtocolVersion::TLSv1_0,
            ),
            (
                rustls::ContentType::ApplicationData,
                ProtocolVersion::TLSv1_1,
            ),
            (
                rustls::ContentType::ApplicationData,
                ProtocolVersion::TLSv1_3,
            ),
        ] {
            let mut decoder = cipher(group);
            let mut bad = good.clone();
            assert!(
                decoder
                    .decrypt(InboundOpaqueMessage::new(typ, version, &mut bad), seq)
                    .is_err()
            );
            assert!(decrypt(&mut decoder, &mut good.clone(), seq).is_err());
        }
    }
}

#[test]
fn malformed_public_lengths_and_outbound_errors_permanently_fail() {
    let data = fixtures();
    for group in data["groups"].as_array().unwrap() {
        let alg = algorithm(group);
        let vector = &group["vectors"][0];
        let good = hex(vector["wire_hex"].as_str().unwrap());
        let seq = vector["sequence"].as_u64().unwrap();
        for size in [
            0,
            1,
            BLOCK,
            BLOCK + alg.digest.size(),
            good.len() - 1,
            BLOCK + MAX_PLAIN + alg.digest.size() + 257,
        ] {
            let mut decoder = cipher(group);
            assert!(decrypt(&mut decoder, &mut vec![0; size], seq).is_err());
            assert!(decrypt(&mut decoder, &mut good.clone(), seq).is_err());
        }
        for version in [
            ProtocolVersion::TLSv1_0,
            ProtocolVersion::TLSv1_1,
            ProtocolVersion::TLSv1_3,
        ] {
            let mut encoder = cipher(group);
            assert!(
                encoder
                    .encrypt(
                        OutboundPlainMessage {
                            typ: rustls::ContentType::ApplicationData,
                            version,
                            payload: b"valid".as_slice().into()
                        },
                        0
                    )
                    .is_err()
            );
            assert!(encrypt(&mut encoder, b"valid", 1).is_err());
        }
        let mut encoder = cipher(group);
        assert!(encrypt(&mut encoder, &vec![0; MAX_PLAIN + 1], 0).is_err());
        assert!(encrypt(&mut encoder, b"valid", 1).is_err());
        for size in [usize::MAX, usize::MAX - alg.digest.size()] {
            assert_eq!(encoder.encrypted_payload_len(size), usize::MAX);
        }
        assert!(encoder.encrypted_payload_len(u32::MAX as usize) >= u32::MAX as usize);
    }
}

#[test]
fn factories_require_exact_directional_mac_keys_and_no_key_block_iv() {
    for alg in [&AES128_SHA256, &AES256_SHA256, &AES256_SHA384] {
        let shape = alg.key_block_shape();
        assert_eq!(shape.enc_key_len, alg.key_len);
        assert_eq!(shape.fixed_iv_len, 0);
        assert_eq!(shape.explicit_nonce_len, 0);
        assert_eq!(alg.mac_key_len(), alg.digest.size());
        for key_len in [0, 15, 16, 24, 31, 32, 33] {
            for mac_len in [0, 20, 31, 32, 33, 47, 48, 49] {
                assert_eq!(
                    Cipher::new(alg, &vec![1; key_len], &[], &vec![2; mac_len]).is_some(),
                    key_len == alg.key_len && mac_len == alg.digest.size()
                );
            }
        }
        assert!(
            Cipher::new(
                alg,
                &vec![1; alg.key_len],
                &[0; 16],
                &vec![2; alg.digest.size()]
            )
            .is_none()
        );
        assert!(alg.extract_keys(AeadKey::from([0; 32]), &[], &[]).is_err());
        let mut decoder = alg.decrypter(AeadKey::from([0; 32]), &[]);
        assert!(
            decoder
                .decrypt(
                    InboundOpaqueMessage::new(
                        rustls::ContentType::ApplicationData,
                        ProtocolVersion::TLSv1_2,
                        &mut [0; 80]
                    ),
                    0
                )
                .is_err()
        );
        let mut encoder = alg.encrypter_with_mac(
            AeadKey::from([0; 32]),
            &[],
            &[0],
            &vec![0; alg.digest.size()],
        );
        assert!(
            encoder
                .encrypt(
                    OutboundPlainMessage {
                        typ: rustls::ContentType::ApplicationData,
                        version: ProtocolVersion::TLSv1_2,
                        payload: b"x".as_slice().into()
                    },
                    0
                )
                .is_err()
        );
    }
}

#[test]
fn all_six_suites_have_the_rfc_prf_hash_kx_and_record_mac_and_stay_opt_in() {
    let data = fixtures();
    for (suite, id, key_len, mac_len, rsa) in [
        (
            &TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
            0xc023u16,
            16,
            32,
            false,
        ),
        (
            &TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
            0xc024,
            32,
            48,
            false,
        ),
        (
            &TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
            0xc027,
            16,
            32,
            false,
        ),
        (
            &TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
            0xc028,
            32,
            48,
            false,
        ),
        (&TLS_RSA_WITH_AES_128_CBC_SHA256, 0x003c, 16, 32, true),
        (&TLS_RSA_WITH_AES_256_CBC_SHA256, 0x003d, 32, 32, true),
    ] {
        assert_eq!(u16::from(suite.common.suite), id);
        assert_eq!(suite.aead_alg.key_block_shape().enc_key_len, key_len);
        assert_eq!(suite.aead_alg.mac_key_len(), mac_len);
        assert_eq!(suite.common.hash_provider.output_len(), mac_len);
        assert_eq!(
            suite.kx,
            if rsa {
                rustls::crypto::KeyExchangeAlgorithm::RSA
            } else {
                rustls::crypto::KeyExchangeAlgorithm::ECDHE
            }
        );
        let digest = if mac_len == 48 { "sha384" } else { "sha256" };
        let vector = data["prfs"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["digest"] == digest)
            .unwrap();
        let expected = hex(vector["output_hex"].as_str().unwrap());
        let mut actual = vec![0; expected.len()];
        suite.prf_provider.for_secret(
            &mut actual,
            &hex(vector["secret_hex"].as_str().unwrap()),
            &hex(vector["label_hex"].as_str().unwrap()),
            &hex(vector["seed_hex"].as_str().unwrap()),
        );
        assert_eq!(actual, expected, "suite {id:04x}");
        assert_eq!(
            suite
                .common
                .hash_provider
                .hash(&hex(vector["transcript_hex"].as_str().unwrap()))
                .as_ref(),
            hex(vector["transcript_hash_hex"].as_str().unwrap())
        );
        let supported = SupportedCipherSuite::Tls12(suite);
        assert_eq!(supported.version().version, ProtocolVersion::TLSv1_2);
        assert!(!crate::provider().cipher_suites.contains(&supported));
        assert!(
            !crate::legacy_provider::provider()
                .cipher_suites
                .contains(&supported)
        );
        for version in [ProtocolVersion::TLSv1_0, ProtocolVersion::TLSv1_1] {
            assert!(
                crate::legacy_provider::LEGACY_TLS
                    .cipher_suite(suite.common.suite, version)
                    .is_none()
            );
        }
    }
    assert_eq!(suites().len(), 6);
}
