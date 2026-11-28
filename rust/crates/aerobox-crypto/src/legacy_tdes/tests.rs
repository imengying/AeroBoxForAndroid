use super::*;
use rustls::{ContentType, SignatureAlgorithm, SignatureScheme, pki_types::CertificateDer};
use serde_json::Value;

const VERSIONS: [ProtocolVersion; 3] = [
    ProtocolVersion::TLSv1_0,
    ProtocolVersion::TLSv1_1,
    ProtocolVersion::TLSv1_2,
];

fn hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn fixtures() -> Value {
    serde_json::from_str(include_str!(
        "../../tests/fixtures/tdes-reference/vectors.json"
    ))
    .unwrap()
}

fn version(vector: &Value) -> ProtocolVersion {
    ProtocolVersion::from(u16::try_from(vector["version"].as_u64().unwrap()).unwrap())
}

fn cipher(data: &Value, version: ProtocolVersion) -> Cipher {
    let iv = if version == ProtocolVersion::TLSv1_0 {
        hex(data["iv"].as_str().unwrap())
    } else {
        Vec::new()
    };
    Cipher::new(
        &hex(data["key"].as_str().unwrap()),
        &iv,
        &hex(data["mac"].as_str().unwrap()),
        version,
    )
    .unwrap()
}

fn implicit_iv(cipher: &Cipher) -> Option<[u8; BLOCK]> {
    match &cipher.iv {
        RecordIv::Implicit(iv) => Some(**iv),
        RecordIv::Explicit(_) => None,
    }
}

fn encrypt(cipher: &mut Cipher, plain: &[u8], seq: u64) -> Result<Vec<u8>, Error> {
    cipher
        .encrypt(
            OutboundPlainMessage {
                typ: ContentType::ApplicationData,
                version: cipher.version,
                payload: plain.into(),
            },
            seq,
        )
        .map(|record| record.payload.as_ref().to_vec())
}

fn decrypt<'a>(cipher: &mut Cipher, wire: &'a mut [u8], seq: u64) -> Result<&'a [u8], Error> {
    cipher
        .decrypt(
            InboundOpaqueMessage::new(ContentType::ApplicationData, cipher.version, wire),
            seq,
        )
        .map(|record| record.payload)
}

fn first_record(data: &Value, wanted: ProtocolVersion) -> &Value {
    data["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|vector| version(vector) == wanted && vector["sequence"] == 0)
        .unwrap()
}

#[test]
fn primitive_matches_independent_tdes_known_answer_and_keys_have_zeroize_on_drop() {
    // The feature contract must hold for both the traffic key and IV PRP key.
    fn requires_zeroizing_drop<T: zeroize::ZeroizeOnDrop>() {}
    requires_zeroizing_drop::<des::TdesEde3>();
    let data = fixtures();
    let tdes = des::TdesEde3::new_from_slice(&hex(data["key"].as_str().unwrap())).unwrap();
    let input: [u8; BLOCK] = hex(data["primitive"]["plaintext"].as_str().unwrap())
        .try_into()
        .unwrap();
    let mut block = input;
    tdes.encrypt_block((&mut block).into());
    assert_eq!(
        block.as_slice(),
        hex(data["primitive"]["ciphertext"].as_str().unwrap())
    );
    tdes.decrypt_block((&mut block).into());
    assert_eq!(block, input);
}

#[test]
fn independent_sequential_records_hold_iv_chains_mac_headers_and_block_counts() {
    let data = fixtures();
    let mut checked = 0;
    for wanted in VERSIONS {
        let mut encoder = cipher(&data, wanted);
        let mut decoder = cipher(&data, wanted);
        let mut blocks = 0;
        let mut ivs = std::collections::BTreeSet::new();
        for vector in data["records"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|vector| version(vector) == wanted)
        {
            let seq = vector["sequence"].as_u64().unwrap();
            let plain = hex(vector["plain"].as_str().unwrap());
            let expected = hex(vector["ciphertext"].as_str().unwrap());
            assert_eq!(encrypt(&mut encoder, &plain, seq).unwrap(), expected);
            assert_eq!(encoder.encrypted_payload_len(plain.len()), expected.len());
            assert_eq!(
                decrypt(&mut decoder, &mut expected.clone(), seq).unwrap(),
                plain
            );
            blocks += ((expected.len() - encoder.explicit_len()) / BLOCK) as u64;
            assert_eq!(encoder.blocks, blocks);
            assert_eq!(decoder.blocks, blocks);
            assert!(!encoder.failed && !decoder.failed);
            if wanted == ProtocolVersion::TLSv1_0 {
                let last = expected[expected.len() - BLOCK..].try_into().unwrap();
                assert_eq!(implicit_iv(&encoder), Some(last));
                assert_eq!(implicit_iv(&decoder), Some(last));
                // A fresh receiver has the wrong chaining IV after the first
                // record. Its failure cannot advance the stored chain.
                if seq != 0 {
                    let mut fresh = cipher(&data, wanted);
                    let initial = implicit_iv(&fresh);
                    let mut wire = expected.clone();
                    assert!(decrypt(&mut fresh, &mut wire, seq).is_err());
                    assert_eq!(implicit_iv(&fresh), initial);
                    assert!(wire.iter().all(|byte| *byte == 0));
                }
            } else {
                assert!(ivs.insert(expected[..BLOCK].to_vec()));
                // TLS1.1/1.2 use the IV on the wire: no previous record state.
                assert_eq!(
                    decrypt(&mut cipher(&data, wanted), &mut expected.clone(), seq).unwrap(),
                    plain
                );
            }
            checked += 1;
        }
    }
    assert_eq!(checked, 27);
}

#[test]
fn all_256_padding_sizes_per_version_match_independent_ciphertexts() {
    let data = fixtures();
    let mut seen = std::collections::BTreeSet::new();
    for vector in data["padding"].as_array().unwrap() {
        let wanted = version(vector);
        let mut decoder = cipher(&data, wanted);
        let mut wire = hex(vector["ciphertext"].as_str().unwrap());
        let expected_blocks = ((wire.len() - decoder.explicit_len()) / BLOCK) as u64;
        assert_eq!(
            decrypt(&mut decoder, &mut wire, 42).unwrap(),
            hex(vector["plain"].as_str().unwrap())
        );
        assert_eq!(decoder.blocks, expected_blocks);
        assert!(!decoder.failed);
        assert!(seen.insert((u16::from(wanted), vector["padding"].as_u64().unwrap())));
    }
    assert_eq!(seen.len(), 3 * 256);
    for wanted in VERSIONS {
        for pad in 1..=256 {
            assert!(seen.contains(&(u16::from(wanted), pad)));
        }
    }
}

#[test]
fn independent_invalid_mac_and_padding_are_erased_and_permanently_fail() {
    let data = fixtures();
    let invalid = data["invalid"].as_array().unwrap();
    assert_eq!(invalid.len(), 6);
    for vector in invalid {
        let wanted = version(vector);
        let mut decoder = cipher(&data, wanted);
        let original_iv = implicit_iv(&decoder);
        let mut wire = hex(vector["ciphertext"].as_str().unwrap());
        let explicit = decoder.explicit_len();
        let public_iv = wire[..explicit].to_vec();
        let blocks = ((wire.len() - explicit) / BLOCK) as u64;
        assert!(matches!(
            decrypt(&mut decoder, &mut wire, 42),
            Err(Error::DecryptError)
        ));
        assert!(decoder.failed);
        assert_eq!(decoder.blocks, blocks);
        assert_eq!(implicit_iv(&decoder), original_iv);
        assert_eq!(wire[..explicit], public_iv);
        assert!(wire[explicit..].iter().all(|byte| *byte == 0));
        let good = hex(first_record(&data, wanted)["ciphertext"].as_str().unwrap());
        let mut retry = good.clone();
        assert!(decrypt(&mut decoder, &mut retry, 0).is_err());
        // The failed direction never decrypts a later input at all.
        assert_eq!(retry, good);
        assert_eq!(decoder.blocks, blocks);
        assert_eq!(implicit_iv(&decoder), original_iv);
    }
}

#[test]
fn sequence_record_type_version_and_iv_tampering_cannot_release_plaintext() {
    let data = fixtures();
    for wanted in VERSIONS {
        let vector = data["padding"]
            .as_array()
            .unwrap()
            .iter()
            .find(|vector| version(vector) == wanted && vector["padding"] == 256)
            .unwrap();
        let good = hex(vector["ciphertext"].as_str().unwrap());
        for wrong_sequence in [0, 41, 43, u32::MAX as u64, (1u64 << 32) + 42, u64::MAX] {
            let mut decoder = cipher(&data, wanted);
            let mut wire = good.clone();
            assert!(decrypt(&mut decoder, &mut wire, wrong_sequence).is_err());
            assert!(wire[decoder.explicit_len()..].iter().all(|byte| *byte == 0));
            assert!(decrypt(&mut decoder, &mut good.clone(), 42).is_err());
        }
        for typ in [
            ContentType::Handshake,
            ContentType::Alert,
            ContentType::ChangeCipherSpec,
        ] {
            let mut decoder = cipher(&data, wanted);
            let mut wire = good.clone();
            assert!(
                decoder
                    .decrypt(InboundOpaqueMessage::new(typ, wanted, &mut wire), 42)
                    .is_err()
            );
            assert!(wire[decoder.explicit_len()..].iter().all(|byte| *byte == 0));
            assert!(decrypt(&mut decoder, &mut good.clone(), 42).is_err());
        }
        for wrong in [
            ProtocolVersion::SSLv3,
            ProtocolVersion::TLSv1_0,
            ProtocolVersion::TLSv1_1,
            ProtocolVersion::TLSv1_2,
            ProtocolVersion::TLSv1_3,
            ProtocolVersion::Unknown(0xffff),
        ] {
            if wrong == wanted {
                continue;
            }
            let mut decoder = cipher(&data, wanted);
            let mut wire = good.clone();
            assert!(
                decoder
                    .decrypt(
                        InboundOpaqueMessage::new(ContentType::ApplicationData, wrong, &mut wire),
                        42
                    )
                    .is_err()
            );
            assert!(decoder.failed);
            assert_eq!(decoder.blocks, 0);
            assert_eq!(wire, good); // Public header rejected before decryption.
            assert!(decrypt(&mut decoder, &mut good.clone(), 42).is_err());
        }
        for index in [0, BLOCK - 1, BLOCK, good.len() / 2, good.len() - 1] {
            let mut decoder = cipher(&data, wanted);
            let mut wire = good.clone();
            wire[index] ^= 0x80;
            assert!(decrypt(&mut decoder, &mut wire, 42).is_err());
            assert!(wire[decoder.explicit_len()..].iter().all(|byte| *byte == 0));
            assert!(decoder.failed);
        }
    }
}

#[test]
fn malformed_lengths_and_outbound_failure_latch_without_advancing_keys_or_budget() {
    let data = fixtures();
    for wanted in VERSIONS {
        let good = hex(first_record(&data, wanted)["ciphertext"].as_str().unwrap());
        let explicit = cipher(&data, wanted).explicit_len();
        for size in [
            0,
            1,
            explicit,
            explicit + 2 * BLOCK,
            good.len() - 1,
            explicit + MAX_PLAIN + MAC_SIZE + 257,
        ] {
            let mut decoder = cipher(&data, wanted);
            let initial = implicit_iv(&decoder);
            assert!(decrypt(&mut decoder, &mut vec![0; size], 0).is_err());
            assert!(decoder.failed);
            assert_eq!(decoder.blocks, 0);
            assert_eq!(implicit_iv(&decoder), initial);
            assert!(decrypt(&mut decoder, &mut good.clone(), 0).is_err());
        }
        let mut encoder = cipher(&data, wanted);
        let initial = implicit_iv(&encoder);
        assert!(encrypt(&mut encoder, &vec![0; MAX_PLAIN + 1], 0).is_err());
        assert!(encoder.failed);
        assert_eq!(encoder.blocks, 0);
        assert_eq!(implicit_iv(&encoder), initial);
        assert!(encrypt(&mut encoder, b"valid", 1).is_err());
        for wrong in VERSIONS.into_iter().chain([ProtocolVersion::TLSv1_3]) {
            if wrong == wanted {
                continue;
            }
            let mut encoder = cipher(&data, wanted);
            assert!(
                encoder
                    .encrypt(
                        OutboundPlainMessage {
                            typ: ContentType::ApplicationData,
                            version: wrong,
                            payload: b"x".as_slice().into(),
                        },
                        0
                    )
                    .is_err()
            );
            assert_eq!(encoder.blocks, 0);
            assert!(encoder.failed);
            assert!(encrypt(&mut encoder, b"valid", 1).is_err());
        }
        for size in [
            usize::MAX,
            usize::MAX - MAC_SIZE,
            usize::MAX - MAC_SIZE - BLOCK + 1,
        ] {
            assert_eq!(encoder.encrypted_payload_len(size), usize::MAX);
        }
        assert!(encoder.encrypted_payload_len(u32::MAX as usize) >= u32::MAX as usize);
    }
}

#[test]
fn block_budget_accepts_the_last_exact_record_then_latches_and_never_wraps() {
    let data = fixtures();
    for wanted in VERSIONS {
        let good = hex(first_record(&data, wanted)["ciphertext"].as_str().unwrap());
        let explicit = cipher(&data, wanted).explicit_len();
        let used = ((good.len() - explicit) / BLOCK) as u64;
        assert_eq!(used, 3); // Empty content still consumes MAC and padding blocks.
        let mut encoder = cipher(&data, wanted);
        encoder.blocks = MAX_BLOCKS - used;
        assert_eq!(encrypt(&mut encoder, b"", 0).unwrap(), good);
        assert_eq!(encoder.blocks, MAX_BLOCKS);
        assert!(!encoder.failed);
        let final_iv = implicit_iv(&encoder);
        assert!(encrypt(&mut encoder, b"", 1).is_err());
        assert!(encoder.failed);
        assert_eq!(encoder.blocks, MAX_BLOCKS);
        assert_eq!(implicit_iv(&encoder), final_iv);

        let mut decoder = cipher(&data, wanted);
        decoder.blocks = MAX_BLOCKS - used;
        assert_eq!(decrypt(&mut decoder, &mut good.clone(), 0).unwrap(), b"");
        assert_eq!(decoder.blocks, MAX_BLOCKS);
        assert!(!decoder.failed);
        let final_iv = implicit_iv(&decoder);
        let mut untouched = good.clone();
        assert!(decrypt(&mut decoder, &mut untouched, 0).is_err());
        assert_eq!(untouched, good);
        assert!(decoder.failed);
        assert_eq!(decoder.blocks, MAX_BLOCKS);
        assert_eq!(implicit_iv(&decoder), final_iv);

        for count in [MAX_BLOCKS - used + 1, MAX_BLOCKS, u64::MAX - 1, u64::MAX] {
            let mut encoder = cipher(&data, wanted);
            encoder.blocks = count;
            let initial = implicit_iv(&encoder);
            assert!(encrypt(&mut encoder, b"", 0).is_err());
            assert!(encoder.failed);
            assert_eq!(encoder.blocks, count);
            assert_eq!(implicit_iv(&encoder), initial);
            // Resetting a count cannot revive a retired direction.
            encoder.blocks = 0;
            assert!(encrypt(&mut encoder, b"", 0).is_err());

            let mut decoder = cipher(&data, wanted);
            decoder.blocks = count;
            let mut wire = good.clone();
            assert!(decrypt(&mut decoder, &mut wire, 0).is_err());
            assert_eq!(wire, good);
            assert!(decoder.failed);
            assert_eq!(decoder.blocks, count);
            decoder.blocks = 0;
            assert!(decrypt(&mut decoder, &mut good.clone(), 0).is_err());
        }
    }
}

#[test]
fn budget_counts_all_padding_blocks_but_not_public_explicit_iv() {
    let data = fixtures();
    for wanted in VERSIONS {
        let vector = data["padding"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| version(v) == wanted && v["padding"] == 256)
            .unwrap();
        let good = hex(vector["ciphertext"].as_str().unwrap());
        let mut decoder = cipher(&data, wanted);
        let used = ((good.len() - decoder.explicit_len()) / BLOCK) as u64;
        assert_eq!(used, 35);
        decoder.blocks = MAX_BLOCKS - used;
        assert_eq!(
            decrypt(&mut decoder, &mut good.clone(), 42).unwrap(),
            hex(vector["plain"].as_str().unwrap())
        );
        assert_eq!(decoder.blocks, MAX_BLOCKS);
        let mut decoder = cipher(&data, wanted);
        decoder.blocks = MAX_BLOCKS - used + 1;
        let mut wire = good.clone();
        assert!(decrypt(&mut decoder, &mut wire, 42).is_err());
        assert_eq!(wire, good);
        assert!(decoder.failed);
    }
}

#[test]
fn explicit_iv_permutation_separates_direction_keys_and_full_u64_sequence() {
    let data = fixtures();
    for wanted in [ProtocolVersion::TLSv1_1, ProtocolVersion::TLSv1_2] {
        let original = cipher(&data, wanted);
        let mut key = hex(data["key"].as_str().unwrap());
        let mut mac = hex(data["mac"].as_str().unwrap());
        key[0] ^= 2; // A DES key bit, not its parity bit.
        let other_key = Cipher::new(&key, &[], &mac, wanted).unwrap();
        key[0] ^= 2;
        mac[0] ^= 1;
        let other_direction = Cipher::new(&key, &[], &mac, wanted).unwrap();
        let mut seen = std::collections::BTreeSet::new();
        for seq in [0, 1, 255, 256, u32::MAX as u64, 1u64 << 32, u64::MAX] {
            let iv = original.iv(seq);
            assert!(seen.insert(iv));
            assert_ne!(iv, seq.to_be_bytes());
            assert_ne!(iv, other_key.iv(seq));
            assert_ne!(iv, other_direction.iv(seq));
        }
    }
}

#[test]
fn factories_enforce_exact_24_byte_keys_mac_iv_and_version_shapes() {
    for wanted in VERSIONS {
        let alg = algorithm_for_version(wanted).unwrap();
        let shape = alg.key_block_shape();
        let iv_len = if wanted == ProtocolVersion::TLSv1_0 {
            BLOCK
        } else {
            0
        };
        assert_eq!(shape.enc_key_len, KEY);
        assert_eq!(shape.fixed_iv_len, iv_len);
        assert_eq!(shape.explicit_nonce_len, 0);
        assert_eq!(alg.mac_key_len(), MAC_SIZE);
        for key_len in [0, 8, 16, 23, 24, 25, 32] {
            for mac_len in [0, 19, 20, 21, 32] {
                for fixed_iv in [0, 7, 8, 9, 16] {
                    assert_eq!(
                        Cipher::new(
                            &vec![1; key_len],
                            &vec![2; fixed_iv],
                            &vec![3; mac_len],
                            wanted
                        )
                        .is_some(),
                        key_len == KEY && mac_len == MAC_SIZE && fixed_iv == iv_len
                    );
                }
            }
        }
        assert!(alg.extract_keys(AeadKey::from([0; 32]), &[], &[]).is_err());
        // AeadKey's public constructor only makes 32-byte keys; rustls owns
        // actual 24-byte key-block slicing. Live handshake validation must
        // cover that successful factory path separately.
        let mut encoder = alg.encrypter_with_mac(
            AeadKey::from([0; 32]),
            &vec![0; iv_len],
            &[],
            &[0; MAC_SIZE],
        );
        assert!(
            encoder
                .encrypt(
                    OutboundPlainMessage {
                        typ: ContentType::ApplicationData,
                        version: wanted,
                        payload: b"x".as_slice().into()
                    },
                    0
                )
                .is_err()
        );
        let mut decoder =
            alg.decrypter_with_mac(AeadKey::from([0; 32]), &vec![0; iv_len], &[0; MAC_SIZE]);
        assert!(
            decoder
                .decrypt(
                    InboundOpaqueMessage::new(ContentType::ApplicationData, wanted, &mut [0; 32]),
                    0
                )
                .is_err()
        );
        let mut encoder = alg.encrypter(AeadKey::from([0; 32]), &vec![0; iv_len], &[]);
        assert!(
            encoder
                .encrypt(
                    OutboundPlainMessage {
                        typ: ContentType::ApplicationData,
                        version: wanted,
                        payload: b"x".as_slice().into()
                    },
                    0
                )
                .is_err()
        );
        let mut decoder = alg.decrypter(AeadKey::from([0; 32]), &vec![0; iv_len]);
        assert!(
            decoder
                .decrypt(
                    InboundOpaqueMessage::new(ContentType::ApplicationData, wanted, &mut [0; 32]),
                    0
                )
                .is_err()
        );
    }
    for version in [
        ProtocolVersion::SSLv3,
        ProtocolVersion::TLSv1_3,
        ProtocolVersion::Unknown(0xffff),
    ] {
        assert!(algorithm_for_version(version).is_none());
        assert!(Cipher::new(&[0; KEY], &[], &[0; MAC_SIZE], version).is_none());
    }
}

#[test]
fn suites_are_opt_in_and_legacy_mapping_has_correct_hash_prf_signature_and_iv() {
    use rustls::crypto::{KeyExchangeAlgorithm, hash::HashAlgorithm};
    let ordinary = crate::provider();
    let android = crate::legacy_provider::provider();
    assert_eq!(suites().len(), 3);
    for (base, id, kx, signature) in [
        (
            &TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
            0xc012u16,
            KeyExchangeAlgorithm::ECDHE,
            SignatureScheme::RSA_PKCS1_MD5_SHA1_Legacy,
        ),
        (
            &TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
            0xc008,
            KeyExchangeAlgorithm::ECDHE,
            SignatureScheme::ECDSA_SHA1_Legacy,
        ),
        (
            &TLS_RSA_WITH_3DES_EDE_CBC_SHA,
            0x000a,
            KeyExchangeAlgorithm::RSA,
            SignatureScheme::RSA_PKCS1_MD5_SHA1_Legacy,
        ),
    ] {
        let supported = SupportedCipherSuite::Tls12(base);
        assert_eq!(u16::from(base.common.suite), id);
        assert_eq!(base.kx, kx);
        assert_eq!(base.common.hash_provider.algorithm(), HashAlgorithm::SHA256);
        assert_eq!(base.common.confidentiality_limit, MAX_BLOCKS / 3);
        assert_eq!(supported.version().version, ProtocolVersion::TLSv1_2);
        assert!(!ordinary.cipher_suites.contains(&supported));
        assert!(!android.cipher_suites.contains(&supported));
        // Independently generated Python HMAC PRFs, not a comparison with
        // another instance of this crate's PRF implementation.
        let mut prf = [0; 48];
        base.prf_provider.for_secret(
            &mut prf,
            b"independent 3DES fixture",
            b"master secret",
            b"client random/server random",
        );
        assert_eq!(
            prf.as_slice(),
            hex(
                "a6eaa86f85b22e70f92e13002a31a507a81068485f1caf653a820e96b3f7852a18cf357efe63b9b1bbefd5e8d53211ce"
            )
        );
        for version in [ProtocolVersion::TLSv1_0, ProtocolVersion::TLSv1_1] {
            assert!(
                crate::legacy_provider::LEGACY_TLS
                    .cipher_suite(base.common.suite, version)
                    .is_none()
            );
            let old = LEGACY_TLS_WITH_TDES
                .cipher_suite(base.common.suite, version)
                .unwrap();
            assert_eq!(old.common.suite, base.common.suite);
            assert_eq!(old.kx, kx);
            assert_eq!(old.sign, &[signature]);
            assert_eq!(
                old.common.hash_provider.algorithm(),
                HashAlgorithm::MD5_SHA1
            );
            assert_eq!(old.common.hash_provider.output_len(), 36);
            assert_eq!(old.common.confidentiality_limit, MAX_BLOCKS / 3);
            assert_eq!(old.aead_alg.mac_key_len(), MAC_SIZE);
            let shape = old.aead_alg.key_block_shape();
            assert_eq!(shape.enc_key_len, KEY);
            assert_eq!(
                shape.fixed_iv_len,
                if version == ProtocolVersion::TLSv1_0 {
                    BLOCK
                } else {
                    0
                }
            );
            assert_eq!(shape.explicit_nonce_len, 0);
            old.prf_provider.for_secret(
                &mut prf,
                b"independent 3DES fixture",
                b"master secret",
                b"client random/server random",
            );
            assert_eq!(
                prf.as_slice(),
                hex(
                    "32cd878238fad16ed2ea83842cb2530849a40289a976c5559c7989c7228463436c0087df60ebdf701954b932ef7dde3b"
                )
            );
        }
        for version in [
            ProtocolVersion::SSLv3,
            ProtocolVersion::TLSv1_2,
            ProtocolVersion::TLSv1_3,
        ] {
            assert!(
                LEGACY_TLS_WITH_TDES
                    .cipher_suite(base.common.suite, version)
                    .is_none()
            );
        }
    }
    for version in [ProtocolVersion::TLSv1_0, ProtocolVersion::TLSv1_1] {
        for id in [0xc013u16, 0xc014, 0xc009, 0xc00a, 0x002f, 0x0035] {
            let id = CipherSuite::from(id);
            assert!(std::ptr::eq(
                LEGACY_TLS_WITH_TDES.cipher_suite(id, version).unwrap(),
                crate::legacy_provider::LEGACY_TLS
                    .cipher_suite(id, version)
                    .unwrap()
            ));
        }
        for id in [0xc02bu16, 0xc023, 0x003d, 0x009c, 0x1301, 0xffff] {
            assert!(
                LEGACY_TLS_WITH_TDES
                    .cipher_suite(CipherSuite::from(id), version)
                    .is_none()
            );
        }
    }
}

#[test]
fn legacy_provider_signature_delegation_keeps_authentication_and_algorithm_checks() {
    let message = include_bytes!("../legacy_sign/fixtures/message.bin");
    let signature = include_bytes!("../legacy_sign/fixtures/rsa-md5-sha1.sig");
    let rsa = CertificateDer::from(include_bytes!("../../tests/fixtures/rsa-cert.der").as_slice());
    let ecdsa =
        CertificateDer::from(include_bytes!("../../tests/fixtures/ecdsa-cert.der").as_slice());
    LEGACY_TLS_WITH_TDES
        .verify_signature(message, &rsa, SignatureAlgorithm::RSA, signature)
        .unwrap();
    assert!(
        LEGACY_TLS_WITH_TDES
            .verify_signature(b"changed", &rsa, SignatureAlgorithm::RSA, signature)
            .is_err()
    );
    assert!(
        LEGACY_TLS_WITH_TDES
            .verify_signature(message, &ecdsa, SignatureAlgorithm::RSA, signature)
            .is_err()
    );
    assert!(
        LEGACY_TLS_WITH_TDES
            .verify_signature(message, &rsa, SignatureAlgorithm::ECDSA, signature)
            .is_err()
    );
    assert!(
        LEGACY_TLS_WITH_TDES
            .verify_signature(message, &rsa, SignatureAlgorithm::Unknown(0xff), signature)
            .is_err()
    );
}
