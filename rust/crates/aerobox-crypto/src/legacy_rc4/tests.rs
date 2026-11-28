use super::*;
use rustls::crypto::cipher::OutboundChunks;
use serde_json::Value;

const VERSIONS: [ProtocolVersion; 3] = [
    ProtocolVersion::TLSv1_0,
    ProtocolVersion::TLSv1_1,
    ProtocolVersion::TLSv1_2,
];
const KEY: [u8; KEY_SIZE] = *b"0123456789abcdef";
const MAC: [u8; MAC_SIZE] = *b"0123456789abcdefghij";
const RFC: &str = include_str!("../../tests/fixtures/rc4/rfc6229-vectors.json");

fn hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
fn fresh(version: ProtocolVersion) -> Cipher {
    Cipher::new(&KEY, &MAC, version).unwrap()
}
fn seal(cipher: &mut Cipher, typ: ContentType, plain: &[u8], seq: u64) -> Result<Vec<u8>, Error> {
    cipher
        .encrypt(
            OutboundPlainMessage {
                typ,
                version: cipher.version,
                payload: plain.into(),
            },
            seq,
        )
        .map(|record| record.payload.as_ref().to_vec())
}
fn open<'a>(
    cipher: &mut Cipher,
    typ: ContentType,
    wire: &'a mut [u8],
    seq: u64,
) -> Result<&'a [u8], Error> {
    cipher
        .decrypt(InboundOpaqueMessage::new(typ, cipher.version, wire), seq)
        .map(|record| record.payload)
}
fn retired(cipher: &mut Cipher, good: &[u8]) {
    assert!(cipher.active.is_none());
    let mut untouched = good.to_vec();
    assert!(matches!(
        open(cipher, ContentType::ApplicationData, &mut untouched, 0),
        Err(Error::DecryptError)
    ));
    assert_eq!(untouched, good, "retired stream does not decrypt again");
    assert!(matches!(
        seal(cipher, ContentType::ApplicationData, b"retry", 0),
        Err(Error::EncryptError)
    ));
}

#[test]
fn rfc6229_all_252_answers_and_owned_state_zeroize_contract() {
    fn zeroizing<T: zeroize::ZeroizeOnDrop>() {}
    zeroizing::<rc4::Rc4>();
    zeroizing::<Zeroizing<[u8; MAC_SIZE]>>();
    let data: Value = serde_json::from_str(RFC).unwrap();
    let cases = data["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 14);
    let mut checked = 0;
    for case in cases {
        let key = hex(case["key_hex"].as_str().unwrap());
        assert_eq!(key.len() * 8, case["key_bits"].as_u64().unwrap() as usize);
        let mut cipher = rc4::Rc4::new_from_slice(&key).unwrap();
        let mut stream = [0; 4112];
        cipher.try_apply_keystream(&mut stream).unwrap();
        assert_eq!(case["rows"].as_array().unwrap().len(), 18);
        for row in case["rows"].as_array().unwrap() {
            let offset = row["offset"].as_u64().unwrap() as usize;
            assert_eq!(
                &stream[offset..offset + 16],
                hex(row["keystream"].as_str().unwrap())
            );
            checked += 1;
        }
    }
    assert_eq!(checked, 252);
}

#[test]
#[ignore = "requires independently generated AEROBOX_RC4_RECORD_VECTORS JSON; see validation-plan.md"]
fn independent_go_records_cover_both_directions_new_epochs_and_all_versions() {
    use sha2::{Digest, Sha256};
    let file =
        std::env::var_os("AEROBOX_RC4_RECORD_VECTORS").expect("independent Go vectors required");
    let data: Value = serde_json::from_slice(&std::fs::read(file).unwrap()).unwrap();
    let hash: String = Sha256::digest(RFC.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(
        data["generator"],
        "Go standard crypto/rc4 + crypto/hmac + crypto/sha1; TLS1.0/1.1/1.2"
    );
    assert_eq!(data["rfc_vectors_sha256"], hash);
    assert_eq!(data["verified_rfc_values"], 252);
    let epochs = data["epochs"].as_array().unwrap();
    assert_eq!(epochs.len(), 12);
    let mut seen = std::collections::BTreeSet::new();
    let mut checked = 0;
    for epoch in epochs {
        let version_id = u16::try_from(epoch["version"].as_u64().unwrap()).unwrap();
        let version = ProtocolVersion::from(version_id);
        assert!(VERSIONS.contains(&version));
        let name = epoch["name"].as_str().unwrap();
        assert!(
            [
                "client-write",
                "server-write",
                "client-renegotiated",
                "server-renegotiated"
            ]
            .contains(&name)
        );
        assert!(seen.insert((version_id, name)));
        let key = hex(epoch["key_hex"].as_str().unwrap());
        let mac = hex(epoch["mac_key_hex"].as_str().unwrap());
        let mut encoder = Cipher::new(&key, &mac, version).unwrap();
        let mut decoder = Cipher::new(&key, &mac, version).unwrap();
        let records = epoch["records"].as_array().unwrap();
        assert_eq!(records.len(), 9);
        for (seq, record) in records.iter().enumerate() {
            assert_eq!(record["sequence"], seq);
            let typ =
                ContentType::from(u8::try_from(record["content_type"].as_u64().unwrap()).unwrap());
            let plain = hex(record["plaintext_hex"].as_str().unwrap());
            assert_eq!(plain.len(), [16, 0, 1, 15, 16, 17, 127, 16384, 2][seq]);
            assert_eq!(
                typ,
                if seq == 0 {
                    ContentType::Handshake
                } else if seq == 8 {
                    ContentType::Alert
                } else {
                    ContentType::ApplicationData
                }
            );
            let expected = hex(record["ciphertext_hex"].as_str().unwrap());
            assert_eq!(expected.len(), plain.len() + MAC_SIZE);
            assert_eq!(
                encoder
                    .active
                    .as_ref()
                    .unwrap()
                    .tag(seq as u64, typ, version, &plain)
                    .unwrap()
                    .as_slice(),
                hex(record["mac_hex"].as_str().unwrap())
            );
            assert_eq!(
                seal(&mut encoder, typ, &plain, seq as u64).unwrap(),
                expected
            );
            let mut wire = expected.clone();
            assert_eq!(
                open(&mut decoder, typ, &mut wire, seq as u64).unwrap(),
                plain
            );
            assert!(
                wire[plain.len()..].iter().all(|b| *b == 0),
                "successful decrypted MAC erased"
            );
            assert_eq!(encoder.next_seq, seq as u64 + 1);
            assert_eq!(decoder.next_seq, seq as u64 + 1);
            checked += 1;
        }
    }
    assert_eq!(seen.len(), 12);
    assert_eq!(checked, 108);
}

#[test]
fn record_boundaries_continue_stream_and_scattered_payloads_match() {
    // Behavioral tests below use this implementation in both directions;
    // independent known answers are the RFC and external Go test above.
    for version in VERSIONS {
        let mut sender = fresh(version);
        let mut receiver = fresh(version);
        for (seq, len) in [0, 1, 15, 16, 17, 255, MAX_PLAIN, 2]
            .into_iter()
            .enumerate()
        {
            let plain: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let mut wire = seal(
                &mut sender,
                ContentType::ApplicationData,
                &plain,
                seq as u64,
            )
            .unwrap();
            assert_eq!(
                wire.len(),
                len + MAC_SIZE,
                "no IV or padding in any version"
            );
            assert_eq!(
                open(
                    &mut receiver,
                    ContentType::ApplicationData,
                    &mut wire,
                    seq as u64
                )
                .unwrap(),
                plain
            );
        }
        let chunks: &[&[u8]] = &[b"", b"first", b"", b"second", b"last", b""];
        let mut scattered = fresh(version);
        let record = scattered
            .encrypt(
                OutboundPlainMessage {
                    typ: ContentType::ApplicationData,
                    version,
                    payload: OutboundChunks::new(chunks),
                },
                0,
            )
            .unwrap();
        let mut flat = fresh(version);
        assert_eq!(
            record.payload.as_ref(),
            seal(
                &mut flat,
                ContentType::ApplicationData,
                b"firstsecondlast",
                0
            )
            .unwrap()
        );
        assert_eq!(
            seal(&mut scattered, ContentType::Alert, &[1, 0], 1).unwrap(),
            seal(&mut flat, ContentType::Alert, &[1, 0], 1).unwrap()
        );
        assert_eq!(flat.encrypted_payload_len(usize::MAX), usize::MAX);
        assert_eq!(flat.encrypted_payload_len(MAX_PLAIN), MAX_PLAIN + MAC_SIZE);
    }
}

#[test]
fn every_ciphertext_and_mac_byte_tamper_erases_decrypted_bytes_and_retires_keys() {
    for version in VERSIONS {
        let good = seal(
            &mut fresh(version),
            ContentType::ApplicationData,
            b"authenticated only",
            0,
        )
        .unwrap();
        for index in 0..good.len() {
            let mut receiver = fresh(version);
            let mut wire = good.clone();
            wire[index] ^= 1;
            assert!(matches!(
                open(&mut receiver, ContentType::ApplicationData, &mut wire, 0),
                Err(Error::DecryptError)
            ));
            assert!(wire.iter().all(|b| *b == 0));
            assert_eq!(receiver.next_seq, 0);
            retired(&mut receiver, &good);
        }
        for typ in [
            ContentType::Handshake,
            ContentType::Alert,
            ContentType::ChangeCipherSpec,
        ] {
            let mut receiver = fresh(version);
            let mut wire = good.clone();
            assert!(open(&mut receiver, typ, &mut wire, 0).is_err());
            assert!(
                wire.iter().all(|b| *b == 0),
                "record type is MAC authenticated"
            );
            retired(&mut receiver, &good);
        }
        for (key, mac) in [([0x41; KEY_SIZE], MAC), (KEY, [0x42; MAC_SIZE])] {
            let mut receiver = Cipher::new(&key, &mac, version).unwrap();
            let mut wire = good.clone();
            assert!(open(&mut receiver, ContentType::ApplicationData, &mut wire, 0).is_err());
            assert!(wire.iter().all(|b| *b == 0));
            retired(&mut receiver, &good);
        }
    }
}

#[test]
fn truncation_and_extension_are_fatal_with_predecrypt_and_postdecrypt_cleanup_distinguished() {
    for version in VERSIONS {
        let good = seal(
            &mut fresh(version),
            ContentType::ApplicationData,
            b"record body",
            0,
        )
        .unwrap();
        for size in 0..good.len() {
            let mut receiver = fresh(version);
            let mut wire = good[..size].to_vec();
            assert!(open(&mut receiver, ContentType::ApplicationData, &mut wire, 0).is_err());
            if size < MAC_SIZE {
                assert_eq!(wire, good[..size]);
            } else {
                assert!(wire.iter().all(|b| *b == 0));
            }
            retired(&mut receiver, &good);
        }
        for extra in [1, 20, 257] {
            let mut receiver = fresh(version);
            let mut wire = good.clone();
            wire.resize(good.len() + extra, 0x5a);
            assert!(open(&mut receiver, ContentType::ApplicationData, &mut wire, 0).is_err());
            assert!(wire.iter().all(|b| *b == 0));
            retired(&mut receiver, &good);
        }
        let mut receiver = fresh(version);
        let mut wire = vec![0x5a; MAX_PLAIN + MAC_SIZE + 1];
        assert!(open(&mut receiver, ContentType::ApplicationData, &mut wire, 0).is_err());
        assert!(
            wire.iter().all(|b| *b == 0x5a),
            "oversized ciphertext was never decrypted"
        );
        retired(&mut receiver, &good);
    }
}

#[test]
fn bad_version_type_sequence_and_empty_control_records_retire_before_decryption() {
    for version in VERSIONS {
        let good = seal(
            &mut fresh(version),
            ContentType::ApplicationData,
            b"body",
            0,
        )
        .unwrap();
        for wrong in VERSIONS.into_iter().chain([
            ProtocolVersion::SSLv3,
            ProtocolVersion::TLSv1_3,
            ProtocolVersion::Unknown(0xffff),
        ]) {
            if wrong == version {
                continue;
            }
            let mut receiver = fresh(version);
            let mut wire = good.clone();
            assert!(
                receiver
                    .decrypt(
                        InboundOpaqueMessage::new(ContentType::ApplicationData, wrong, &mut wire),
                        0
                    )
                    .is_err()
            );
            assert_eq!(wire, good);
            retired(&mut receiver, &good);
        }
        for typ in [
            ContentType::Unknown(0),
            ContentType::Unknown(24),
            ContentType::Unknown(255),
        ] {
            let mut receiver = fresh(version);
            let mut wire = good.clone();
            assert!(open(&mut receiver, typ, &mut wire, 0).is_err());
            assert_eq!(wire, good);
            retired(&mut receiver, &good);
        }
        for seq in [1, 1 << 32, u64::MAX - 1, u64::MAX] {
            let mut receiver = fresh(version);
            let mut wire = good.clone();
            assert!(open(&mut receiver, ContentType::ApplicationData, &mut wire, seq).is_err());
            assert_eq!(wire, good);
            retired(&mut receiver, &good);
        }
        for typ in [
            ContentType::Handshake,
            ContentType::Alert,
            ContentType::ChangeCipherSpec,
        ] {
            let mut sender = fresh(version);
            assert!(seal(&mut sender, typ, &[], 0).is_err());
            retired(&mut sender, &good);
            let mut receiver = fresh(version);
            let mut wire = [0x5a; MAC_SIZE];
            assert!(open(&mut receiver, typ, &mut wire, 0).is_err());
            assert_eq!(wire, [0x5a; MAC_SIZE]);
            retired(&mut receiver, &good);
        }
    }
}

#[test]
fn replay_or_skipped_record_is_permanent_even_when_caller_supplies_expected_sequence() {
    for version in VERSIONS {
        let mut sender = fresh(version);
        let first = seal(&mut sender, ContentType::ApplicationData, b"first", 0).unwrap();
        let second = seal(&mut sender, ContentType::ApplicationData, b"second", 1).unwrap();
        let third = seal(&mut sender, ContentType::ApplicationData, b"third", 2).unwrap();
        for damaged in [&first, &third] {
            let mut receiver = fresh(version);
            assert_eq!(
                open(
                    &mut receiver,
                    ContentType::ApplicationData,
                    &mut first.clone(),
                    0
                )
                .unwrap(),
                b"first"
            );
            let mut wire = damaged.clone();
            assert!(open(&mut receiver, ContentType::ApplicationData, &mut wire, 1).is_err());
            assert!(wire.iter().all(|b| *b == 0));
            retired(&mut receiver, &second);
        }
        let mut receiver = fresh(version);
        open(
            &mut receiver,
            ContentType::ApplicationData,
            &mut first.clone(),
            0,
        )
        .unwrap();
        let mut wire = first.clone();
        assert!(open(&mut receiver, ContentType::ApplicationData, &mut wire, 0).is_err());
        assert_eq!(
            wire, first,
            "explicitly repeated sequence rejected before RC4"
        );
        retired(&mut receiver, &second);
    }
}

#[test]
fn outbound_errors_drop_state_and_never_silently_accept_or_reset_stream() {
    for version in VERSIONS {
        for bad in 0..5 {
            let mut sender = fresh(version);
            let large = vec![0; MAX_PLAIN + 1];
            let message = OutboundPlainMessage {
                typ: if bad == 0 {
                    ContentType::Unknown(24)
                } else {
                    ContentType::ApplicationData
                },
                version: if bad == 1 {
                    ProtocolVersion::TLSv1_3
                } else {
                    version
                },
                payload: if bad == 2 { large.as_slice() } else { b"body" }.into(),
            };
            let result = if bad == 4 {
                sender.encrypt_with_padding(message, 0, 1)
            } else {
                sender.encrypt(message, u64::from(bad == 3))
            };
            assert!(matches!(result, Err(Error::EncryptError)));
            assert_eq!(sender.next_seq, 0);
            retired(&mut sender, &[]);
        }
    }
}

#[test]
fn sequence_boundary_cannot_wrap_and_fresh_directions_are_independent() {
    for version in VERSIONS {
        // Direct boundary injection exercises the arithmetic without falsely
        // claiming that 2^64 records are secure or practical to transmit.
        let mut sender = fresh(version);
        let mut receiver = fresh(version);
        sender.next_seq = u64::MAX - 1;
        receiver.next_seq = u64::MAX - 1;
        let mut wire = seal(
            &mut sender,
            ContentType::ApplicationData,
            b"last",
            u64::MAX - 1,
        )
        .unwrap();
        assert_eq!(
            open(
                &mut receiver,
                ContentType::ApplicationData,
                &mut wire,
                u64::MAX - 1
            )
            .unwrap(),
            b"last"
        );
        assert_eq!(sender.next_seq, u64::MAX);
        assert_eq!(receiver.next_seq, u64::MAX);
        assert!(seal(&mut sender, ContentType::ApplicationData, b"wrap", u64::MAX).is_err());
        assert!(
            open(
                &mut receiver,
                ContentType::ApplicationData,
                &mut wire,
                u64::MAX
            )
            .is_err()
        );
        sender.next_seq = 0;
        receiver.next_seq = 0;
        retired(&mut sender, &[]);
        retired(&mut receiver, &[]);
        let mut outputs = std::collections::BTreeSet::new();
        for salt in 0..4u8 {
            let mut key = KEY;
            let mut mac = MAC;
            key[0] ^= salt;
            mac[0] ^= salt;
            let mut encoder = Cipher::new(&key, &mac, version).unwrap();
            let mut decoder = Cipher::new(&key, &mac, version).unwrap();
            let wire = seal(&mut encoder, ContentType::ApplicationData, b"epoch", 0).unwrap();
            assert!(outputs.insert(wire.clone()));
            assert_eq!(
                open(
                    &mut decoder,
                    ContentType::ApplicationData,
                    &mut wire.clone(),
                    0
                )
                .unwrap(),
                b"epoch"
            );
        }
    }
}

#[test]
fn exact_key_block_and_invalid_factory_arguments_fail_closed() {
    for version in VERSIONS {
        let alg = algorithm_for_version(version).unwrap();
        let shape = alg.key_block_shape();
        assert_eq!(
            (
                shape.enc_key_len,
                shape.fixed_iv_len,
                shape.explicit_nonce_len,
                alg.mac_key_len()
            ),
            (16, 0, 0, 20)
        );
        for key_len in [0, 15, 16, 17, 32] {
            for mac_len in [0, 19, 20, 21, 32] {
                assert_eq!(
                    Cipher::new(&vec![1; key_len], &vec![2; mac_len], version).is_some(),
                    key_len == 16 && mac_len == 20
                );
            }
        }
        // The public AeadKey constructor only makes 32 bytes. Actual 16-byte
        // key-block extraction is checked by the live handshake tests.
        for mut encoder in [
            alg.encrypter(AeadKey::from([0; 32]), &[], &[]),
            alg.encrypter_with_mac(AeadKey::from([0; 32]), &[], &[], &MAC),
        ] {
            for seq in 0..2 {
                assert!(matches!(
                    encoder.encrypt(
                        OutboundPlainMessage {
                            typ: ContentType::ApplicationData,
                            version,
                            payload: b"x".as_slice().into()
                        },
                        seq
                    ),
                    Err(Error::EncryptError)
                ));
            }
        }
        for mut decoder in [
            alg.decrypter(AeadKey::from([0; 32]), &[]),
            alg.decrypter_with_mac(AeadKey::from([0; 32]), &[], &MAC),
        ] {
            let mut wire = [0x5a; 32];
            assert!(matches!(
                decoder.decrypt(
                    InboundOpaqueMessage::new(ContentType::ApplicationData, version, &mut wire),
                    0
                ),
                Err(Error::DecryptError)
            ));
            assert_eq!(wire, [0x5a; 32]);
        }
        assert!(alg.extract_keys(AeadKey::from([0; 32]), &[], &[]).is_err());
    }
    for version in [
        ProtocolVersion::SSLv3,
        ProtocolVersion::TLSv1_3,
        ProtocolVersion::Unknown(0xffff),
    ] {
        assert!(algorithm_for_version(version).is_none());
        assert!(Cipher::new(&KEY, &MAC, version).is_none());
    }
}

#[test]
fn suites_remain_opt_in_with_version_specific_prf_and_strong_tls12_signatures() {
    use rustls::crypto::{KeyExchangeAlgorithm, hash::HashAlgorithm};
    let normal = crate::provider();
    let selected = provider();
    assert_eq!(selected.cipher_suites, suites());
    assert_eq!(
        selected
            .signature_verification_algorithms
            .supported_schemes(),
        normal.signature_verification_algorithms.supported_schemes()
    );
    for (suite, id) in suites().into_iter().zip([0xc007, 0xc011, 0x0005]) {
        assert_eq!(u16::from(suite.suite()), id);
        assert!(!normal.cipher_suites.contains(&suite));
        let SupportedCipherSuite::Tls12(base) = suite else {
            panic!("TLS12 only")
        };
        assert_eq!(base.common.hash_provider.algorithm(), HashAlgorithm::SHA256);
        assert_eq!(base.common.confidentiality_limit, u64::MAX);
        assert_eq!(
            base.kx,
            if id == 5 {
                KeyExchangeAlgorithm::RSA
            } else {
                KeyExchangeAlgorithm::ECDHE
            }
        );
        assert!(base.sign.iter().all(|scheme| !matches!(
            scheme,
            rustls::SignatureScheme::RSA_PKCS1_SHA1
                | rustls::SignatureScheme::ECDSA_SHA1_Legacy
                | rustls::SignatureScheme::RSA_PKCS1_MD5_SHA1_Legacy
        )));
        for version in VERSIONS[..2].iter().copied() {
            let old = LEGACY_TLS_WITH_RC4
                .cipher_suite(suite.suite(), version)
                .unwrap();
            assert_eq!(
                old.common.hash_provider.algorithm(),
                HashAlgorithm::MD5_SHA1
            );
            assert_eq!(
                old.sign,
                &[if id == 0xc007 {
                    rustls::SignatureScheme::ECDSA_SHA1_Legacy
                } else {
                    rustls::SignatureScheme::RSA_PKCS1_MD5_SHA1_Legacy
                }]
            );
            assert!(
                crate::legacy_provider::LEGACY_TLS
                    .cipher_suite(suite.suite(), version)
                    .is_none()
            );
        }
        assert!(
            LEGACY_TLS_WITH_RC4
                .cipher_suite(suite.suite(), ProtocolVersion::TLSv1_2)
                .is_none()
        );
    }
    for id in [0x0004, 0x0016, 0x0013, 0xc013, 0x1301] {
        assert!(
            LEGACY_TLS_WITH_RC4
                .cipher_suite(CipherSuite::from(id), ProtocolVersion::TLSv1_0)
                .is_none()
        );
    }
}
