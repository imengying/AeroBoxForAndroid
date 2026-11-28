use super::*;

fn cipher(bits: usize) -> Cipher {
    Cipher::from_slices(bits / 8, &vec![0x11; bits / 8], &[], &[0x22; MAC_SIZE]).unwrap()
}
fn encoded(bits: usize, plain: &[u8], pad: usize) -> Vec<u8> {
    let cipher = cipher(bits);
    assert!((plain.len() + MAC_SIZE + pad) % BLOCK == 0);
    assert!((1..=256).contains(&pad));
    let iv = [0x33; BLOCK];
    let mut output = Vec::from(iv);
    output.extend_from_slice(plain);
    output.extend_from_slice(&cipher.tag(
        42,
        rustls::ContentType::ApplicationData,
        rustls::ProtocolVersion::TLSv1_2,
        plain,
    ));
    output.extend(std::iter::repeat_n((pad - 1) as u8, pad));
    cipher.encrypt_blocks(&mut output[BLOCK..], iv);
    output
}
fn decrypt<'a>(cipher: &mut Cipher, bytes: &'a mut [u8], seq: u64) -> Result<&'a [u8], Error> {
    cipher
        .decrypt(
            InboundOpaqueMessage::new(
                rustls::ContentType::ApplicationData,
                rustls::ProtocolVersion::TLSv1_2,
                bytes,
            ),
            seq,
        )
        .map(|m| m.payload)
}
#[test]
fn both_key_sizes_round_trip_boundary_lengths_and_unique_explicit_iv() {
    for bits in [128, 256] {
        let mut enc = cipher(bits);
        let mut dec = cipher(bits);
        for (index, length) in [0, 1, 11, 12, 15, 16, 17, 255, 1024, 16384]
            .into_iter()
            .enumerate()
        {
            let plain: Vec<u8> = (0..length).map(|i| (i % 251) as u8).collect();
            let message = || OutboundPlainMessage {
                typ: rustls::ContentType::ApplicationData,
                version: rustls::ProtocolVersion::TLSv1_2,
                payload: plain.as_slice().into(),
            };
            let sequence = (index as u64) * 2;
            let one = enc.encrypt(message(), sequence).unwrap();
            let two = enc.encrypt(message(), sequence + 1).unwrap();
            let mut bytes = one.payload.as_ref().to_vec();
            assert_eq!(bytes.len(), enc.encrypted_payload_len(length));
            assert_ne!(&bytes[..16], &two.payload.as_ref()[..16]);
            assert_eq!(decrypt(&mut dec, &mut bytes, sequence).unwrap(), plain);
            let mut bytes = two.payload.as_ref().to_vec();
            assert_eq!(decrypt(&mut dec, &mut bytes, sequence + 1).unwrap(), plain);
        }
    }
}

#[test]
fn iv_permutation_separates_keys_directions_and_sequence_boundaries() {
    for bits in [128, 256] {
        let key = vec![0x11; bits / 8];
        let original = Cipher::from_slices(bits / 8, &key, &[], &[0x22; MAC_SIZE]).unwrap();
        let other_mac = Cipher::from_slices(bits / 8, &key, &[], &[0x23; MAC_SIZE]).unwrap();
        let other_key =
            Cipher::from_slices(bits / 8, &vec![0x12; bits / 8], &[], &[0x22; MAC_SIZE]).unwrap();
        let mut ivs = std::collections::HashSet::new();
        for seq in [
            0,
            1,
            255,
            256,
            u32::MAX as u64,
            u32::MAX as u64 + 1,
            u64::MAX,
        ] {
            let iv = original.explicit_iv(seq);
            assert!(ivs.insert(iv));
            assert_ne!(iv, other_mac.explicit_iv(seq));
            assert_ne!(iv, other_key.explicit_iv(seq));
            // The IV must not expose the sequence, or use the record cipher
            // directly under its traffic encryption key.
            let mut counter = [0u8; BLOCK];
            counter[8..].copy_from_slice(&seq.to_be_bytes());
            assert_ne!(iv, counter);
            match &original.aes {
                Aes::Aes128(aes) => aes.encrypt_block((&mut counter).into()),
                Aes::Aes256(aes) => aes.encrypt_block((&mut counter).into()),
            }
            assert_ne!(iv, counter);
        }
    }
}
#[test]
fn all_tls_padding_lengths_are_accepted_and_invalid_padding_never_exposes_plaintext() {
    for pad in 1usize..=256 {
        let length = (BLOCK - (MAC_SIZE + pad) % BLOCK) % BLOCK;
        let plain = vec![0x5a; length];
        let mut bytes = encoded(128, &plain, pad);
        assert_eq!(decrypt(&mut cipher(128), &mut bytes, 42).unwrap(), plain);
        let mut bytes = encoded(128, &plain, pad);
        // Corrupt the last padding byte while keeping the content/MAC equal.
        let iv: [u8; BLOCK] = bytes[..BLOCK].try_into().unwrap();
        cipher(128).decrypt_blocks(&mut bytes[BLOCK..], iv);
        *bytes.last_mut().unwrap() ^= 1;
        cipher(128).encrypt_blocks(&mut bytes[BLOCK..], iv);
        assert!(matches!(
            decrypt(&mut cipher(128), &mut bytes, 42),
            Err(Error::DecryptError)
        ));
    }
}
#[test]
fn mac_iv_sequence_record_type_and_lengths_cannot_be_forged() {
    let good = encoded(256, b"abcdefghijkl", 16);
    for offset in [0, 15, 16, 31, good.len() - 1] {
        let mut bytes = good.clone();
        bytes[offset] ^= 0x80;
        assert!(matches!(
            decrypt(&mut cipher(256), &mut bytes, 42),
            Err(Error::DecryptError)
        ));
    }
    for length in 0..48 {
        let mut bytes = vec![0; length];
        assert!(decrypt(&mut cipher(128), &mut bytes, 42).is_err());
    }
    let mut bytes = vec![0; BLOCK + MAX_PLAIN + MAC_SIZE + 257];
    assert!(decrypt(&mut cipher(128), &mut bytes, 42).is_err());
    assert!(decrypt(&mut cipher(256), &mut good.clone(), 43).is_err());
    let mut bytes = good.clone();
    assert!(
        cipher(256)
            .decrypt(
                InboundOpaqueMessage::new(
                    rustls::ContentType::Handshake,
                    rustls::ProtocolVersion::TLSv1_2,
                    &mut bytes
                ),
                42
            )
            .is_err()
    );
}
#[test]
fn suites_are_opt_in_and_key_schedule_requires_independent_mac_keys() {
    for suite in suites() {
        assert!(!crate::provider().cipher_suites.contains(&suite));
    }
    assert_eq!(AES128.mac_key_len(), 20);
    assert_eq!(AES256.mac_key_len(), 20);
    for key in [AeadKey::from([0; 32])] {
        let mut decoder = AES128.decrypter(key, &[]);
        assert!(
            decoder
                .decrypt(
                    InboundOpaqueMessage::new(
                        rustls::ContentType::ApplicationData,
                        rustls::ProtocolVersion::TLSv1_2,
                        &mut [0; 48]
                    ),
                    0
                )
                .is_err()
        );
    }
}

fn cipher_for_version(bits: usize, version: ProtocolVersion) -> Cipher {
    let iv: &[u8] = if version == ProtocolVersion::TLSv1_0 {
        &[0x33; BLOCK]
    } else {
        &[]
    };
    Cipher::from_slices_for_version(
        bits / 8,
        &vec![0x11; bits / 8],
        iv,
        &[0x22; MAC_SIZE],
        version,
    )
    .unwrap()
}

fn decrypt_version<'a>(
    cipher: &mut Cipher,
    bytes: &'a mut [u8],
    seq: u64,
    version: ProtocolVersion,
) -> Result<&'a [u8], Error> {
    cipher
        .decrypt(
            InboundOpaqueMessage::new(rustls::ContentType::ApplicationData, version, bytes),
            seq,
        )
        .map(|message| message.payload)
}

fn encrypt_version(
    cipher: &mut Cipher,
    plain: &[u8],
    seq: u64,
    version: ProtocolVersion,
) -> Result<Vec<u8>, Error> {
    cipher
        .encrypt(
            OutboundPlainMessage {
                typ: rustls::ContentType::ApplicationData,
                version,
                payload: plain.into(),
            },
            seq,
        )
        .map(|message| message.payload.as_ref().to_vec())
}

fn encoded_version(
    bits: usize,
    plain: &[u8],
    pad: usize,
    seq: u64,
    version: ProtocolVersion,
) -> Vec<u8> {
    let cipher = cipher_for_version(bits, version);
    assert_eq!((plain.len() + MAC_SIZE + pad) % BLOCK, 0);
    let mut bytes = Vec::new();
    if version != ProtocolVersion::TLSv1_0 {
        bytes.extend_from_slice(&[0x33; BLOCK]);
    }
    let explicit = bytes.len();
    bytes.extend_from_slice(plain);
    bytes.extend_from_slice(&cipher.tag(seq, rustls::ContentType::ApplicationData, version, plain));
    bytes.extend(std::iter::repeat_n((pad - 1) as u8, pad));
    cipher.encrypt_blocks(&mut bytes[explicit..], [0x33; BLOCK]);
    bytes
}

#[test]
fn version_factory_consumes_only_the_correct_key_block_and_never_falls_back() {
    for version in [
        ProtocolVersion::TLSv1_0,
        ProtocolVersion::TLSv1_1,
        ProtocolVersion::TLSv1_2,
    ] {
        for key_len in [16, 32] {
            let factory = algorithm_for_version(key_len, version).unwrap();
            let shape = factory.key_block_shape();
            assert_eq!(shape.enc_key_len, key_len);
            assert_eq!(
                shape.fixed_iv_len,
                if version == ProtocolVersion::TLSv1_0 {
                    BLOCK
                } else {
                    0
                }
            );
            assert_eq!(shape.explicit_nonce_len, 0);
            assert_eq!(factory.mac_key_len(), MAC_SIZE);
            for iv_len in [0, 15, 16, 17] {
                let cipher = Cipher::from_slices_for_version(
                    key_len,
                    &vec![0; key_len],
                    &vec![0; iv_len],
                    &[0; MAC_SIZE],
                    version,
                );
                assert_eq!(cipher.is_some(), iv_len == shape.fixed_iv_len);
            }
            assert!(
                Cipher::from_slices_for_version(
                    key_len,
                    &vec![0; key_len - 1],
                    &vec![0; shape.fixed_iv_len],
                    &[0; MAC_SIZE],
                    version
                )
                .is_none()
            );
            assert!(
                Cipher::from_slices_for_version(
                    key_len,
                    &vec![0; key_len],
                    &vec![0; shape.fixed_iv_len],
                    &[0; MAC_SIZE - 1],
                    version
                )
                .is_none()
            );
        }
    }
    for version in [
        ProtocolVersion::SSLv3,
        ProtocolVersion::TLSv1_3,
        ProtocolVersion::Unknown(0x0305),
    ] {
        assert!(algorithm_for_version(16, version).is_none());
    }
    for length in [0, 15, 24, 31, 33, usize::MAX] {
        assert!(algorithm_for_version(length, ProtocolVersion::TLSv1_0).is_none());
    }
}

#[test]
fn tls10_implicit_iv_advances_to_previous_records_final_ciphertext_block() {
    for bits in [128, 256] {
        let version = ProtocolVersion::TLSv1_0;
        let mut enc = cipher_for_version(bits, version);
        let mut dec = cipher_for_version(bits, version);
        let mut previous = [0x33; BLOCK];
        for (seq, length) in [0, 1, 15, 16, 17, 16384].into_iter().enumerate() {
            let plain = vec![seq as u8; length];
            let wire = encrypt_version(&mut enc, &plain, seq as u64, version).unwrap();
            assert_eq!(wire.len(), wire_len(length, 0));
            assert_eq!(enc.encrypted_payload_len(length), wire.len());
            let mut independent = wire.clone();
            cipher_for_version(bits, version).decrypt_blocks(&mut independent, previous);
            assert_eq!(&independent[..length], plain.as_slice());
            assert_eq!(
                &independent[length..length + MAC_SIZE],
                enc.tag(
                    seq as u64,
                    rustls::ContentType::ApplicationData,
                    version,
                    &plain
                )
            );
            previous.copy_from_slice(&wire[wire.len() - BLOCK..]);
            match &enc.iv {
                RecordIv::Implicit(iv) => assert_eq!(iv.as_ref(), previous),
                _ => panic!("TLS 1.0 must use implicit IVs"),
            }
            assert_eq!(
                decrypt_version(&mut dec, &mut wire.clone(), seq as u64, version).unwrap(),
                plain
            );
            if seq > 0 {
                // A fresh key epoch cannot decrypt later records even with
                // the correct sequence number; the prior ciphertext is needed.
                assert!(
                    decrypt_version(
                        &mut cipher_for_version(bits, version),
                        &mut wire.clone(),
                        seq as u64,
                        version
                    )
                    .is_err()
                );
            }
            match &dec.iv {
                RecordIv::Implicit(iv) => assert_eq!(iv.as_ref(), previous),
                _ => unreachable!(),
            }
        }
    }
}

#[test]
fn tls11_explicit_ivs_do_not_depend_on_prior_records_but_bind_the_record_version() {
    let version = ProtocolVersion::TLSv1_1;
    for bits in [128, 256] {
        let mut enc = cipher_for_version(bits, version);
        for (seq, length) in [0, 1, 15, 16, 17, 16384].into_iter().enumerate() {
            let plain = vec![0x55; length];
            let wire = encrypt_version(&mut enc, &plain, seq as u64, version).unwrap();
            assert_eq!(wire.len(), wire_len(length, BLOCK));
            assert_eq!(
                decrypt_version(
                    &mut cipher_for_version(bits, version),
                    &mut wire.clone(),
                    seq as u64,
                    version
                )
                .unwrap(),
                plain
            );
            assert!(
                decrypt_version(
                    &mut cipher_for_version(bits, ProtocolVersion::TLSv1_2),
                    &mut wire.clone(),
                    seq as u64,
                    ProtocolVersion::TLSv1_2
                )
                .is_err()
            );
        }
    }
}

#[test]
fn tls10_and_tls11_accept_all_256_padding_lengths_and_reject_each_corrupt_form() {
    for version in [ProtocolVersion::TLSv1_0, ProtocolVersion::TLSv1_1] {
        for pad in 1usize..=256 {
            let plain = vec![0x5a; (BLOCK - (MAC_SIZE + pad) % BLOCK) % BLOCK];
            let mut wire = encoded_version(128, &plain, pad, 0, version);
            assert_eq!(
                decrypt_version(&mut cipher_for_version(128, version), &mut wire, 0, version)
                    .unwrap(),
                plain
            );
            let mut wire = encoded_version(128, &plain, pad, 0, version);
            let explicit = if version == ProtocolVersion::TLSv1_0 {
                0
            } else {
                BLOCK
            };
            let cipher = cipher_for_version(128, version);
            cipher.decrypt_blocks(&mut wire[explicit..], [0x33; BLOCK]);
            *wire.last_mut().unwrap() ^= 1;
            cipher.encrypt_blocks(&mut wire[explicit..], [0x33; BLOCK]);
            assert!(matches!(
                decrypt_version(&mut cipher_for_version(128, version), &mut wire, 0, version),
                Err(Error::DecryptError)
            ));
        }
    }
}

#[test]
fn every_failure_permanently_invalidates_the_directional_record_state() {
    for version in [
        ProtocolVersion::TLSv1_0,
        ProtocolVersion::TLSv1_1,
        ProtocolVersion::TLSv1_2,
    ] {
        let good = encoded_version(128, b"abcdefghijkl", 16, 0, version);
        let mut damaged = good.clone();
        *damaged.last_mut().unwrap() ^= 0x80;
        let failures = [
            damaged,
            Vec::new(),
            vec![0; MAX_PLAIN + MAC_SIZE + 256 + BLOCK + 1],
        ];
        for mut failure in failures {
            let mut decoder = cipher_for_version(128, version);
            assert!(matches!(
                decrypt_version(&mut decoder, &mut failure, 0, version),
                Err(Error::DecryptError)
            ));
            assert!(matches!(
                decrypt_version(&mut decoder, &mut good.clone(), 0, version),
                Err(Error::DecryptError)
            ));
            assert!(decoder.failed);
            if let RecordIv::Implicit(previous) = &decoder.iv {
                assert_eq!(previous.as_ref(), &[0x33; BLOCK]);
            }
            // A record which reached authentication was decrypted in place;
            // its unauthenticated plaintext must be erased on failure.
            if failure.len() == good.len() {
                assert!(
                    failure[decoder.explicit_iv_len()..]
                        .iter()
                        .all(|&byte| byte == 0)
                );
            }
        }
        let wrong = if version == ProtocolVersion::TLSv1_2 {
            ProtocolVersion::TLSv1_1
        } else {
            ProtocolVersion::TLSv1_2
        };
        let mut decoder = cipher_for_version(128, version);
        assert!(decrypt_version(&mut decoder, &mut good.clone(), 0, wrong).is_err());
        assert!(decrypt_version(&mut decoder, &mut good.clone(), 0, version).is_err());
        for (plain, record_version) in [(vec![0; MAX_PLAIN + 1], version), (vec![0; 1], wrong)] {
            let mut encoder = cipher_for_version(128, version);
            assert!(matches!(
                encrypt_version(&mut encoder, &plain, 0, record_version),
                Err(Error::EncryptError)
            ));
            assert!(matches!(
                encrypt_version(&mut encoder, b"valid", 0, version),
                Err(Error::EncryptError)
            ));
        }
    }
}

#[test]
fn length_queries_are_bounded_even_on_32_bit_overflow_inputs() {
    for version in [
        ProtocolVersion::TLSv1_0,
        ProtocolVersion::TLSv1_1,
        ProtocolVersion::TLSv1_2,
    ] {
        let cipher = cipher_for_version(128, version);
        assert_eq!(cipher.encrypted_payload_len(usize::MAX), usize::MAX);
        assert_eq!(
            cipher.encrypted_payload_len(usize::MAX - MAC_SIZE),
            usize::MAX
        );
        for length in [u16::MAX as usize, u32::MAX as usize] {
            let wire = cipher.encrypted_payload_len(length);
            assert!(wire >= length);
        }
    }
}

#[test]
fn aes_cbc_block_chaining_matches_nist_sp800_38a_vectors() {
    // NIST SP 800-38A F.2.1 and F.2.5. These are block-mode KATs; the TLS
    // record tests above additionally exercise the MAC, version and padding.
    fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }
    let plaintext = hex(concat!(
        "6bc1bee22e409f96e93d7e117393172a",
        "ae2d8a571e03ac9c9eb76fac45af8e51",
        "30c81c46a35ce411e5fbc1191a0a52ef",
        "f69f2445df4f9b17ad2b417be66c3710",
    ));
    let iv: [u8; 16] = hex("000102030405060708090a0b0c0d0e0f").try_into().unwrap();
    for (key, expected) in [
        (
            "2b7e151628aed2a6abf7158809cf4f3c",
            concat!(
                "7649abac8119b246cee98e9b12e9197d",
                "5086cb9b507219ee95db113a917678b2",
                "73bed6b8e3c1743b7116e69e22229516",
                "3ff1caa1681fac09120eca307586e1a7"
            ),
        ),
        (
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
            concat!(
                "f58c4c04d6e5f1ba779eabfb5f7bfbd6",
                "9cfc4e967edb808d679f777bc6702c7d",
                "39f23369a9d9bacfa530e26304231461",
                "b2eb05e2c39be9fcda6c19078c6a9d1b"
            ),
        ),
    ] {
        let key = hex(key);
        let cipher = Cipher::from_slices_for_version(
            key.len(),
            &key,
            &iv,
            &[0x22; MAC_SIZE],
            ProtocolVersion::TLSv1_0,
        )
        .unwrap();
        let mut actual = plaintext.clone();
        cipher.encrypt_blocks(&mut actual, iv);
        assert_eq!(actual, hex(expected));
        cipher.decrypt_blocks(&mut actual, iv);
        assert_eq!(actual, plaintext);
    }
}

#[test]
fn legacy_record_hmac_matches_independent_binary_header_vectors() {
    // Python HMAC-SHA1 known answers; sequence is above the 32-bit boundary.
    for (version, expected) in [
        (
            ProtocolVersion::TLSv1_0,
            "9d89e6a0dba5168bf52be29ee71bffb93c1cec00",
        ),
        (
            ProtocolVersion::TLSv1_1,
            "7611b4161578a89e3bb5be896efa0844a6f2691c",
        ),
        (
            ProtocolVersion::TLSv1_2,
            "2528223f6f7f4bbd54760ad57cc96e362844fcd4",
        ),
    ] {
        let expected: Vec<u8> = expected
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        let cipher = cipher_for_version(128, version);
        assert_eq!(
            cipher
                .tag(
                    0x1_0000_0001,
                    rustls::ContentType::ApplicationData,
                    version,
                    b"TLS CBC version-bound MAC"
                )
                .as_slice(),
            expected
        );
    }
}
