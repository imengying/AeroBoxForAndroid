use aerobox_primitives::{aead::*, cipher, digest, hkdf, hmac};

fn bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn nist_aes128_gcm_and_tamper_rejection() {
    let key = LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &[0; 16]).unwrap());
    let mut data = vec![0; 16];
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key([0; 12]),
        Aad::empty(),
        &mut data,
    )
    .unwrap();
    assert_eq!(
        data,
        bytes("0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf")
    );
    let mut bad = data.clone();
    bad[31] ^= 1;
    assert!(
        key.open_in_place(
            Nonce::assume_unique_for_key([0; 12]),
            Aad::empty(),
            &mut bad
        )
        .is_err()
    );
    assert_eq!(&bad[..16], &[0; 16]);
    assert_eq!(
        key.open_in_place(
            Nonce::assume_unique_for_key([0; 12]),
            Aad::empty(),
            &mut data
        )
        .unwrap(),
        &[0; 16]
    );
}

#[test]
fn rfc5869_hkdf_sha256_case_one() {
    struct Len;
    impl hkdf::KeyType for Len {
        fn len(&self) -> usize {
            42
        }
    }
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &bytes("000102030405060708090a0b0c"));
    let prk = salt.extract(&[0x0b; 22]);
    let info = bytes("f0f1f2f3f4f5f6f7f8f9");
    let mut output = [0; 42];
    prk.expand(&[&info], Len)
        .unwrap()
        .fill(&mut output)
        .unwrap();
    assert_eq!(
        output.as_slice(),
        bytes(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        )
    );
}

#[test]
fn rfc4231_hmac_sha256_case_one() {
    let key = hmac::Key::new(hmac::HMAC_SHA256, &[0x0b; 20]);
    let expected = bytes("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    assert_eq!(hmac::sign(&key, b"Hi There").as_ref(), expected);
    assert!(hmac::verify(&key, b"Hi There", &expected).is_ok());
    assert!(hmac::verify(&key, b"hi There", &expected).is_err());
}

#[test]
fn fips197_aes_ecb() {
    let raw = bytes("000102030405060708090a0b0c0d0e0f");
    let mut block = bytes("00112233445566778899aabbccddeeff");
    let key =
        cipher::EncryptingKey::ecb(cipher::UnboundCipherKey::new(&cipher::AES_128, &raw).unwrap())
            .unwrap();
    key.less_safe_encrypt(&mut block, cipher::EncryptionContext::None)
        .unwrap();
    assert_eq!(block, bytes("69c4e0d86a7b0430d8cdb78070b4c55a"));
    let key =
        cipher::DecryptingKey::ecb(cipher::UnboundCipherKey::new(&cipher::AES_128, &raw).unwrap())
            .unwrap();
    key.decrypt(&mut block, cipher::DecryptionContext::None)
        .unwrap();
    assert_eq!(block, bytes("00112233445566778899aabbccddeeff"));
}

#[test]
fn sha256_known_digest() {
    assert_eq!(
        digest::digest(&digest::SHA256, b"abc").as_ref(),
        bytes("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
}

#[test]
fn rfc8452_aes256_gcm_siv_with_aad_and_tamper_rejection() {
    let mut raw_key = [0; 32];
    raw_key[0] = 1;
    let mut nonce = [0; 12];
    nonce[0] = 3;
    let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM_SIV, &raw_key).unwrap());
    for (plain, aad, ciphertext) in [
        ("", "", "07f5f4169bbf55a8400cd47ea6fd400f"),
        (
            "0100000000000000",
            "",
            "c2ef328e5c71c83b843122130f7364b761e0b97427e3df28",
        ),
        (
            "0200000000000000",
            "01",
            "1de22967237a813291213f267e3b452f02d01ae33e4ec854",
        ),
    ] {
        let plain = bytes(plain);
        let aad = bytes(aad);
        let mut wire = plain.clone();
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(&aad),
            &mut wire,
        )
        .unwrap();
        assert_eq!(wire, bytes(ciphertext));
        let mut bad = wire.clone();
        let end = bad.len() - 1;
        bad[end] ^= 1;
        assert!(
            key.open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(&aad),
                &mut bad
            )
            .is_err()
        );
        assert!(bad[..plain.len()].iter().all(|byte| *byte == 0));
        assert_eq!(
            key.open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(&aad),
                &mut wire
            )
            .unwrap(),
            plain
        );
    }
}

#[test]
fn hkdf_imported_prk_matches_rfc5869_and_enforces_output_bounds() {
    struct Len(usize);
    impl hkdf::KeyType for Len {
        fn len(&self) -> usize {
            self.0
        }
    }
    let prk = hkdf::Prk::new_less_safe(
        hkdf::HKDF_SHA256,
        &bytes("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"),
    );
    let info = bytes("f0f1f2f3f4f5f6f7f8f9");
    let mut output = [0; 42];
    prk.expand(&[&info[..4], &info[4..]], Len(42))
        .unwrap()
        .fill(&mut output)
        .unwrap();
    assert_eq!(
        output.as_slice(),
        bytes(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        )
    );
    assert!(prk.expand(&[], Len(255 * 32 + 1)).is_err());
    assert!(prk.expand(&[], Len(1)).unwrap().fill(&mut [0; 2]).is_err());
    let short = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, &[0; 31]);
    assert!(
        short
            .expand(&[], Len(1))
            .unwrap()
            .fill(&mut [0; 1])
            .is_err()
    );
}
