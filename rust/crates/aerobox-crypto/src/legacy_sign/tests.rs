use super::*;
use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey};

const MESSAGE: &[u8] = include_bytes!("fixtures/message.bin");
const SIGNATURE: &[u8] = include_bytes!("fixtures/rsa-md5-sha1.sig");

fn private_key() -> RsaPrivateKey {
    RsaPrivateKey::from_pkcs8_der(include_bytes!("../../tests/fixtures/rsa-key.der")).unwrap()
}

#[test]
fn independent_raw_rsa_fixture_has_no_digest_info_and_blinding_preserves_signature() {
    let key = private_key();
    let public = key.to_public_key();
    let digest = crate::legacy_hash::digest(&[MESSAGE]);
    verify_rsa_md5_sha1(&public, &digest, SIGNATURE).unwrap();
    for seed in [0x15, 0x92] {
        let calls = std::cell::Cell::new(0);
        let signature = sign_with_seed_source(&key, &digest, |out| {
            calls.set(calls.get() + 1);
            out.fill(seed);
            Ok(())
        })
        .unwrap();
        assert_eq!(calls.get(), 1);
        assert_eq!(signature, SIGNATURE);
    }
    assert_eq!(sign_rsa_md5_sha1(&key, &digest).unwrap(), SIGNATURE);
    let encoded = BigUint::from_bytes_be(SIGNATURE)
        .modpow(public.e(), public.n())
        .to_bytes_be();
    assert_eq!(encoded.len(), public.size() - 1); // leading 00 omitted by bigint
    assert_eq!(encoded[0], 1);
    let split = encoded.len() - 36;
    assert!(encoded[1..split - 1].iter().all(|&byte| byte == 0xff));
    assert_eq!(encoded[split - 1], 0);
    assert_eq!(&encoded[split..], digest);
}

#[test]
fn raw_rsa_rejects_changed_message_digest_info_padding_and_signature_length() {
    let key = private_key();
    let public = key.to_public_key();
    let digest = crate::legacy_hash::digest(&[MESSAGE]);
    let mut changed = digest;
    for position in [0, 15, 16, 35] {
        changed[position] ^= 1;
        assert!(verify_rsa_md5_sha1(&public, &changed, SIGNATURE).is_err());
        changed[position] ^= 1;
    }
    let wrong = crate::legacy_hash::digest(&[b"different handshake"]);
    assert!(verify_rsa_md5_sha1(&public, &wrong, SIGNATURE).is_err());
    for length in [0, 1, SIGNATURE.len() - 1, SIGNATURE.len() + 1] {
        assert!(verify_rsa_md5_sha1(&public, &digest, &vec![0; length]).is_err());
    }
    let mut changed_signature = SIGNATURE.to_vec();
    changed_signature[3] ^= 0x80;
    assert!(verify_rsa_md5_sha1(&public, &digest, &changed_signature).is_err());
    // A correctly padded RSA signature on SHA-1 plus its DigestInfo is still
    // wrong for pre-TLS-1.2 RSA. This catches accidentally aliasing SHA-1.
    let sha1_padding = Pkcs1v15Sign {
        hash_len: Some(20),
        prefix: vec![
            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
            0x14,
        ]
        .into_boxed_slice(),
    };
    let mut rng = ChaCha20Rng::from_seed([0x42; 32]);
    let wrong = key
        .sign_with_rng(&mut rng, sha1_padding, &digest[16..])
        .unwrap();
    assert!(verify_rsa_md5_sha1(&public, &digest, &wrong).is_err());
    assert!(
        key.sign_with_rng(&mut rng, raw_md5_sha1_padding(), &digest[..35])
            .is_err()
    );
}

#[test]
fn rsa_entropy_failure_propagates_before_any_signature_is_returned() {
    let key = private_key();
    let digest = crate::legacy_hash::digest(&[MESSAGE]);
    let calls = std::cell::Cell::new(0);
    let error = sign_with_seed_source(&key, &digest, |seed| {
        seed[..16].fill(0xa5);
        calls.set(calls.get() + 1);
        Err(Error::FailedToGetRandomBytes)
    })
    .unwrap_err();
    assert_eq!(calls.get(), 1);
    assert!(matches!(error, Error::FailedToGetRandomBytes));
}

#[test]
fn certificate_entry_preserves_rsa_key_type_message_order_and_full_der_consumption() {
    let key = private_key();
    let public = key.to_public_key().to_public_key_der().unwrap();
    assert_eq!(
        rsa_public_key_from_spki(public.as_bytes()).unwrap(),
        key.to_public_key()
    );
    let cert = CertificateDer::from(include_bytes!("../../tests/fixtures/rsa-cert.der").as_slice());
    verify_rsa_certificate(&cert, &[&MESSAGE[..7], &MESSAGE[7..]], SIGNATURE).unwrap();
    assert!(verify_rsa_certificate(&cert, &[&MESSAGE[7..], &MESSAGE[..7]], SIGNATURE).is_err());
    let non_rsa =
        CertificateDer::from(include_bytes!("../../tests/fixtures/ecdsa-cert.der").as_slice());
    assert!(verify_rsa_certificate(&non_rsa, &[MESSAGE], SIGNATURE).is_err());
    let mut trailing = cert.as_ref().to_vec();
    trailing.push(0);
    assert!(verify_rsa_certificate(&trailing.into(), &[MESSAGE], SIGNATURE).is_err());
    assert!(verify_rsa_certificate(&vec![0; 65537].into(), &[MESSAGE], SIGNATURE).is_err());
    let mut trailing = public.as_bytes().to_vec();
    trailing.push(0);
    assert!(rsa_public_key_from_spki(&trailing).is_err());
    assert!(rsa_public_key_from_spki(&vec![0; 1121]).is_err());
}

#[test]
fn rsa_spki_rejects_restricted_pss_keys_and_out_of_range_moduli() {
    use rsa::pkcs8::der::{
        Encode,
        asn1::{AnyRef, BitStringRef, UintRef},
    };
    for bits in [1024usize, 2047, 2048, 4096, 8192, 8193] {
        let mut modulus = vec![0; bits.div_ceil(8)];
        modulus[0] = 1 << ((bits - 1) % 8);
        *modulus.last_mut().unwrap() = 1;
        let raw = rsa::pkcs1::RsaPublicKey {
            modulus: UintRef::new(&modulus).unwrap(),
            public_exponent: UintRef::new(&[1, 0, 1]).unwrap(),
        }
        .to_der()
        .unwrap();
        for rsa_algorithm in [true, false] {
            let algorithm = rsa::pkcs8::AlgorithmIdentifierRef {
                oid: if rsa_algorithm {
                    rsa::pkcs1::ALGORITHM_OID
                } else {
                    "1.2.840.113549.1.1.10".parse().unwrap()
                },
                parameters: Some(AnyRef::NULL),
            };
            let spki = rsa::pkcs8::SubjectPublicKeyInfoRef {
                algorithm,
                subject_public_key: BitStringRef::from_bytes(&raw).unwrap(),
            }
            .to_der()
            .unwrap();
            assert_eq!(
                rsa_public_key_from_spki(&spki).is_ok(),
                rsa_algorithm && (2048..=8192).contains(&bits)
            );
        }
    }
    let small = RsaPrivateKey::from_components(
        3233u32.into(),
        17u32.into(),
        2753u32.into(),
        vec![61u32.into(), 53u32.into()],
    )
    .unwrap();
    let digest = [0; 36];
    assert!(verify_rsa_md5_sha1(&small.to_public_key(), &digest, &[0; 2]).is_err());
    let mut called = false;
    assert!(
        sign_with_seed_source(&small, &digest, |_| {
            called = true;
            Ok(())
        })
        .is_err()
    );
    assert!(!called);
}
