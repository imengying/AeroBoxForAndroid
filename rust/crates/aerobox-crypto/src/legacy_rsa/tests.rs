use super::*;
use rsa::{RsaPrivateKey, pkcs8::DecodePrivateKey, traits::PublicKeyParts};

fn public_key_der(
    bits: usize,
    exponent: &[u8],
    algorithm: rsa::pkcs8::AlgorithmIdentifierRef<'_>,
) -> Vec<u8> {
    use rsa::pkcs8::der::{
        Encode,
        asn1::{BitStringRef, UintRef},
    };
    let mut modulus = vec![0u8; bits.div_ceil(8)];
    modulus[0] = 1 << ((bits - 1) % 8);
    *modulus.last_mut().unwrap() |= 1;
    let pkcs1 = rsa::pkcs1::RsaPublicKey {
        modulus: UintRef::new(&modulus).unwrap(),
        public_exponent: UintRef::new(exponent).unwrap(),
    }
    .to_der()
    .unwrap();
    rsa::pkcs8::SubjectPublicKeyInfoRef {
        algorithm,
        subject_public_key: BitStringRef::from_bytes(&pkcs1).unwrap(),
    }
    .to_der()
    .unwrap()
}

#[test]
fn rsa_transport_public_key_decoder_enforces_algorithm_and_2048_to_8192_bits() {
    use rsa::pkcs8::der::{Tag, asn1::AnyRef};
    let exponent = &[1, 0, 1];
    for bits in [2048, 4096, 8192] {
        let der = public_key_der(bits, exponent, rsa::pkcs1::ALGORITHM_ID);
        let key = decode_public_key(&der).unwrap();
        assert_eq!(key.n().bits(), bits);
    }
    for bits in [1024, 2047, 8193, 16384] {
        let der = public_key_der(bits, exponent, rsa::pkcs1::ALGORITHM_ID);
        assert!(decode_public_key(&der).is_err(), "accepted {bits} bits");
    }
    for algorithm in [
        rsa::pkcs8::AlgorithmIdentifierRef {
            // RSASSA-PSS keys are restricted to signatures.
            oid: "1.2.840.113549.1.1.10".parse().unwrap(),
            parameters: Some(AnyRef::NULL),
        },
        rsa::pkcs8::AlgorithmIdentifierRef {
            parameters: None,
            ..rsa::pkcs1::ALGORITHM_ID
        },
        rsa::pkcs8::AlgorithmIdentifierRef {
            parameters: Some(AnyRef::new(Tag::OctetString, &[]).unwrap()),
            ..rsa::pkcs1::ALGORITHM_ID
        },
    ] {
        let der = public_key_der(2048, exponent, algorithm);
        assert!(decode_public_key(&der).is_err(), "accepted {algorithm:?}");
    }
    let invalid_exponent = public_key_der(2048, &[2], rsa::pkcs1::ALGORITHM_ID);
    assert!(decode_public_key(&invalid_exponent).is_err());
    let mut trailing = public_key_der(2048, exponent, rsa::pkcs1::ALGORITHM_ID);
    trailing.push(0);
    assert!(decode_public_key(&trailing).is_err());
}

#[test]
fn rsa_transport_encrypts_to_independent_go_8192_bit_certified_key() {
    use rustls::client::danger::ServerCertVerifier;
    use std::{sync::Arc, time::Duration};
    let certificate = rustls::pki_types::CertificateDer::from(
        include_bytes!("../../tests/fixtures/rsa8192/leaf.der").as_slice(),
    );
    let private =
        RsaPrivateKey::from_pkcs8_der(include_bytes!("../../tests/fixtures/rsa8192/key.der"))
            .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(
            include_bytes!("../../tests/fixtures/rsa8192/ca.der")
                .as_slice()
                .into(),
        )
        .unwrap();
    let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(crate::provider()),
    )
    .build()
    .unwrap();
    verifier
        .verify_server_cert(
            &certificate,
            &[],
            &"rsa8192.aerobox.test".try_into().unwrap(),
            &[],
            rustls::pki_types::UnixTime::since_unix_epoch(Duration::from_secs(1_893_456_000)),
        )
        .unwrap();
    let (ciphertext, secret) = encrypt(&certificate, rustls::ProtocolVersion::TLSv1_2).unwrap();
    assert_eq!(ciphertext.len(), 1024);
    assert_eq!(private.n().bits(), 8192);
    assert_eq!(
        private.decrypt(rsa::Pkcs1v15Encrypt, &ciphertext).unwrap(),
        secret.secret_bytes()
    );
}

#[test]
fn rsa_transport_seed_failure_returns_error_without_panicking() {
    let certificate = rustls::pki_types::CertificateDer::from(
        include_bytes!("../../tests/fixtures/rsa-cert.der").as_slice(),
    );
    let outcome = std::panic::catch_unwind(|| {
        encrypt_with_seed_source(&certificate, rustls::ProtocolVersion::TLSv1_2, |seed| {
            assert_eq!(seed.len(), 32);
            // A source may partially fill its destination before reporting an
            // error. Those bytes must not be used to proceed with a handshake.
            seed[..16].fill(0x5a);
            Err(Error::FailedToGetRandomBytes)
        })
    });
    let result = outcome.expect("an OS entropy failure must not unwind");
    assert!(matches!(result, Err(Error::FailedToGetRandomBytes)));
}

#[test]
fn rsa_transport_uses_one_seed_for_premaster_and_padding() {
    let certificate = rustls::pki_types::CertificateDer::from(
        include_bytes!("../../tests/fixtures/rsa-cert.der").as_slice(),
    );
    let private =
        RsaPrivateKey::from_pkcs8_der(include_bytes!("../../tests/fixtures/rsa-key.der")).unwrap();
    let encrypt_from_seed = |value| {
        let calls = std::cell::Cell::new(0);
        let result =
            encrypt_with_seed_source(&certificate, rustls::ProtocolVersion::TLSv1_2, |seed| {
                calls.set(calls.get() + 1);
                seed.fill(value);
                Ok(())
            })
            .unwrap();
        assert_eq!(calls.get(), 1);
        result
    };
    let (ciphertext, secret) = encrypt_from_seed(0x7b);
    let (same_ciphertext, same_secret) = encrypt_from_seed(0x7b);
    assert_eq!(ciphertext, same_ciphertext);
    assert_eq!(secret.secret_bytes(), same_secret.secret_bytes());
    assert_eq!(&secret.secret_bytes()[..2], &[3, 3]);
    assert_eq!(
        private.decrypt(rsa::Pkcs1v15Encrypt, &ciphertext).unwrap(),
        secret.secret_bytes()
    );
    let (different_ciphertext, different_secret) = encrypt_from_seed(0x7c);
    assert_ne!(ciphertext, different_ciphertext);
    assert_ne!(secret.secret_bytes(), different_secret.secret_bytes());
}

#[test]
fn rsa_transport_encrypts_fresh_versioned_secret_and_is_never_a_default() {
    let certificate = rustls::pki_types::CertificateDer::from(
        include_bytes!("../../tests/fixtures/rsa-cert.der").as_slice(),
    );
    let private =
        RsaPrivateKey::from_pkcs8_der(include_bytes!("../../tests/fixtures/rsa-key.der")).unwrap();
    let mut previous = Vec::new();
    for _ in 0..4 {
        let (encrypted, secret) = encrypt(&certificate, rustls::ProtocolVersion::TLSv1_2).unwrap();
        assert_eq!(encrypted.len(), private.size());
        assert_eq!(secret.secret_bytes().len(), 48);
        assert_eq!(&secret.secret_bytes()[..2], &[3, 3]);
        assert_ne!(secret.secret_bytes(), previous);
        assert_eq!(
            private.decrypt(rsa::Pkcs1v15Encrypt, &encrypted).unwrap(),
            secret.secret_bytes()
        );
        previous = secret.secret_bytes().to_vec();
    }
    for suite in suites() {
        assert!(!crate::provider().cipher_suites.contains(&suite));
    }
}

#[test]
fn rsa_premaster_preserves_each_supported_client_hello_version() {
    let certificate = rustls::pki_types::CertificateDer::from(
        include_bytes!("../../tests/fixtures/rsa-cert.der").as_slice(),
    );
    let private =
        RsaPrivateKey::from_pkcs8_der(include_bytes!("../../tests/fixtures/rsa-key.der")).unwrap();
    for version in [
        rustls::ProtocolVersion::TLSv1_0,
        rustls::ProtocolVersion::TLSv1_1,
        rustls::ProtocolVersion::TLSv1_2,
    ] {
        let (encrypted, secret) = encrypt_with_seed_source(&certificate, version, |seed| {
            seed.fill(0x55);
            Ok(())
        })
        .unwrap();
        assert_eq!(
            &secret.secret_bytes()[..2],
            u16::from(version).to_be_bytes()
        );
        assert_eq!(
            private.decrypt(rsa::Pkcs1v15Encrypt, &encrypted).unwrap(),
            secret.secret_bytes()
        );
    }
    for version in [
        rustls::ProtocolVersion::SSLv3,
        rustls::ProtocolVersion::TLSv1_3,
        rustls::ProtocolVersion::Unknown(0xffff),
    ] {
        assert!(encrypt(&certificate, version).is_err());
    }
}

#[test]
fn rsa_transport_rejects_invalid_certificate_algorithm_usage_and_version() {
    let good = include_bytes!("../../tests/fixtures/rsa-cert.der").as_slice();
    let (_, parsed) = x509_parser::parse_x509_certificate(good).unwrap();
    let usage = parsed
        .extensions()
        .iter()
        .find(|extension| extension.oid.to_id_string() == "2.5.29.15")
        .unwrap();
    // This provider operates after chain verification. Change only KeyUsage
    // DER to exercise its independent encryption-purpose check.
    assert_eq!(usage.value, &[3, 2, 5, 0xa0]);
    let start = usage.value.as_ptr() as usize - good.as_ptr() as usize;
    let mut signature_only = good.to_vec();
    signature_only[start + 2] = 7;
    signature_only[start + 3] = 0x80;
    for certificate in [
        signature_only.as_slice(),
        include_bytes!("../../tests/fixtures/ecdsa-cert.der").as_slice(),
        &good[..good.len() - 1],
        &[0; 64],
    ] {
        assert!(encrypt(&certificate.into(), rustls::ProtocolVersion::TLSv1_2).is_err());
    }
    assert!(encrypt(&good.into(), rustls::ProtocolVersion::TLSv1_3).is_err());
    let mut trailing = good.to_vec();
    trailing.push(0);
    assert!(encrypt(&trailing.into(), rustls::ProtocolVersion::TLSv1_2).is_err());
}
