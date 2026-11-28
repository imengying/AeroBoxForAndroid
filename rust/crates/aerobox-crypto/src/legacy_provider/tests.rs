use super::*;
use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey};
use rustls::{crypto::KeyProvider, pki_types::PrivateKeyDer};

const MESSAGE: &[u8] = b"client random/server random/encoded ECDHE params";

fn rsa_key() -> PrivateKeyDer<'static> {
    PrivateKeyDer::Pkcs8(
        include_bytes!("../../tests/fixtures/rsa-key.der")
            .as_slice()
            .into(),
    )
}

#[test]
fn android11_provider_has_exact_cipher_signature_and_group_order() {
    let legacy = provider();
    let ciphers: Vec<_> = legacy
        .cipher_suites
        .iter()
        .map(|suite| u16::from(suite.suite()))
        .collect();
    assert_eq!(
        ciphers,
        [
            0xc02b, 0xc02c, 0xcca9, 0xc02f, 0xc030, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f,
            0x0035
        ]
    );
    let signatures: Vec<_> = legacy
        .signature_verification_algorithms
        .supported_schemes()
        .into_iter()
        .map(u16::from)
        .collect();
    assert_eq!(
        signatures,
        [
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201
        ]
    );
    let groups: Vec<_> = legacy
        .kx_groups
        .iter()
        .map(|group| u16::from(group.name()))
        .collect();
    assert_eq!(groups, [29, 23, 24]);
    let ordinary = crate::provider();
    assert!(
        !ordinary
            .signature_verification_algorithms
            .supported_schemes()
            .contains(&SignatureScheme::RSA_PKCS1_SHA1)
    );
    // The old handshake policy does not add SHA-1 to X.509 chain verification.
    assert_eq!(
        legacy.signature_verification_algorithms.all.len(),
        ordinary.signature_verification_algorithms.all.len()
    );
    for (legacy, ordinary) in legacy
        .signature_verification_algorithms
        .all
        .iter()
        .zip(ordinary.signature_verification_algorithms.all)
    {
        assert_eq!(legacy.public_key_alg_id(), ordinary.public_key_alg_id());
        assert_eq!(legacy.signature_alg_id(), ordinary.signature_alg_id());
    }
    for suite in &ANDROID11_TLS12 {
        assert_eq!(
            suite.common.hash_provider.output_len(),
            if matches!(
                suite.common.suite,
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                    | CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                    | CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384
            ) {
                48
            } else {
                32
            }
        );
    }
}

#[test]
fn legacy_suite_mapping_binds_real_prf_hash_iv_shape_and_rejects_aead() {
    for version in [ProtocolVersion::TLSv1_0, ProtocolVersion::TLSv1_1] {
        for id in [0xc013, 0xc014, 0xc009, 0xc00a, 0x002f, 0x0035] {
            let suite = LEGACY_TLS
                .cipher_suite(CipherSuite::from(id), version)
                .unwrap();
            assert_eq!(u16::from(suite.common.suite), id);
            assert_eq!(
                suite.common.hash_provider.algorithm(),
                rustls::crypto::hash::HashAlgorithm::MD5_SHA1
            );
            assert_eq!(suite.common.hash_provider.output_len(), 36);
            assert_eq!(suite.aead_alg.mac_key_len(), 20);
            let shape = suite.aead_alg.key_block_shape();
            assert_eq!(
                shape.enc_key_len,
                if matches!(id, 0xc013 | 0xc009 | 0x002f) {
                    16
                } else {
                    32
                }
            );
            assert_eq!(
                shape.fixed_iv_len,
                if version == ProtocolVersion::TLSv1_0 {
                    16
                } else {
                    0
                }
            );
            let mut actual = [0; 48];
            let mut expected = [0; 48];
            suite
                .prf_provider
                .for_secret(&mut actual, b"secret", b"master secret", b"randoms");
            rustls::crypto::tls12::Prf::for_secret(
                &crate::legacy_prf::TLS10_PRF,
                &mut expected,
                b"secret",
                b"master secret",
                b"randoms",
            );
            assert_eq!(actual, expected);
            assert_eq!(
                suite.sign,
                if matches!(id, 0xc009 | 0xc00a) {
                    &[SignatureScheme::ECDSA_SHA1_Legacy]
                } else {
                    &[SignatureScheme::RSA_PKCS1_MD5_SHA1_Legacy]
                }
            );
        }
        for id in [0xc02b, 0xc02f, 0x009c, 0x1301, 0xffff] {
            assert!(
                LEGACY_TLS
                    .cipher_suite(CipherSuite::from(id), version)
                    .is_none()
            );
        }
    }
    for version in [
        ProtocolVersion::SSLv3,
        ProtocolVersion::TLSv1_2,
        ProtocolVersion::TLSv1_3,
    ] {
        assert!(
            LEGACY_TLS
                .cipher_suite(CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, version)
                .is_none()
        );
    }
}

#[test]
fn old_rsa_signer_hashes_the_original_message_and_rejects_wrong_certificate_algorithm() {
    let key = provider().key_provider.load_private_key(rsa_key()).unwrap();
    let signer = key.choose_legacy_scheme().unwrap();
    assert_eq!(signer.scheme(), SignatureScheme::RSA_PKCS1_MD5_SHA1_Legacy);
    let signature = signer.sign(MESSAGE).unwrap();
    let cert = CertificateDer::from(include_bytes!("../../tests/fixtures/rsa-cert.der").as_slice());
    LEGACY_TLS
        .verify_signature(MESSAGE, &cert, SignatureAlgorithm::RSA, &signature)
        .unwrap();
    assert!(
        LEGACY_TLS
            .verify_signature(b"wrong", &cert, SignatureAlgorithm::RSA, &signature)
            .is_err()
    );
    assert!(
        LEGACY_TLS
            .verify_signature(MESSAGE, &cert, SignatureAlgorithm::ECDSA, &signature)
            .is_err()
    );
    assert!(
        LEGACY_TLS
            .verify_signature(MESSAGE, &cert, SignatureAlgorithm::ED25519, &signature)
            .is_err()
    );
    let independent_signature = include_bytes!("../legacy_sign/fixtures/rsa-md5-sha1.sig");
    assert_eq!(
        signer
            .sign(include_bytes!("../legacy_sign/fixtures/message.bin"))
            .unwrap(),
        independent_signature
    );
}

#[test]
fn tls12_sha1_with_digest_info_is_opt_in_and_distinct_from_raw_old_rsa() {
    let ordinary = crate::provider()
        .key_provider
        .load_private_key(rsa_key())
        .unwrap();
    assert!(
        ordinary
            .choose_scheme(&[SignatureScheme::RSA_PKCS1_SHA1])
            .is_none()
    );
    let legacy = provider();
    let key = legacy.key_provider.load_private_key(rsa_key()).unwrap();
    let signer = key
        .choose_scheme(&[SignatureScheme::RSA_PKCS1_SHA1])
        .unwrap();
    assert_eq!(signer.scheme(), SignatureScheme::RSA_PKCS1_SHA1);
    let signature = signer.sign(MESSAGE).unwrap();
    let raw = key.choose_legacy_scheme().unwrap().sign(MESSAGE).unwrap();
    let private =
        rsa::RsaPrivateKey::from_pkcs8_der(include_bytes!("../../tests/fixtures/rsa-key.der"))
            .unwrap();
    let public = private.to_public_key().to_public_key_der().unwrap();
    use rsa::pkcs8::der::Decode;
    let spki = rsa::pkcs8::SubjectPublicKeyInfoRef::from_der(public.as_bytes()).unwrap();
    let raw_key = spki.subject_public_key.as_bytes().unwrap();
    let verifier = legacy
        .signature_verification_algorithms
        .mapping
        .iter()
        .find(|(scheme, _)| *scheme == SignatureScheme::RSA_PKCS1_SHA1)
        .unwrap()
        .1[0];
    verifier
        .verify_signature(raw_key, MESSAGE, &signature)
        .unwrap();
    assert!(verifier.verify_signature(raw_key, MESSAGE, &raw).is_err());
    assert!(
        verifier
            .verify_signature(raw_key, b"changed", &signature)
            .is_err()
    );
    let cert = CertificateDer::from(include_bytes!("../../tests/fixtures/rsa-cert.der").as_slice());
    assert!(
        LEGACY_TLS
            .verify_signature(MESSAGE, &cert, SignatureAlgorithm::RSA, &signature)
            .is_err()
    );
    for suite in ANDROID11_TLS12.iter().filter(|suite| {
        !matches!(
            suite.common.suite,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                | CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                | CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        )
    }) {
        assert_eq!(
            suite.resolve_sig_schemes(&[SignatureScheme::RSA_PKCS1_SHA1]),
            [SignatureScheme::RSA_PKCS1_SHA1]
        );
    }
}

#[test]
fn legacy_p256_and_p521_signers_verify_against_authenticated_leaf_certificates() {
    for (key, cert) in [
        (
            include_bytes!("../../tests/fixtures/ecdsa-key.der").as_slice(),
            include_bytes!("../../tests/fixtures/ecdsa-cert.der").as_slice(),
        ),
        (
            include_bytes!("../../tests/fixtures/p521-key.der").as_slice(),
            include_bytes!("../../tests/fixtures/p521-cert.der").as_slice(),
        ),
    ] {
        let key = provider()
            .key_provider
            .load_private_key(PrivateKeyDer::Pkcs8(key.into()))
            .unwrap();
        let signer = key.choose_legacy_scheme().unwrap();
        assert_eq!(signer.scheme(), SignatureScheme::ECDSA_SHA1_Legacy);
        let signature = signer.sign(MESSAGE).unwrap();
        let cert = CertificateDer::from(cert);
        LEGACY_TLS
            .verify_signature(MESSAGE, &cert, SignatureAlgorithm::ECDSA, &signature)
            .unwrap();
        assert!(
            LEGACY_TLS
                .verify_signature(b"changed", &cert, SignatureAlgorithm::ECDSA, &signature)
                .is_err()
        );
        assert!(
            LEGACY_TLS
                .verify_signature(MESSAGE, &cert, SignatureAlgorithm::RSA, &signature)
                .is_err()
        );
        let mut corrupted = signature.clone();
        *corrupted.last_mut().unwrap() ^= 0x80;
        assert!(
            LEGACY_TLS
                .verify_signature(MESSAGE, &cert, SignatureAlgorithm::ECDSA, &corrupted)
                .is_err()
        );
    }
}

#[test]
fn p384_legacy_sha1_and_ed25519_rejection_use_explicit_signer_selection() {
    use p384::ecdsa::signature::hazmat::PrehashVerifier;
    use p384::pkcs8::EncodePrivateKey;
    use sha1::Digest;
    let secret = p384::SecretKey::from_slice(&[0x13; 48]).unwrap();
    let public = p384::ecdsa::VerifyingKey::from(secret.public_key());
    let private = secret.to_pkcs8_der().unwrap();
    let key = provider()
        .key_provider
        .load_private_key(PrivateKeyDer::Pkcs8(private.as_bytes().to_vec().into()))
        .unwrap();
    let signature = key.choose_legacy_scheme().unwrap().sign(MESSAGE).unwrap();
    let signature = p384::ecdsa::Signature::from_der(&signature).unwrap();
    let mut digest = [0; 48];
    digest[28..].copy_from_slice(&sha1::Sha1::digest(MESSAGE));
    public.verify_prehash(&digest, &signature).unwrap();
    digest[47] ^= 1;
    assert!(public.verify_prehash(&digest, &signature).is_err());
    let ed25519 = ed25519_dalek::SigningKey::from_bytes(&[7; 32])
        .to_pkcs8_der()
        .unwrap();
    let key = provider()
        .key_provider
        .load_private_key(PrivateKeyDer::Pkcs8(ed25519.as_bytes().to_vec().into()))
        .unwrap();
    assert!(key.choose_legacy_scheme().is_none());
}
