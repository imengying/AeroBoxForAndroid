use super::*;
use ::rsa::pkcs8::EncodePrivateKey;
use rustls::crypto::KeyProvider;

const MESSAGE: &[u8] = b"AeroBox seeded RSA signature regression";

fn private_key() -> Arc<RsaPrivateKey> {
    Arc::new(
        RsaPrivateKey::from_pkcs8_der(include_bytes!("../../../tests/fixtures/rsa-key.der"))
            .unwrap(),
    )
}

fn verify(key: &RsaPrivateKey, scheme: SignatureScheme, message: &[u8], signature: &[u8]) -> bool {
    let key = key.to_public_key();
    macro_rules! pkcs1 {
        ($hash:ty) => {
            key.verify(
                ::rsa::Pkcs1v15Sign::new::<$hash>(),
                &<$hash>::digest(message),
                signature,
            )
        };
    }
    macro_rules! pss {
        ($hash:ty) => {
            key.verify(
                ::rsa::Pss::new::<$hash>(),
                &<$hash>::digest(message),
                signature,
            )
        };
    }
    match scheme {
        SignatureScheme::RSA_PSS_SHA512 => pss!(Sha512),
        SignatureScheme::RSA_PSS_SHA384 => pss!(Sha384),
        SignatureScheme::RSA_PSS_SHA256 => pss!(Sha256),
        SignatureScheme::RSA_PKCS1_SHA512 => pkcs1!(Sha512),
        SignatureScheme::RSA_PKCS1_SHA384 => pkcs1!(Sha384),
        SignatureScheme::RSA_PKCS1_SHA256 => pkcs1!(Sha256),
        _ => unreachable!(),
    }
    .is_ok()
}

#[test]
fn rsa_signer_preserves_scheme_preference_and_public_key_matching() {
    let der = PrivateKeyDer::Pkcs8(
        include_bytes!("../../../tests/fixtures/rsa-key.der")
            .as_slice()
            .into(),
    );
    let key = super::super::Provider
        .load_private_key(der.clone_key())
        .unwrap();
    assert_eq!(key.algorithm(), SignatureAlgorithm::RSA);
    for index in 0..SCHEMES.len() {
        let mut offered = SCHEMES[index..].to_vec();
        offered.reverse();
        assert_eq!(
            key.choose_scheme(&offered).unwrap().scheme(),
            SCHEMES[index]
        );
    }
    assert!(
        key.choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
            .is_none()
    );
    let (_, cert) =
        x509_parser::parse_x509_certificate(include_bytes!("../../../tests/fixtures/rsa-cert.der"))
            .unwrap();
    assert_eq!(key.public_key().unwrap().as_ref(), cert.public_key().raw);
    let certified = rustls::sign::CertifiedKey::new(
        vec![
            include_bytes!("../../../tests/fixtures/rsa-cert.der")
                .as_slice()
                .into(),
        ],
        key,
    );
    certified.keys_match().unwrap();
}

#[test]
fn all_six_rsa_signers_use_one_seed_and_reject_modified_messages() {
    let private = private_key();
    for &scheme in SCHEMES {
        let signer = RsaSigner {
            key: private.clone(),
            scheme,
        };
        let calls = std::cell::Cell::new(0);
        let signature = signer
            .sign_with_seed_source(MESSAGE, |seed| {
                calls.set(calls.get() + 1);
                seed.fill(0x25);
                Ok(())
            })
            .unwrap();
        assert_eq!(calls.get(), 1);
        assert!(verify(&private, scheme, MESSAGE, &signature), "{scheme:?}");
        assert!(!verify(&private, scheme, b"altered message", &signature));
        let mut corrupted = signature.clone();
        corrupted[0] ^= 1;
        assert!(!verify(&private, scheme, MESSAGE, &corrupted));
        let signature2 = signer.sign(MESSAGE).unwrap();
        assert!(verify(&private, scheme, MESSAGE, &signature2));
        if matches!(
            scheme,
            SignatureScheme::RSA_PSS_SHA256
                | SignatureScheme::RSA_PSS_SHA384
                | SignatureScheme::RSA_PSS_SHA512
        ) {
            assert_ne!(signature, signature2, "fresh PSS salt");
        } else {
            assert_eq!(
                signature, signature2,
                "PKCS#1 blinding must preserve its signature"
            );
        }
    }
}

#[test]
fn rsa_signers_return_partial_entropy_failure_for_every_scheme() {
    let private = private_key();
    for &scheme in SCHEMES {
        let signer = RsaSigner {
            key: private.clone(),
            scheme,
        };
        let result = signer.sign_with_seed_source(MESSAGE, |seed| {
            seed[..16].fill(0x66);
            Err(Error::FailedToGetRandomBytes)
        });
        assert!(matches!(result, Err(Error::FailedToGetRandomBytes)));
    }
}

#[test]
fn rsa_key_size_and_der_kind_are_enforced_before_fallback() {
    let small = RsaPrivateKey::from_components(
        3233u32.into(),
        17u32.into(),
        2753u32.into(),
        vec![61u32.into(), 53u32.into()],
    )
    .unwrap()
    .to_pkcs8_der()
    .unwrap();
    let error = load(&PrivateKeyDer::Pkcs8(small.as_bytes().into())).unwrap_err();
    assert!(error.to_string().contains("2048..8192"));
    let p256 = PrivateKeyDer::Pkcs8(
        include_bytes!("../../../tests/fixtures/ecdsa-key.der")
            .as_slice()
            .into(),
    );
    assert!(load(&p256).unwrap().is_none());
    assert!(load(&PrivateKeyDer::Pkcs1(vec![0; 6145].into())).is_err());
}

#[test]
fn p521_signer_returns_entropy_failure_and_uses_seeded_nonce() {
    use p521::ecdsa::signature::Verifier;
    let key =
        p521::SecretKey::from_pkcs8_der(include_bytes!("../../../tests/fixtures/p521-key.der"))
            .unwrap();
    let bytes = zeroize::Zeroizing::new(key.to_bytes());
    let key = Arc::new(p521::ecdsa::SigningKey::from_bytes(&bytes).unwrap());
    let signer = super::super::P521Signer(key.clone());
    let result = signer.sign_with_seed_source(MESSAGE, |seed| {
        seed[..16].fill(0x55);
        Err(Error::FailedToGetRandomBytes)
    });
    assert!(matches!(result, Err(Error::FailedToGetRandomBytes)));
    let signature = signer
        .sign_with_seed_source(MESSAGE, |seed| {
            seed.fill(0x33);
            Ok(())
        })
        .unwrap();
    let signature = p521::ecdsa::Signature::from_der(&signature).unwrap();
    let public = p521::ecdsa::VerifyingKey::from(key.as_ref());
    public.verify(MESSAGE, &signature).unwrap();
    assert!(public.verify(b"wrong message", &signature).is_err());
}
