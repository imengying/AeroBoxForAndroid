//! Extend ECDSA with P-521/SHA-512 and enforce explicit RSA key size bounds.
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use rustls::{
    SignatureScheme,
    crypto::WebPkiSupportedAlgorithms,
    pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm, alg_id},
};
use sha2::Digest;
use std::sync::OnceLock;

mod rsa;

macro_rules! verifier {
    ($name:ident, $curve:ident, $public_id:ident, $hash:ident, $signature_id:ident) => {
        #[derive(Debug)]
        struct $name;
        impl SignatureVerificationAlgorithm for $name {
            fn public_key_alg_id(&self) -> AlgorithmIdentifier {
                alg_id::$public_id
            }
            fn signature_alg_id(&self) -> AlgorithmIdentifier {
                alg_id::$signature_id
            }
            fn verify_signature(
                &self,
                public_key: &[u8],
                message: &[u8],
                signature: &[u8],
            ) -> Result<(), InvalidSignature> {
                let key = $curve::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
                    .map_err(|_| InvalidSignature)?;
                let signature =
                    $curve::ecdsa::Signature::from_der(signature).map_err(|_| InvalidSignature)?;
                let digest = sha2::$hash::digest(message);
                // ECDSA interprets shorter digests as an integer with leading
                // zeroes. RustCrypto rejects SHA-256's 32 bytes for P-521
                // before doing that padding (its minimum is 66 / 2 bytes).
                let mut padded = [0u8; 66];
                let hash = if alg_id::$public_id == alg_id::ECDSA_P521 {
                    padded[66 - digest.len()..].copy_from_slice(&digest);
                    padded.as_slice()
                } else {
                    digest.as_slice()
                };
                key.verify_prehash(hash, &signature)
                    .map_err(|_| InvalidSignature)
            }
        }
    };
}
verifier!(P521Sha256, p521, ECDSA_P521, Sha256, ECDSA_SHA256);
verifier!(P521Sha384, p521, ECDSA_P521, Sha384, ECDSA_SHA384);
verifier!(P521Sha512, p521, ECDSA_P521, Sha512, ECDSA_SHA512);
verifier!(P256Sha512, p256, ECDSA_P256, Sha512, ECDSA_SHA512);
verifier!(P384Sha512, p384, ECDSA_P384, Sha512, ECDSA_SHA512);

pub(super) fn algorithms() -> WebPkiSupportedAlgorithms {
    static ALGORITHMS: OnceLock<WebPkiSupportedAlgorithms> = OnceLock::new();
    *ALGORITHMS.get_or_init(|| {
        let base = rustls_rustcrypto::provider().signature_verification_algorithms;
        let replace = |algorithm: &'static dyn SignatureVerificationAlgorithm| {
            if algorithm.public_key_alg_id() == alg_id::RSA_ENCRYPTION {
                rsa::replacement(algorithm.signature_alg_id()).unwrap_or(algorithm)
            } else {
                algorithm
            }
        };
        let mut all: Vec<_> = base.all.iter().copied().map(replace).collect();
        all.extend_from_slice(&[
            &P521Sha256,
            &P521Sha384,
            &P521Sha512,
            &P256Sha512,
            &P384Sha512,
        ]);
        let mut mapping = base.mapping.to_vec();
        for (scheme, algorithms) in &mut mapping {
            if algorithms
                .iter()
                .any(|v| v.public_key_alg_id() == alg_id::RSA_ENCRYPTION)
            {
                *algorithms = Box::leak(
                    algorithms
                        .iter()
                        .copied()
                        .map(replace)
                        .collect::<Vec<_>>()
                        .into_boxed_slice(),
                );
            }
            let extra: Option<&'static dyn SignatureVerificationAlgorithm> = match scheme {
                SignatureScheme::ECDSA_NISTP256_SHA256 => Some(&P521Sha256),
                SignatureScheme::ECDSA_NISTP384_SHA384 => Some(&P521Sha384),
                _ => None,
            };
            if let Some(extra) = extra {
                let mut extended = algorithms.to_vec();
                extended.push(extra);
                *algorithms = Box::leak(extended.into_boxed_slice());
            }
        }
        // TLS 1.3 takes the first algorithm (fixed curve); TLS 1.2 can try all.
        mapping.push((
            SignatureScheme::ECDSA_NISTP521_SHA512,
            &[&P521Sha512, &P256Sha512, &P384Sha512],
        ));
        WebPkiSupportedAlgorithms {
            all: Box::leak(all.into_boxed_slice()),
            mapping: Box::leak(mapping.into_boxed_slice()),
        }
    })
}

/// TLS 1.2 handshake-only RSA/SHA-1 verifier. This is intentionally absent from
/// the normal provider and from the certificate-chain algorithm collection.
#[derive(Debug)]
struct LegacyRsaSha1;
impl SignatureVerificationAlgorithm for LegacyRsaSha1 {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_ENCRYPTION
    }
    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        // RFC 3279 sha1WithRSAEncryption (1.2.840.113549.1.1.5), NULL parameters;
        // AlgorithmIdentifier stores the SEQUENCE contents, not its outer tag.
        AlgorithmIdentifier::from_slice(&[
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00,
        ])
    }
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        use ::rsa::traits::PublicKeyParts;
        let key = crate::legacy_sign::rsa_public_key_from_pkcs1(public_key)
            .map_err(|_| InvalidSignature)?;
        if signature.len() != key.size() {
            return Err(InvalidSignature);
        }
        key.verify(
            crate::legacy_sign::rsa_sha1_padding(),
            &sha1::Sha1::digest(message),
            signature,
        )
        .map_err(|_| InvalidSignature)
    }
}

/// Exact Android 11 signature_algorithms order from fixed uTLS v1.8.7.
pub(super) const ANDROID11_SIGNATURE_SCHEMES: [SignatureScheme; 9] = [
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA256,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA1,
];

pub(super) fn android11_algorithms() -> WebPkiSupportedAlgorithms {
    static ALGORITHMS: OnceLock<WebPkiSupportedAlgorithms> = OnceLock::new();
    *ALGORITHMS.get_or_init(|| {
        let base = algorithms();
        let mapping: Vec<_> = ANDROID11_SIGNATURE_SCHEMES
            .into_iter()
            .map(|scheme| {
                let implementations: &'static [&'static dyn SignatureVerificationAlgorithm] =
                    if scheme == SignatureScheme::RSA_PKCS1_SHA1 {
                        &[&LegacyRsaSha1]
                    } else {
                        base.mapping
                            .iter()
                            .find(|(entry, _)| *entry == scheme)
                            .expect("Android11 requires an implemented signature verifier")
                            .1
                    };
                (scheme, implementations)
            })
            .collect();
        WebPkiSupportedAlgorithms {
            // Enabling old TLS handshake signatures does not enable SHA-1 CA
            // signatures or alter normal certificate-chain validation policy.
            all: base.all,
            mapping: Box::leak(mapping.into_boxed_slice()),
        }
    })
}
