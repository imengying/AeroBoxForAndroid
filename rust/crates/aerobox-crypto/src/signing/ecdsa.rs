//! Retain RustCrypto's randomized ECDSA while making OS entropy errors fallible.
use super::*;

macro_rules! implementation {
    ($curve:ident, $key:ident, $signer:ident, $legacy_signer:ident, $scheme:ident, $field_len:expr) => {
        struct $key {
            key: Arc<$curve::ecdsa::SigningKey>,
            spki: Vec<u8>,
        }
        impl std::fmt::Debug for $key {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(stringify!($key))
            }
        }
        impl $key {
            fn load(der: &PrivateKeyDer<'_>) -> Option<Self> {
                let key = match der {
                    PrivateKeyDer::Sec1(k) => {
                        $curve::SecretKey::from_sec1_der(k.secret_sec1_der()).ok()
                    }
                    PrivateKeyDer::Pkcs8(k) => {
                        $curve::SecretKey::from_pkcs8_der(k.secret_pkcs8_der()).ok()
                    }
                    _ => None,
                }?;
                let spki = key
                    .public_key()
                    .to_public_key_der()
                    .ok()?
                    .as_bytes()
                    .to_vec();
                let bytes = zeroize::Zeroizing::new(key.to_bytes());
                let key = Arc::new($curve::ecdsa::SigningKey::from_bytes(&bytes).ok()?);
                Some(Self { key, spki })
            }
        }
        impl SigningKey for $key {
            fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
                offered
                    .contains(&SignatureScheme::$scheme)
                    .then(|| Box::new($signer(self.key.clone())) as Box<dyn Signer>)
            }
            fn choose_legacy_scheme(&self) -> Option<Box<dyn Signer>> {
                Some(Box::new($legacy_signer(self.key.clone())))
            }
            fn algorithm(&self) -> SignatureAlgorithm {
                SignatureAlgorithm::ECDSA
            }
            fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
                Some(self.spki.as_slice().into())
            }
        }
        struct $signer(Arc<$curve::ecdsa::SigningKey>);
        impl std::fmt::Debug for $signer {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(stringify!($signer))
            }
        }
        impl Signer for $signer {
            fn scheme(&self) -> SignatureScheme {
                SignatureScheme::$scheme
            }
            fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
                self.sign_with_seed_source(message, fill_seed)
            }
        }
        impl $signer {
            fn sign_with_seed_source(
                &self,
                message: &[u8],
                source: impl FnOnce(&mut [u8; 32]) -> Result<(), Error>,
            ) -> Result<Vec<u8>, Error> {
                use $curve::ecdsa::signature::RandomizedSigner;
                let mut rng = seeded_rng_with(source)?;
                let signature: $curve::ecdsa::Signature = self
                    .0
                    .try_sign_with_rng(&mut rng, message)
                    .map_err(|_| Error::General("ECDSA signing failed".into()))?;
                Ok(signature.to_der().as_bytes().to_vec())
            }
        }
        struct $legacy_signer(Arc<$curve::ecdsa::SigningKey>);
        impl std::fmt::Debug for $legacy_signer {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(stringify!($legacy_signer))
            }
        }
        impl Signer for $legacy_signer {
            fn scheme(&self) -> SignatureScheme {
                SignatureScheme::ECDSA_SHA1_Legacy
            }
            fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
                self.sign_with_seed_source(message, fill_seed)
            }
        }
        impl $legacy_signer {
            fn sign_with_seed_source(
                &self,
                message: &[u8],
                source: impl FnOnce(&mut [u8; 32]) -> Result<(), Error>,
            ) -> Result<Vec<u8>, Error> {
                use sha1::Digest;
                use $curve::ecdsa::signature::hazmat::RandomizedPrehashSigner;
                let mut rng = seeded_rng_with(source)?;
                // ECDSA's SHA-1 integer is left-padded, never rehashed. The
                // prehash API otherwise rejects a short SHA-1 digest on P-384.
                let mut hash = [0; $field_len];
                hash[$field_len - 20..].copy_from_slice(&sha1::Sha1::digest(message));
                let signature: $curve::ecdsa::Signature = self
                    .0
                    .sign_prehash_with_rng(&mut rng, &hash)
                    .map_err(|_| Error::General("legacy ECDSA signing failed".into()))?;
                Ok(signature.to_der().as_bytes().to_vec())
            }
        }
    };
}
implementation!(
    p256,
    P256Key,
    P256Signer,
    LegacyP256Signer,
    ECDSA_NISTP256_SHA256,
    32
);
implementation!(
    p384,
    P384Key,
    P384Signer,
    LegacyP384Signer,
    ECDSA_NISTP384_SHA384,
    48
);

pub(super) fn load(der: &PrivateKeyDer<'_>) -> Option<Arc<dyn SigningKey>> {
    P256Key::load(der)
        .map(|key| Arc::new(key) as Arc<dyn SigningKey>)
        .or_else(|| P384Key::load(der).map(|key| Arc::new(key) as Arc<dyn SigningKey>))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::{ecdsa::signature::Verifier, pkcs8::EncodePrivateKey};
    macro_rules! check {
        ($name:ident, $curve:ident, $key:ident, $signer:ident, $legacy:ident, $bytes:expr) => {
            #[test]
            fn $name() {
                let secret = $curve::SecretKey::from_slice(&$bytes).unwrap();
                let der = secret.to_pkcs8_der().unwrap();
                let der = PrivateKeyDer::Pkcs8(der.as_bytes().to_vec().into());
                let key = $key::load(&der).unwrap();
                let signer = $signer(key.key.clone());
                assert!(matches!(
                    signer.sign_with_seed_source(b"test", |seed| {
                        seed[..16].fill(1);
                        Err(Error::FailedToGetRandomBytes)
                    }),
                    Err(Error::FailedToGetRandomBytes)
                ));
                let calls = std::cell::Cell::new(0);
                let signature = signer
                    .sign_with_seed_source(b"test", |seed| {
                        calls.set(calls.get() + 1);
                        seed.fill(2);
                        Ok(())
                    })
                    .unwrap();
                assert_eq!(calls.get(), 1);
                let signature = $curve::ecdsa::Signature::from_der(&signature).unwrap();
                key.key.verifying_key().verify(b"test", &signature).unwrap();
                assert!(
                    key.key
                        .verifying_key()
                        .verify(b"changed", &signature)
                        .is_err()
                );
                let loaded = Provider.load_private_key(der).unwrap();
                assert_eq!(loaded.algorithm(), SignatureAlgorithm::ECDSA);
                assert_eq!(loaded.public_key().unwrap().as_ref(), key.spki);
                assert_eq!(
                    loaded.choose_scheme(&[signer.scheme()]).unwrap().scheme(),
                    signer.scheme()
                );
                assert!(
                    loaded
                        .choose_scheme(&[SignatureScheme::RSA_PSS_SHA256])
                        .is_none()
                );
                let legacy = $legacy(key.key.clone());
                assert!(matches!(
                    legacy.sign_with_seed_source(b"old TLS", |seed| {
                        seed[..16].fill(1);
                        Err(Error::FailedToGetRandomBytes)
                    }),
                    Err(Error::FailedToGetRandomBytes)
                ));
                let calls = std::cell::Cell::new(0);
                let signature = legacy
                    .sign_with_seed_source(b"old TLS", |seed| {
                        calls.set(calls.get() + 1);
                        seed.fill(5);
                        Ok(())
                    })
                    .unwrap();
                assert_eq!(calls.get(), 1);
                use sha1::Digest;
                use $curve::ecdsa::signature::hazmat::PrehashVerifier;
                let mut hash = vec![0; ($bytes).len()];
                let start = hash.len() - 20;
                hash[start..].copy_from_slice(&sha1::Sha1::digest(b"old TLS"));
                key.key
                    .verifying_key()
                    .verify_prehash(
                        &hash,
                        &$curve::ecdsa::Signature::from_der(&signature).unwrap(),
                    )
                    .unwrap();
            }
        };
    }
    check!(
        p256_entropy_error_and_seeded_nonce,
        p256,
        P256Key,
        P256Signer,
        LegacyP256Signer,
        [1u8; 32]
    );
    check!(
        p384_entropy_error_and_seeded_nonce,
        p384,
        P384Key,
        P384Signer,
        LegacyP384Signer,
        [1u8; 48]
    );
}
