//! Preserve the public half of signing keys so rustls can reject mismatched
//! certificate/key pairs. The upstream alpha omitted SigningKey::public_key.
use p256::pkcs8::{DecodePrivateKey, EncodePublicKey};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use rustls::{
    Error, SignatureAlgorithm, SignatureScheme,
    crypto::KeyProvider,
    pki_types::{PrivateKeyDer, SubjectPublicKeyInfoDer},
    sign::{Signer, SigningKey},
};
use std::sync::Arc;
mod ecdsa;
mod rsa;
#[derive(Debug)]
pub(super) struct Provider;

/// Only the explicitly selected Android11 provider enables TLS 1.2 RSA/SHA-1.
#[derive(Debug)]
pub(super) struct LegacyProvider;
impl KeyProvider for LegacyProvider {
    fn supports_rsa_key_exchange(&self) -> bool {
        true
    }
    fn encrypt_tls12_rsa_premaster(
        &self,
        certificate: &rustls::pki_types::CertificateDer<'_>,
        version: rustls::ProtocolVersion,
    ) -> Result<(Vec<u8>, rustls::crypto::SharedSecret), Error> {
        crate::legacy_rsa::encrypt(certificate, version)
    }
    fn load_private_key(&self, der: PrivateKeyDer<'static>) -> Result<Arc<dyn SigningKey>, Error> {
        if let Some(key) = rsa::load_legacy(&der)? {
            return Ok(key);
        }
        Provider.load_private_key(der)
    }
}
impl KeyProvider for Provider {
    fn supports_rsa_key_exchange(&self) -> bool {
        true
    }
    fn encrypt_tls12_rsa_premaster(
        &self,
        certificate: &rustls::pki_types::CertificateDer<'_>,
        version: rustls::ProtocolVersion,
    ) -> Result<(Vec<u8>, rustls::crypto::SharedSecret), Error> {
        crate::legacy_rsa::encrypt(certificate, version)
    }
    fn load_private_key(&self, der: PrivateKeyDer<'static>) -> Result<Arc<dyn SigningKey>, Error> {
        if let Some(key) = rsa::load(&der)? {
            return Ok(key);
        }
        if let Some(key) = ecdsa::load(&der) {
            return Ok(key);
        }
        if let Some(key) = match &der {
            PrivateKeyDer::Sec1(k) => p521::SecretKey::from_sec1_der(k.secret_sec1_der()).ok(),
            PrivateKeyDer::Pkcs8(k) => p521::SecretKey::from_pkcs8_der(k.secret_pkcs8_der()).ok(),
            _ => None,
        } {
            let spki = key
                .public_key()
                .to_public_key_der()
                .map_err(|_| Error::General("invalid P-521 public key".into()))?
                .as_bytes()
                .to_vec();
            let bytes = zeroize::Zeroizing::new(key.to_bytes());
            let key = p521::ecdsa::SigningKey::from_bytes(&bytes)
                .map_err(|_| Error::General("invalid P-521 private key".into()))?;
            return Ok(Arc::new(P521Key {
                key: Arc::new(key),
                spki,
            }));
        }
        let inner = rustls_rustcrypto::provider()
            .key_provider
            .load_private_key(der.clone_key())?;
        let spki = public_key(&der)
            .ok_or_else(|| Error::General("cannot derive signing key public component".into()))?;
        Ok(Arc::new(WithPublic { inner, spki }))
    }
}

struct P521Key {
    key: Arc<p521::ecdsa::SigningKey>,
    spki: Vec<u8>,
}
impl std::fmt::Debug for P521Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("P521SigningKey")
    }
}
impl SigningKey for P521Key {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered
            .contains(&SignatureScheme::ECDSA_NISTP521_SHA512)
            .then(|| Box::new(P521Signer(self.key.clone())) as Box<dyn Signer>)
    }
    fn choose_legacy_scheme(&self) -> Option<Box<dyn Signer>> {
        Some(Box::new(LegacyP521Signer(self.key.clone())))
    }
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(self.spki.as_slice().into())
    }
}

struct LegacyP521Signer(Arc<p521::ecdsa::SigningKey>);
impl std::fmt::Debug for LegacyP521Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LegacyP521Sha1Signer")
    }
}
impl Signer for LegacyP521Signer {
    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ECDSA_SHA1_Legacy
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        self.sign_with_seed_source(message, fill_seed)
    }
}
impl LegacyP521Signer {
    fn sign_with_seed_source(
        &self,
        message: &[u8],
        source: impl FnOnce(&mut [u8; 32]) -> Result<(), Error>,
    ) -> Result<Vec<u8>, Error> {
        use p521::ecdsa::signature::hazmat::RandomizedPrehashSigner;
        use sha1::Digest;
        let mut rng = seeded_rng_with(source)?;
        let mut digest = [0u8; 66];
        digest[46..].copy_from_slice(&sha1::Sha1::digest(message));
        let signature: p521::ecdsa::Signature = self
            .0
            .sign_prehash_with_rng(&mut rng, &digest)
            .map_err(|_| Error::General("legacy P-521 signing failed".into()))?;
        Ok(signature.to_der().as_bytes().to_vec())
    }
}
struct P521Signer(Arc<p521::ecdsa::SigningKey>);
impl std::fmt::Debug for P521Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("P521Signer")
    }
}
impl Signer for P521Signer {
    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ECDSA_NISTP521_SHA512
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        self.sign_with_seed_source(message, fill_seed)
    }
}
impl P521Signer {
    fn sign_with_seed_source(
        &self,
        message: &[u8],
        source: impl FnOnce(&mut [u8; 32]) -> Result<(), Error>,
    ) -> Result<Vec<u8>, Error> {
        use p521::ecdsa::signature::RandomizedSigner;
        let mut rng = seeded_rng_with(source)?;
        let signature: p521::ecdsa::Signature = self
            .0
            .try_sign_with_rng(&mut rng, message)
            .map_err(|_| Error::General("P-521 signing failed".into()))?;
        Ok(signature.to_der().as_bytes().to_vec())
    }
}
struct WithPublic {
    inner: Arc<dyn SigningKey>,
    spki: Vec<u8>,
}
impl std::fmt::Debug for WithPublic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RustCryptoSigningKey")
            .field("algorithm", &self.inner.algorithm())
            .finish_non_exhaustive()
    }
}
impl SigningKey for WithPublic {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        self.inner.choose_scheme(offered)
    }
    fn choose_legacy_scheme(&self) -> Option<Box<dyn Signer>> {
        self.inner.choose_legacy_scheme()
    }
    fn algorithm(&self) -> SignatureAlgorithm {
        self.inner.algorithm()
    }
    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(self.spki.as_slice().into())
    }
}
fn public_key(der: &PrivateKeyDer<'_>) -> Option<Vec<u8>> {
    if let Some(key) = match der {
        PrivateKeyDer::Sec1(k) => p256::SecretKey::from_sec1_der(k.secret_sec1_der()).ok(),
        PrivateKeyDer::Pkcs8(k) => p256::SecretKey::from_pkcs8_der(k.secret_pkcs8_der()).ok(),
        _ => None,
    } {
        return key
            .public_key()
            .to_public_key_der()
            .ok()
            .map(|v| v.as_bytes().to_vec());
    }
    if let Some(key) = match der {
        PrivateKeyDer::Sec1(k) => p384::SecretKey::from_sec1_der(k.secret_sec1_der()).ok(),
        PrivateKeyDer::Pkcs8(k) => p384::SecretKey::from_pkcs8_der(k.secret_pkcs8_der()).ok(),
        _ => None,
    } {
        return key
            .public_key()
            .to_public_key_der()
            .ok()
            .map(|v| v.as_bytes().to_vec());
    }
    if let PrivateKeyDer::Pkcs8(k) = der {
        if let Ok(key) = ed25519_dalek::SigningKey::from_pkcs8_der(k.secret_pkcs8_der()) {
            return key
                .verifying_key()
                .to_public_key_der()
                .ok()
                .map(|v| v.as_bytes().to_vec());
        }
    }
    None
}

fn fill_seed(seed: &mut [u8; 32]) -> Result<(), Error> {
    rand_core::OsRng
        .try_fill_bytes(seed)
        .map_err(|_| Error::FailedToGetRandomBytes)
}

fn seeded_rng_with(
    source: impl FnOnce(&mut [u8; 32]) -> Result<(), Error>,
) -> Result<ChaCha20Rng, Error> {
    // RSA padding/blinding and P-521 nonce generation call infallible
    // RngCore methods. Only this fallible OS request supplies entropy; the
    // local CSPRNG cannot panic because an OS request failed mid-signature.
    // The temporary seed is erased. rand_chacha 0.3 does not provide wiping
    // of its internal state/buffer, so those copies are not guaranteed erased.
    let mut seed = zeroize::Zeroizing::new([0; 32]);
    source(&mut seed)?;
    Ok(ChaCha20Rng::from_seed(*seed))
}

#[cfg(test)]
mod legacy_tests {
    use super::*;
    #[test]
    fn p521_legacy_signer_uses_fallible_seeded_prehash_signing() {
        use p521::ecdsa::signature::hazmat::PrehashVerifier;
        use sha1::Digest;
        let key = p521::SecretKey::from_pkcs8_der(include_bytes!("../tests/fixtures/p521-key.der"))
            .unwrap();
        let key = Arc::new(p521::ecdsa::SigningKey::from_bytes(&key.to_bytes()).unwrap());
        let signer = LegacyP521Signer(key.clone());
        assert!(matches!(
            signer.sign_with_seed_source(b"old TLS", |seed| {
                seed[..16].fill(1);
                Err(Error::FailedToGetRandomBytes)
            }),
            Err(Error::FailedToGetRandomBytes)
        ));
        let calls = std::cell::Cell::new(0);
        let signature = signer
            .sign_with_seed_source(b"old TLS", |seed| {
                calls.set(calls.get() + 1);
                seed.fill(7);
                Ok(())
            })
            .unwrap();
        assert_eq!(calls.get(), 1);
        let mut hash = [0; 66];
        hash[46..].copy_from_slice(&sha1::Sha1::digest(b"old TLS"));
        p521::ecdsa::VerifyingKey::from(key.as_ref())
            .verify_prehash(
                &hash,
                &p521::ecdsa::Signature::from_der(&signature).unwrap(),
            )
            .unwrap();
    }
}
