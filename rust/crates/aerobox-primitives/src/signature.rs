//! Ed25519 and ML-DSA signatures used by REALITY.
use crate::{
    error::Unspecified,
    rand::{SecureRandom, SystemRandom},
};
use ed25519_dalek::{Signer as _, pkcs8::DecodePrivateKey};
use ml_dsa::{Keypair as _, Signer as _, Verifier as _};
use zeroize::Zeroizing;

pub struct PublicKey(Vec<u8>);
impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
pub struct Signature(Vec<u8>);
impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
pub trait KeyPair {
    fn public_key(&self) -> &PublicKey;
}
pub struct Ed25519KeyPair {
    key: ed25519_dalek::SigningKey,
    public: PublicKey,
}
impl Ed25519KeyPair {
    fn from_key(key: ed25519_dalek::SigningKey) -> Self {
        let public = PublicKey(key.verifying_key().to_bytes().to_vec());
        Self { key, public }
    }
    pub fn generate() -> Result<Self, Unspecified> {
        let mut seed = Zeroizing::new([0; 32]);
        SystemRandom::new().fill(seed.as_mut())?;
        Ok(Self::from_key(ed25519_dalek::SigningKey::from_bytes(&seed)))
    }
    pub fn from_seed_unchecked(seed: &[u8]) -> Result<Self, Unspecified> {
        let seed = seed.try_into().map_err(|_| Unspecified)?;
        Ok(Self::from_key(ed25519_dalek::SigningKey::from_bytes(seed)))
    }
    pub fn from_pkcs8(bytes: &[u8]) -> Result<Self, Unspecified> {
        ed25519_dalek::SigningKey::from_pkcs8_der(bytes)
            .map(Self::from_key)
            .map_err(|_| Unspecified)
    }
    pub fn sign(&self, message: &[u8]) -> Signature {
        Signature(self.key.sign(message).to_bytes().to_vec())
    }
}
impl KeyPair for Ed25519KeyPair {
    fn public_key(&self) -> &PublicKey {
        &self.public
    }
}
pub struct PqdsaSigningAlgorithm;
pub static ML_DSA_65_SIGNING: PqdsaSigningAlgorithm = PqdsaSigningAlgorithm;
pub struct PqdsaKeyPair {
    key: ml_dsa::SigningKey<ml_dsa::MlDsa65>,
    public: PublicKey,
}
impl PqdsaKeyPair {
    pub fn from_seed(_: &PqdsaSigningAlgorithm, seed: &[u8]) -> Result<Self, Unspecified> {
        let seed: [u8; 32] = seed.try_into().map_err(|_| Unspecified)?;
        let key = ml_dsa::SigningKey::from_seed(&seed.into());
        let public = PublicKey(key.verifying_key().encode().to_vec());
        Ok(Self { key, public })
    }
    pub fn sign(&self, message: &[u8], output: &mut [u8]) -> Result<usize, Unspecified> {
        let signature = self
            .key
            .try_sign(message)
            .map_err(|_| Unspecified)?
            .encode();
        output
            .get_mut(..signature.len())
            .ok_or(Unspecified)?
            .copy_from_slice(&signature);
        Ok(signature.len())
    }
}
impl KeyPair for PqdsaKeyPair {
    fn public_key(&self) -> &PublicKey {
        &self.public
    }
}
pub enum VerificationAlgorithm {
    Ed25519,
    MlDsa65,
}
pub static ED25519: VerificationAlgorithm = VerificationAlgorithm::Ed25519;
pub static ML_DSA_65: VerificationAlgorithm = VerificationAlgorithm::MlDsa65;
pub struct UnparsedPublicKey<B: AsRef<[u8]>> {
    algorithm: &'static VerificationAlgorithm,
    bytes: B,
}
impl<B: AsRef<[u8]>> UnparsedPublicKey<B> {
    pub fn new(algorithm: &'static VerificationAlgorithm, bytes: B) -> Self {
        Self { algorithm, bytes }
    }
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Unspecified> {
        match self.algorithm {
            VerificationAlgorithm::Ed25519 => {
                let bytes = self.bytes.as_ref().try_into().map_err(|_| Unspecified)?;
                let public =
                    ed25519_dalek::VerifyingKey::from_bytes(bytes).map_err(|_| Unspecified)?;
                let signature =
                    ed25519_dalek::Signature::from_slice(signature).map_err(|_| Unspecified)?;
                public
                    .verify_strict(message, &signature)
                    .map_err(|_| Unspecified)
            }
            VerificationAlgorithm::MlDsa65 => {
                let encoded = self.bytes.as_ref().try_into().map_err(|_| Unspecified)?;
                let public = ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::decode(&encoded);
                let signature = ml_dsa::Signature::try_from(signature).map_err(|_| Unspecified)?;
                public.verify(message, &signature).map_err(|_| Unspecified)
            }
        }
    }
}

impl std::fmt::Debug for PqdsaKeyPair { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("PqdsaKeyPair([REDACTED])") } }
