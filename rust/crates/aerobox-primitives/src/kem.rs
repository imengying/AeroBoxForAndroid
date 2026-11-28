//! ML-KEM-768 adapter backed by RustCrypto, including public-key validation.
use crate::{
    error::Unspecified,
    rand::{SecureRandom, SystemRandom},
};
use ml_kem::{
    MlKem768,
    kem::{Decapsulate, KeyExport, TryKeyInit},
};
use zeroize::Zeroizing;

pub struct Algorithm;
pub static ML_KEM_768: Algorithm = Algorithm;
pub struct DecapsulationKey(ml_kem::DecapsulationKey<MlKem768>);
#[derive(Clone)]
pub struct EncapsulationKey(ml_kem::EncapsulationKey<MlKem768>);
pub struct KeyBytes(Vec<u8>);
pub struct Ciphertext<'a>(std::borrow::Cow<'a, [u8]>);
pub struct SharedSecret(Zeroizing<[u8; 32]>);
impl AsRef<[u8]> for KeyBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl AsRef<[u8]> for Ciphertext<'_> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl AsRef<[u8]> for SharedSecret {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
impl<'a> From<&'a [u8]> for Ciphertext<'a> {
    fn from(v: &'a [u8]) -> Self {
        Self(v.into())
    }
}
impl DecapsulationKey {
    pub fn generate(_: &Algorithm) -> Result<Self, Unspecified> {
        let mut seed = Zeroizing::new([0; 64]);
        SystemRandom::new().fill(seed.as_mut())?;
        Ok(Self(ml_kem::DecapsulationKey::from_seed((*seed).into())))
    }
    #[allow(
        deprecated,
        reason = "Compatibility with the protocol's expanded-key import API"
    )]
    pub fn new(_: &Algorithm, bytes: &[u8]) -> Result<Self, Unspecified> {
        let expanded = bytes.try_into().map_err(|_| Unspecified)?;
        ml_kem::DecapsulationKey::from_expanded(&expanded)
            .map(Self)
            .map_err(|_| Unspecified)
    }
    pub fn encapsulation_key(&self) -> Result<EncapsulationKey, Unspecified> {
        Ok(EncapsulationKey(self.0.encapsulation_key().clone()))
    }
    pub fn decapsulate(&self, ciphertext: Ciphertext<'_>) -> Result<SharedSecret, Unspecified> {
        let ciphertext = ciphertext.as_ref().try_into().map_err(|_| Unspecified)?;
        let secret = self.0.decapsulate(&ciphertext);
        Ok(SharedSecret(Zeroizing::new(secret.into())))
    }
}
impl EncapsulationKey {
    pub fn new(_: &Algorithm, bytes: &[u8]) -> Result<Self, Unspecified> {
        ml_kem::EncapsulationKey::new_from_slice(bytes)
            .map(Self)
            .map_err(|_| Unspecified)
    }
    pub fn key_bytes(&self) -> Result<KeyBytes, Unspecified> {
        Ok(KeyBytes(self.0.to_bytes().to_vec()))
    }
    pub fn encapsulate(&self) -> Result<(Ciphertext<'static>, SharedSecret), Unspecified> {
        let mut randomness = Zeroizing::new([0; 32]);
        SystemRandom::new().fill(randomness.as_mut())?;
        let (ciphertext, secret) = self.0.encapsulate_deterministic(&(*randomness).into());
        Ok((
            Ciphertext(ciphertext.to_vec().into()),
            SharedSecret(Zeroizing::new(secret.into())),
        ))
    }
}
