//! X25519 with contributory-behaviour checks (RFC 7748 section 6.1).
use crate::error::Unspecified;
use crate::rand::{SecureRandom, SystemRandom};
use x25519_dalek::{PublicKey as DalekPublicKey, StaticSecret};
use zeroize::Zeroizing;

pub struct Algorithm;
pub static X25519: Algorithm = Algorithm;
pub struct PrivateKey(StaticSecret);
pub struct PublicKey([u8; 32]);
impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl PrivateKey {
    pub fn generate(algorithm: &Algorithm) -> Result<Self, Unspecified> {
        let mut bytes = Zeroizing::new([0; 32]);
        SystemRandom::new().fill(bytes.as_mut())?;
        Self::from_private_key(algorithm, bytes.as_ref())
    }
    pub fn from_private_key(_: &Algorithm, bytes: &[u8]) -> Result<Self, Unspecified> {
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| Unspecified)?;
        Ok(Self(StaticSecret::from(bytes)))
    }
    pub fn compute_public_key(&self) -> Result<PublicKey, Unspecified> {
        Ok(PublicKey(DalekPublicKey::from(&self.0).to_bytes()))
    }
}
pub struct UnparsedPublicKey<B: AsRef<[u8]>>(B);
impl<B: AsRef<[u8]>> UnparsedPublicKey<B> {
    pub fn new(_: &Algorithm, bytes: B) -> Self {
        Self(bytes)
    }
}
pub fn agree<B: AsRef<[u8]>, T, E>(
    private: &PrivateKey,
    public: UnparsedPublicKey<B>,
    error: E,
    consume: impl FnOnce(&[u8]) -> Result<T, E>,
) -> Result<T, E> {
    let Ok(bytes) = <[u8; 32]>::try_from(public.0.as_ref()) else {
        return Err(error);
    };
    let shared = private.0.diffie_hellman(&DalekPublicKey::from(bytes));
    if !shared.was_contributory() {
        return Err(error);
    }
    consume(shared.as_bytes())
}
