use crate::error::Unspecified;
use aes_gcm::aead::{AeadInPlace, KeyInit};
use zeroize::Zeroize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Algorithm {
    Aes128,
    Aes256,
    Aes256Siv,
    ChaCha20,
}
pub static AES_128_GCM: Algorithm = Algorithm::Aes128;
pub static AES_256_GCM: Algorithm = Algorithm::Aes256;
pub static AES_256_GCM_SIV: Algorithm = Algorithm::Aes256Siv;
pub static CHACHA20_POLY1305: Algorithm = Algorithm::ChaCha20;
impl Algorithm {
    pub fn key_len(&self) -> usize {
        if *self == Algorithm::Aes128 { 16 } else { 32 }
    }
    pub fn tag_len(&self) -> usize {
        16
    }
    pub fn nonce_len(&self) -> usize {
        12
    }
}
pub const NONCE_LEN: usize = 12;
pub const MAX_TAG_LEN: usize = 16;
pub struct Nonce([u8; 12]);
impl Nonce {
    pub fn assume_unique_for_key(bytes: [u8; 12]) -> Self {
        Self(bytes)
    }
    pub fn try_assume_unique_for_key(bytes: &[u8]) -> Result<Self, Unspecified> {
        Ok(Self(bytes.try_into().map_err(|_| Unspecified)?))
    }
}
impl AsRef<[u8]> for Nonce {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
pub trait NonceSequence {
    fn advance(&mut self) -> Result<Nonce, Unspecified>;
}
pub struct Aad<T: AsRef<[u8]>>(T);
impl<T: AsRef<[u8]>> From<T> for Aad<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}
impl Aad<[u8; 0]> {
    pub fn empty() -> Self {
        Self([])
    }
}
pub struct Tag([u8; 16]);
impl AsRef<[u8]> for Tag {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
#[allow(clippy::large_enum_variant, reason = "Fixed-size key schedules avoid a per-session heap allocation")]
enum Cipher {
    Aes128(aes_gcm::Aes128Gcm),
    Aes256(aes_gcm::Aes256Gcm),
    Aes256Siv(aes_gcm_siv::Aes256GcmSiv),
    ChaCha(chacha20poly1305::ChaCha20Poly1305),
}
pub struct UnboundKey {
    algorithm: &'static Algorithm,
    cipher: Cipher,
}
impl UnboundKey {
    pub fn new(algorithm: &'static Algorithm, bytes: &[u8]) -> Result<Self, Unspecified> {
        let cipher = match algorithm {
            Algorithm::Aes128 => {
                Cipher::Aes128(aes_gcm::Aes128Gcm::new_from_slice(bytes).map_err(|_| Unspecified)?)
            }
            Algorithm::Aes256 => {
                Cipher::Aes256(aes_gcm::Aes256Gcm::new_from_slice(bytes).map_err(|_| Unspecified)?)
            }
            Algorithm::Aes256Siv => Cipher::Aes256Siv(aes_gcm_siv::Aes256GcmSiv::new_from_slice(bytes).map_err(|_| Unspecified)?),
            Algorithm::ChaCha20 => Cipher::ChaCha(
                chacha20poly1305::ChaCha20Poly1305::new_from_slice(bytes)
                    .map_err(|_| Unspecified)?,
            ),
        };
        Ok(Self { algorithm, cipher })
    }
}
pub struct LessSafeKey(UnboundKey);
impl LessSafeKey {
    pub fn new(key: UnboundKey) -> Self {
        Self(key)
    }
    pub fn algorithm(&self) -> &'static Algorithm {
        self.0.algorithm
    }
    pub fn seal_in_place_separate_tag<T: AsRef<[u8]>>(
        &self,
        nonce: Nonce,
        aad: Aad<T>,
        data: &mut [u8],
    ) -> Result<Tag, Unspecified> {
        let nonce = (&nonce.0).into();
        let tag = match &self.0.cipher {
            Cipher::Aes128(c) => c.encrypt_in_place_detached(nonce, aad.0.as_ref(), data),
            Cipher::Aes256(c) => c.encrypt_in_place_detached(nonce, aad.0.as_ref(), data),
            Cipher::Aes256Siv(c) => c.encrypt_in_place_detached(nonce, aad.0.as_ref(), data),
            Cipher::ChaCha(c) => c.encrypt_in_place_detached(nonce, aad.0.as_ref(), data),
        }
        .map_err(|_| Unspecified)?;
        Ok(Tag(tag.into()))
    }
    pub fn seal_in_place_append_tag<T: AsRef<[u8]>>(
        &self,
        nonce: Nonce,
        aad: Aad<T>,
        data: &mut Vec<u8>,
    ) -> Result<(), Unspecified> {
        let tag = self.seal_in_place_separate_tag(nonce, aad, data)?;
        data.extend_from_slice(tag.as_ref());
        Ok(())
    }
    pub fn open_in_place<'a, T: AsRef<[u8]>>(
        &self,
        nonce: Nonce,
        aad: Aad<T>,
        data: &'a mut [u8],
    ) -> Result<&'a mut [u8], Unspecified> {
        let length = data.len().checked_sub(16).ok_or(Unspecified)?;
        let (payload, tag) = data.split_at_mut(length);
        let nonce = (&nonce.0).into();
        let result = match &self.0.cipher {
            Cipher::Aes128(c) => {
                c.decrypt_in_place_detached(nonce, aad.0.as_ref(), payload, (&*tag).into())
            }
            Cipher::Aes256(c) => {
                c.decrypt_in_place_detached(nonce, aad.0.as_ref(), payload, (&*tag).into())
            }
            Cipher::Aes256Siv(c) => c.decrypt_in_place_detached(nonce, aad.0.as_ref(), payload, (&*tag).into()),
            Cipher::ChaCha(c) => {
                c.decrypt_in_place_detached(nonce, aad.0.as_ref(), payload, (&*tag).into())
            }
        };
        if result.is_err() {
            payload.zeroize();
            return Err(Unspecified);
        }
        Ok(payload)
    }
}
pub trait BoundKey<N: NonceSequence>: Sized {
    fn new(key: UnboundKey, sequence: N) -> Self;
    fn algorithm(&self) -> &'static Algorithm;
}
pub struct OpeningKey<N: NonceSequence> {
    key: LessSafeKey,
    sequence: N,
}
pub struct SealingKey<N: NonceSequence> {
    key: LessSafeKey,
    sequence: N,
}
macro_rules! bound {
    ($name:ident) => {
        impl<N: NonceSequence> BoundKey<N> for $name<N> {
            fn new(key: UnboundKey, sequence: N) -> Self {
                Self {
                    key: LessSafeKey::new(key),
                    sequence,
                }
            }
            fn algorithm(&self) -> &'static Algorithm {
                self.key.algorithm()
            }
        }
    };
}
bound!(OpeningKey);
bound!(SealingKey);
impl<N: NonceSequence> OpeningKey<N> {
    pub fn open_in_place<'a, T: AsRef<[u8]>>(
        &mut self,
        aad: Aad<T>,
        data: &'a mut [u8],
    ) -> Result<&'a mut [u8], Unspecified> {
        self.key.open_in_place(self.sequence.advance()?, aad, data)
    }
}
impl<N: NonceSequence> SealingKey<N> {
    pub fn seal_in_place_separate_tag<T: AsRef<[u8]>>(
        &mut self,
        aad: Aad<T>,
        data: &mut [u8],
    ) -> Result<Tag, Unspecified> {
        self.key
            .seal_in_place_separate_tag(self.sequence.advance()?, aad, data)
    }
    pub fn seal_in_place_append_tag<T: AsRef<[u8]>>(
        &mut self,
        aad: Aad<T>,
        data: &mut Vec<u8>,
    ) -> Result<(), Unspecified> {
        self.key
            .seal_in_place_append_tag(self.sequence.advance()?, aad, data)
    }
}
