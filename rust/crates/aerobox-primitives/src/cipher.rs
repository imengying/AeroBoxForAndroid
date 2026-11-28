use crate::error::Unspecified;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, KeyIvInit, StreamCipher};
use zeroize::Zeroizing;

#[derive(Clone, Copy)]
pub enum Algorithm {
    Aes128,
    Aes256,
}
pub static AES_128: Algorithm = Algorithm::Aes128;
pub static AES_256: Algorithm = Algorithm::Aes256;
pub struct UnboundCipherKey {
    algorithm: Algorithm,
    bytes: Zeroizing<Vec<u8>>,
}
impl UnboundCipherKey {
    pub fn new(algorithm: &Algorithm, bytes: &[u8]) -> Result<Self, Unspecified> {
        let expected = match algorithm {
            Algorithm::Aes128 => 16,
            Algorithm::Aes256 => 32,
        };
        if bytes.len() != expected {
            return Err(Unspecified);
        }
        Ok(Self {
            algorithm: *algorithm,
            bytes: Zeroizing::new(bytes.to_vec()),
        })
    }
}
pub enum EncryptionContext {
    None,
    Iv128([u8; 16]),
}
pub enum DecryptionContext {
    None,
    Iv128([u8; 16]),
}
#[allow(clippy::large_enum_variant, reason = "Fixed-size AES key schedules")]
enum Ecb {
    Aes128(aes::Aes128),
    Aes256(aes::Aes256),
}
impl Ecb {
    fn new(key: UnboundCipherKey) -> Result<Self, Unspecified> {
        Ok(match key.algorithm {
            Algorithm::Aes128 => {
                Self::Aes128(aes::Aes128::new_from_slice(&key.bytes).map_err(|_| Unspecified)?)
            }
            Algorithm::Aes256 => {
                Self::Aes256(aes::Aes256::new_from_slice(&key.bytes).map_err(|_| Unspecified)?)
            }
        })
    }
}
pub struct EncryptingKey(Ecb);
pub struct DecryptingKey(Ecb);
impl EncryptingKey {
    pub fn ecb(key: UnboundCipherKey) -> Result<Self, Unspecified> {
        Ecb::new(key).map(Self)
    }
    pub fn less_safe_encrypt(
        &self,
        data: &mut [u8],
        context: EncryptionContext,
    ) -> Result<DecryptionContext, Unspecified> {
        if !matches!(context, EncryptionContext::None) || !data.len().is_multiple_of(16) {
            return Err(Unspecified);
        }
        for block in data.as_chunks_mut::<16>().0 {
            match &self.0 {
                Ecb::Aes128(c) => c.encrypt_block(block.into()),
                Ecb::Aes256(c) => c.encrypt_block(block.into()),
            }
        }
        Ok(DecryptionContext::None)
    }
}
impl DecryptingKey {
    pub fn ecb(key: UnboundCipherKey) -> Result<Self, Unspecified> {
        Ecb::new(key).map(Self)
    }
    pub fn decrypt<'a>(
        &self,
        data: &'a mut [u8],
        context: DecryptionContext,
    ) -> Result<&'a mut [u8], Unspecified> {
        if !matches!(context, DecryptionContext::None) || !data.len().is_multiple_of(16) {
            return Err(Unspecified);
        }
        for block in data.as_chunks_mut::<16>().0 {
            match &self.0 {
                Ecb::Aes128(c) => c.decrypt_block(block.into()),
                Ecb::Aes256(c) => c.decrypt_block(block.into()),
            }
        }
        Ok(data)
    }
}
#[allow(clippy::large_enum_variant, reason = "Fixed-size AES-CTR key schedules")]
pub enum StreamingEncryptingKey {
    Aes128(ctr::Ctr128BE<aes::Aes128>),
    Aes256(ctr::Ctr128BE<aes::Aes256>),
}
pub struct BufferUpdate<'a>(&'a [u8]);
impl BufferUpdate<'_> {
    pub fn written(&self) -> &[u8] {
        self.0
    }
}
impl StreamingEncryptingKey {
    pub fn less_safe_ctr(
        key: UnboundCipherKey,
        context: EncryptionContext,
    ) -> Result<Self, Unspecified> {
        let EncryptionContext::Iv128(iv) = context else {
            return Err(Unspecified);
        };
        Ok(match key.algorithm {
            Algorithm::Aes128 => Self::Aes128(
                ctr::Ctr128BE::<aes::Aes128>::new_from_slices(&key.bytes, &iv)
                    .map_err(|_| Unspecified)?,
            ),
            Algorithm::Aes256 => Self::Aes256(
                ctr::Ctr128BE::<aes::Aes256>::new_from_slices(&key.bytes, &iv)
                    .map_err(|_| Unspecified)?,
            ),
        })
    }
    pub fn update<'a>(
        &mut self,
        input: &[u8],
        output: &'a mut [u8],
    ) -> Result<BufferUpdate<'a>, Unspecified> {
        let output = output.get_mut(..input.len()).ok_or(Unspecified)?;
        output.copy_from_slice(input);
        match self {
            Self::Aes128(c) => c.try_apply_keystream(output),
            Self::Aes256(c) => c.try_apply_keystream(output),
        }
        .map_err(|_| Unspecified)?;
        Ok(BufferUpdate(output))
    }
}
