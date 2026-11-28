use crate::error::Unspecified;
use ::hmac::{Hmac, Mac};
use zeroize::Zeroizing;

#[derive(Clone, Copy)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}
pub const HMAC_SHA1_FOR_LEGACY_USE_ONLY: Algorithm = Algorithm::Sha1;
pub const HMAC_SHA256: Algorithm = Algorithm::Sha256;
pub const HMAC_SHA384: Algorithm = Algorithm::Sha384;
pub const HMAC_SHA512: Algorithm = Algorithm::Sha512;

#[derive(Clone)]
pub struct Key {
    algorithm: Algorithm,
    bytes: Zeroizing<Vec<u8>>,
}
impl Key {
    pub fn new(algorithm: Algorithm, bytes: &[u8]) -> Self {
        Self {
            algorithm,
            bytes: Zeroizing::new(bytes.to_vec()),
        }
    }
}
pub struct Tag(Vec<u8>);
impl AsRef<[u8]> for Tag {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
#[derive(Clone)]
pub enum Context {
    Sha1(Hmac<sha1::Sha1>),
    Sha256(Hmac<sha2::Sha256>),
    Sha384(Hmac<sha2::Sha384>),
    Sha512(Hmac<sha2::Sha512>),
}
impl Context {
    pub fn with_key(key: &Key) -> Self {
        match key.algorithm {
            Algorithm::Sha1 => Self::Sha1(
                Hmac::<sha1::Sha1>::new_from_slice(&key.bytes)
                    .expect("HMAC accepts any key length"),
            ),
            Algorithm::Sha256 => Self::Sha256(
                Hmac::<sha2::Sha256>::new_from_slice(&key.bytes)
                    .expect("HMAC accepts any key length"),
            ),
            Algorithm::Sha384 => Self::Sha384(
                Hmac::<sha2::Sha384>::new_from_slice(&key.bytes)
                    .expect("HMAC accepts any key length"),
            ),
            Algorithm::Sha512 => Self::Sha512(
                Hmac::<sha2::Sha512>::new_from_slice(&key.bytes)
                    .expect("HMAC accepts any key length"),
            ),
        }
    }
    pub fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Sha1(h) => h.update(bytes),
            Self::Sha256(h) => h.update(bytes),
            Self::Sha384(h) => h.update(bytes),
            Self::Sha512(h) => h.update(bytes),
        }
    }
    pub fn sign(self) -> Tag {
        Tag(match self {
            Self::Sha1(h) => h.finalize().into_bytes().to_vec(),
            Self::Sha256(h) => h.finalize().into_bytes().to_vec(),
            Self::Sha384(h) => h.finalize().into_bytes().to_vec(),
            Self::Sha512(h) => h.finalize().into_bytes().to_vec(),
        })
    }
}
pub fn sign(key: &Key, data: &[u8]) -> Tag {
    let mut c = Context::with_key(key);
    c.update(data);
    c.sign()
}
pub fn verify(key: &Key, data: &[u8], tag: &[u8]) -> Result<(), Unspecified> {
    crate::constant_time::verify_slices_are_equal(sign(key, data).as_ref(), tag)
}

impl std::fmt::Debug for Context { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("Context([REDACTED])") } }
