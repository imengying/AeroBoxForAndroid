use crate::error::Unspecified;
use zeroize::Zeroizing;

#[derive(Clone, Copy)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}
pub const HKDF_SHA1_FOR_LEGACY_USE_ONLY: Algorithm = Algorithm::Sha1;
pub const HKDF_SHA256: Algorithm = Algorithm::Sha256;
pub const HKDF_SHA384: Algorithm = Algorithm::Sha384;
pub const HKDF_SHA512: Algorithm = Algorithm::Sha512;
pub trait KeyType {
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
impl KeyType for Algorithm {
    fn len(&self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
}
pub struct Salt {
    algorithm: Algorithm,
    bytes: Zeroizing<Vec<u8>>,
}
pub struct Prk {
    algorithm: Algorithm,
    bytes: Zeroizing<Vec<u8>>,
}
pub struct Okm {
    algorithm: Algorithm,
    prk: Zeroizing<Vec<u8>>,
    info: Vec<u8>,
    length: usize,
}
impl Salt {
    pub fn new(algorithm: Algorithm, bytes: &[u8]) -> Self {
        Self {
            algorithm,
            bytes: Zeroizing::new(bytes.to_vec()),
        }
    }
    pub fn extract(&self, secret: &[u8]) -> Prk {
        let bytes = match self.algorithm {
            Algorithm::Sha1 => ::hkdf::Hkdf::<sha1::Sha1>::extract(Some(&self.bytes), secret)
                .0
                .to_vec(),
            Algorithm::Sha256 => ::hkdf::Hkdf::<sha2::Sha256>::extract(Some(&self.bytes), secret)
                .0
                .to_vec(),
            Algorithm::Sha384 => ::hkdf::Hkdf::<sha2::Sha384>::extract(Some(&self.bytes), secret)
                .0
                .to_vec(),
            Algorithm::Sha512 => ::hkdf::Hkdf::<sha2::Sha512>::extract(Some(&self.bytes), secret)
                .0
                .to_vec(),
        };
        Prk {
            algorithm: self.algorithm,
            bytes: Zeroizing::new(bytes),
        }
    }
}
impl Prk {
    /// Import an already-extracted pseudorandom key. Length is checked at expansion.
    pub fn new_less_safe(algorithm: Algorithm, secret: &[u8]) -> Self {
        Self { algorithm, bytes: Zeroizing::new(secret.to_vec()) }
    }
    pub fn expand(&self, info: &[&[u8]], key_type: impl KeyType) -> Result<Okm, Unspecified> {
        let length = key_type.len();
        if length > 255 * self.algorithm.len() {
            return Err(Unspecified);
        }
        Ok(Okm {
            algorithm: self.algorithm,
            prk: self.bytes.clone(),
            info: info.concat(),
            length,
        })
    }
}
impl Okm {
    pub fn fill(self, output: &mut [u8]) -> Result<(), Unspecified> {
        if output.len() != self.length {
            return Err(Unspecified);
        }
        match self.algorithm {
            Algorithm::Sha1 => ::hkdf::Hkdf::<sha1::Sha1>::from_prk(&self.prk)
                .map_err(|_| Unspecified)?
                .expand(&self.info, output),
            Algorithm::Sha256 => ::hkdf::Hkdf::<sha2::Sha256>::from_prk(&self.prk)
                .map_err(|_| Unspecified)?
                .expand(&self.info, output),
            Algorithm::Sha384 => ::hkdf::Hkdf::<sha2::Sha384>::from_prk(&self.prk)
                .map_err(|_| Unspecified)?
                .expand(&self.info, output),
            Algorithm::Sha512 => ::hkdf::Hkdf::<sha2::Sha512>::from_prk(&self.prk)
                .map_err(|_| Unspecified)?
                .expand(&self.info, output),
        }
        .map_err(|_| Unspecified)
    }
}
