use sha2::Digest as _;

#[derive(Clone, Copy, Debug)]
pub enum Algorithm {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}
pub static SHA1_FOR_LEGACY_USE_ONLY: Algorithm = Algorithm::Sha1;
pub static SHA224: Algorithm = Algorithm::Sha224;
pub static SHA256: Algorithm = Algorithm::Sha256;
pub static SHA384: Algorithm = Algorithm::Sha384;
pub static SHA512: Algorithm = Algorithm::Sha512;

#[derive(Clone)]
pub enum Context {
    Sha1(sha1::Sha1),
    Sha224(sha2::Sha224),
    Sha256(sha2::Sha256),
    Sha384(sha2::Sha384),
    Sha512(sha2::Sha512),
}
pub struct Digest(Vec<u8>);
impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl Context {
    pub fn new(algorithm: &Algorithm) -> Self {
        match algorithm {
            Algorithm::Sha1 => Self::Sha1(sha1::Sha1::new()),
            Algorithm::Sha224 => Self::Sha224(sha2::Sha224::new()),
            Algorithm::Sha256 => Self::Sha256(sha2::Sha256::new()),
            Algorithm::Sha384 => Self::Sha384(sha2::Sha384::new()),
            Algorithm::Sha512 => Self::Sha512(sha2::Sha512::new()),
        }
    }
    pub fn update(&mut self, data: &[u8]) {
        match self {
            Self::Sha1(h) => h.update(data),
            Self::Sha224(h) => h.update(data),
            Self::Sha256(h) => h.update(data),
            Self::Sha384(h) => h.update(data),
            Self::Sha512(h) => h.update(data),
        }
    }
    pub fn finish(self) -> Digest {
        Digest(match self {
            Self::Sha1(h) => h.finalize().to_vec(),
            Self::Sha224(h) => h.finalize().to_vec(),
            Self::Sha256(h) => h.finalize().to_vec(),
            Self::Sha384(h) => h.finalize().to_vec(),
            Self::Sha512(h) => h.finalize().to_vec(),
        })
    }
}
pub fn digest(algorithm: &Algorithm, data: &[u8]) -> Digest {
    let mut context = Context::new(algorithm);
    context.update(data);
    context.finish()
}
