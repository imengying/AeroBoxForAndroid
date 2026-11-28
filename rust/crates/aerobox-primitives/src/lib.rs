//! RustCrypto implementations of the cryptographic operations used by the
//! imported protocol code. This crate contains no native crypto dependency.
pub mod aead;
pub mod agreement;
pub mod cipher;
pub mod digest;
pub mod hkdf;
pub mod hmac;
pub mod kem;
pub mod signature;

pub mod error {
    #[derive(Clone, Copy, Debug)]
    pub struct Unspecified;
    impl std::fmt::Display for Unspecified {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("cryptographic operation failed")
        }
    }
    impl std::error::Error for Unspecified {}
}

pub mod rand {
    use crate::error::Unspecified;
    use rand_core::RngCore;
    pub fn fill(output: &mut [u8]) -> Result<(), Unspecified> {
        SystemRandom::new().fill(output)
    }
    pub trait SecureRandom {
        fn fill(&self, output: &mut [u8]) -> Result<(), Unspecified>;
    }
    #[derive(Default)]
    pub struct SystemRandom;
    impl SystemRandom {
        pub fn new() -> Self {
            Self
        }
    }
    impl SecureRandom for SystemRandom {
        fn fill(&self, output: &mut [u8]) -> Result<(), Unspecified> {
            rand_core::OsRng
                .try_fill_bytes(output)
                .map_err(|_| Unspecified)
        }
    }
}

pub mod constant_time {
    use crate::error::Unspecified;
    use subtle::ConstantTimeEq;
    pub fn verify_slices_are_equal(a: &[u8], b: &[u8]) -> Result<(), Unspecified> {
        if bool::from(a.ct_eq(b)) {
            Ok(())
        } else {
            Err(Unspecified)
        }
    }
}
