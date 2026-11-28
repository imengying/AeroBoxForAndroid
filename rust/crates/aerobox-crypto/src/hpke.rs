//! RFC 9180 base-mode HPKE for rustls ECH, backed entirely by RustCrypto.
use ::hpke::{
    Deserializable, Kem, Serializable,
    aead::{Aead, AeadCtxR, AeadCtxS},
    kdf::Kdf,
};
use rand::{
    SeedableRng, TryRngCore,
    rngs::{OsRng, StdRng},
};
use rustls::{
    Error,
    crypto::hpke::{
        EncapsulatedSecret, Hpke, HpkeOpener, HpkePrivateKey, HpkePublicKey, HpkeSealer, HpkeSuite,
    },
};
use std::{fmt, marker::PhantomData};

fn error(value: impl fmt::Display) -> Error {
    Error::General(format!("Rust HPKE: {value}"))
}
fn random() -> Result<StdRng, Error> {
    let mut seed = zeroize::Zeroizing::new([0u8; 32]);
    OsRng.try_fill_bytes(&mut *seed).map_err(error)?;
    Ok(StdRng::from_seed(*seed))
}

struct Suite<A, K, M>(PhantomData<(A, K, M)>);
impl<A, K, M> fmt::Debug for Suite<A, K, M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RustCryptoHPKE")
    }
}
struct Sealer<A: Aead, K: Kdf, M: Kem>(AeadCtxS<A, K, M>);
struct Opener<A: Aead, K: Kdf, M: Kem>(AeadCtxR<A, K, M>);
impl<A: Aead, K: Kdf, M: Kem> fmt::Debug for Sealer<A, K, M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HpkeSealer")
    }
}
impl<A: Aead, K: Kdf, M: Kem> fmt::Debug for Opener<A, K, M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HpkeOpener")
    }
}

macro_rules! implementation {
    ($aead:ty, $kdf:ty, $kem:ty) => {
        impl HpkeSealer for Sealer<$aead, $kdf, $kem> {
            fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
                self.0.seal(plaintext, aad).map_err(error)
            }
        }
        impl HpkeOpener for Opener<$aead, $kdf, $kem> {
            fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
                self.0.open(ciphertext, aad).map_err(error)
            }
        }
        impl Hpke for Suite<$aead, $kdf, $kem> {
            fn suite(&self) -> HpkeSuite {
                HpkeSuite {
                    kem: <$kem as Kem>::KEM_ID.into(),
                    sym: rustls::internal::msgs::handshake::HpkeSymmetricCipherSuite {
                        kdf_id: <$kdf as Kdf>::KDF_ID.into(),
                        aead_id: <$aead as Aead>::AEAD_ID.into(),
                    },
                }
            }
            fn setup_sealer(
                &self,
                info: &[u8],
                public: &HpkePublicKey,
            ) -> Result<(EncapsulatedSecret, Box<dyn HpkeSealer>), Error> {
                let key = <$kem as Kem>::PublicKey::from_bytes(&public.0).map_err(error)?;
                let (enc, ctx) = ::hpke::setup_sender::<$aead, $kdf, $kem, _>(
                    &::hpke::OpModeS::Base,
                    &key,
                    info,
                    &mut random()?,
                )
                .map_err(error)?;
                Ok((
                    EncapsulatedSecret(enc.to_bytes().to_vec()),
                    Box::new(Sealer(ctx)),
                ))
            }
            fn setup_opener(
                &self,
                enc: &EncapsulatedSecret,
                info: &[u8],
                secret: &HpkePrivateKey,
            ) -> Result<Box<dyn HpkeOpener>, Error> {
                let key =
                    <$kem as Kem>::PrivateKey::from_bytes(secret.secret_bytes()).map_err(error)?;
                let enc = <$kem as Kem>::EncappedKey::from_bytes(&enc.0).map_err(error)?;
                let ctx = ::hpke::setup_receiver::<$aead, $kdf, $kem>(
                    &::hpke::OpModeR::Base,
                    &key,
                    &enc,
                    info,
                )
                .map_err(error)?;
                Ok(Box::new(Opener(ctx)))
            }
            fn seal(
                &self,
                info: &[u8],
                aad: &[u8],
                plaintext: &[u8],
                public: &HpkePublicKey,
            ) -> Result<(EncapsulatedSecret, Vec<u8>), Error> {
                let (enc, mut context) = self.setup_sealer(info, public)?;
                Ok((enc, context.seal(aad, plaintext)?))
            }
            fn open(
                &self,
                enc: &EncapsulatedSecret,
                info: &[u8],
                aad: &[u8],
                ciphertext: &[u8],
                secret: &HpkePrivateKey,
            ) -> Result<Vec<u8>, Error> {
                self.setup_opener(enc, info, secret)?.open(aad, ciphertext)
            }
            fn generate_key_pair(&self) -> Result<(HpkePublicKey, HpkePrivateKey), Error> {
                let (secret, public) = <$kem as Kem>::gen_keypair(&mut random()?);
                Ok((
                    HpkePublicKey(public.to_bytes().to_vec()),
                    secret.to_bytes().to_vec().into(),
                ))
            }
        }
    };
}
use ::hpke::{
    aead::{AesGcm128, AesGcm256, ChaCha20Poly1305},
    kdf::{HkdfSha256, HkdfSha384, HkdfSha512},
    kem::{DhP256HkdfSha256, DhP384HkdfSha384, DhP521HkdfSha512, X25519HkdfSha256},
};
macro_rules! suites {
    ($(($aead:ty,$kdf:ty,$kem:ty)),+ $(,)?) => {
        $(implementation!($aead,$kdf,$kem);)+
        /// Supported HPKE configurations for `rustls::client::EchConfig::new`.
        pub static ALL_SUPPORTED_SUITES: &[&dyn Hpke] = &[$(&Suite::<$aead,$kdf,$kem>(PhantomData)),+];
    };
}
suites!(
    (AesGcm128, HkdfSha256, X25519HkdfSha256),
    (AesGcm256, HkdfSha256, X25519HkdfSha256),
    (ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256),
    (AesGcm128, HkdfSha256, DhP256HkdfSha256),
    (AesGcm256, HkdfSha256, DhP256HkdfSha256),
    (ChaCha20Poly1305, HkdfSha256, DhP256HkdfSha256),
    (AesGcm128, HkdfSha384, DhP384HkdfSha384),
    (AesGcm256, HkdfSha384, DhP384HkdfSha384),
    (ChaCha20Poly1305, HkdfSha384, DhP384HkdfSha384),
    (AesGcm128, HkdfSha512, DhP521HkdfSha512),
    (AesGcm256, HkdfSha512, DhP521HkdfSha512),
    (ChaCha20Poly1305, HkdfSha512, DhP521HkdfSha512),
);
