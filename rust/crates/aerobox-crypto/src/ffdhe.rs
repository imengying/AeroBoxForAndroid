//! Explicit RFC 7919 FFDHE groups for TLS 1.3.
//!
//! These groups are deliberately absent from the ordinary provider. A complete
//! Firefox profile can opt in once its other advertised capabilities exist.
//! Secret exponents use a fixed number of bits and constant-time Montgomery
//! arithmetic; the template/profile random source is never used for keys.
use crypto_bigint::{
    Encoding, U2048, U3072, Uint,
    modular::constant_mod::{Residue, ResidueParams},
};
use rand_core::{CryptoRngCore, OsRng};
use rustls::{
    Error, NamedGroup, PeerMisbehaved, ProtocolVersion, SupportedProtocolVersion,
    crypto::{ActiveKeyExchange, CompletedKeyExchange, SharedSecret, SupportedKxGroup},
    ffdhe_groups::FfdheGroup,
};
use subtle::{Choice, ConditionallySelectable, ConstantTimeGreater, ConstantTimeLess};
use zeroize::Zeroizing;

mod params;

/// Modular exponentiation with a public, fixed iteration count.
///
/// Each exponent bit performs both a square and multiply, then constant-time
/// selection. This uses crypto-bigint's existing Montgomery implementation,
/// not variable-time BigUint arithmetic. It avoids the 0.5.5 `pow` helper's
/// additional complete copies of the exponent in an unzeroized work array.
/// Owned exponent/result/workspace values are zeroized. As with the underlying
/// RustCrypto types, compiler and arithmetic-internal temporary copies cannot
/// be promised to be erased; this is not a claim of whole-stack zeroization.
fn power<M: ResidueParams<LIMBS>, const LIMBS: usize>(
    base: &Uint<LIMBS>,
    exponent: &[u8],
) -> Zeroizing<Uint<LIMBS>> {
    let base = Zeroizing::new(Residue::<M, LIMBS>::new(base));
    let mut result = Zeroizing::new(Residue::<M, LIMBS>::ONE);
    for byte in exponent {
        for bit in (0..8).rev() {
            let squared = Zeroizing::new(result.square());
            let multiplied = Zeroizing::new(squared.mul(&base));
            *result =
                Residue::conditional_select(&squared, &multiplied, Choice::from((byte >> bit) & 1));
        }
    }
    Zeroizing::new(result.retrieve())
}

macro_rules! group {
    ($public:ident, $kind:ident, $exchange:ident, $modulus:ty, $uint:ty, $secret_len:expr) => {
        /// An explicit TLS 1.3 FFDHE group using the RFC 7919 parameters.
        #[derive(Debug)]
        pub struct $kind;

        /// Opt-in group; adding this does not enable a browser fingerprint.
        pub static $public: $kind = $kind;

        impl $kind {
            fn validate_peer(peer: &[u8]) -> Result<$uint, Error> {
                // TLS1.3 requires exactly the modulus length, including any
                // leading zeros. Do not silently normalize malformed shares.
                if peer.len() != <$uint>::BYTES {
                    return Err(PeerMisbehaved::InvalidKeyShare.into());
                }
                let peer = <$uint>::from_be_slice(peer);
                let maximum = <$modulus>::MODULUS.wrapping_sub(&<$uint>::ONE);
                if !bool::from(peer.ct_gt(&<$uint>::ONE) & peer.ct_lt(&maximum)) {
                    return Err(PeerMisbehaved::InvalidKeyShare.into());
                }
                Ok(peer)
            }

            fn start_with_rng(
                &self,
                rng: &mut dyn CryptoRngCore,
            ) -> Result<Box<dyn ActiveKeyExchange>, Error> {
                // Fixed 256/384-bit exponents exceed RFC7919's 225/275-bit
                // short-exponent minima. The high bit makes length fixed and
                // ensures 2 <= x < q without a secret-dependent retry loop.
                let mut secret = Zeroizing::new([0u8; $secret_len]);
                rng.try_fill_bytes(secret.as_mut())
                    .map_err(|_| Error::FailedToGetRandomBytes)?;
                secret[0] |= 0x80;
                let public =
                    power::<$modulus, { <$uint>::LIMBS }>(&<$uint>::from_u8(2), secret.as_ref())
                        .to_be_bytes()
                        .to_vec();
                Ok(Box::new($exchange { secret, public }))
            }
        }

        impl SupportedKxGroup for $kind {
            fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
                self.start_with_rng(&mut OsRng)
            }

            fn start_and_complete(
                &self,
                peer_pub_key: &[u8],
            ) -> Result<CompletedKeyExchange, Error> {
                // Reject malformed public input before starting expensive
                // private-key work on the server-side combined path too.
                Self::validate_peer(peer_pub_key)?;
                let exchange = self.start()?;
                Ok(CompletedKeyExchange {
                    group: self.name(),
                    pub_key: exchange.pub_key().to_vec(),
                    secret: exchange.complete(peer_pub_key)?,
                })
            }

            fn name(&self) -> NamedGroup {
                NamedGroup::$public
            }

            fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
                Some(rustls::ffdhe_groups::$public)
            }

            fn usable_for_version(&self, version: ProtocolVersion) -> bool {
                version == ProtocolVersion::TLSv1_3
            }
        }

        struct $exchange {
            secret: Zeroizing<[u8; $secret_len]>,
            public: Vec<u8>,
        }

        impl ActiveKeyExchange for $exchange {
            fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
                let peer = $kind::validate_peer(peer)?;
                let result = power::<$modulus, { <$uint>::LIMBS }>(&peer, self.secret.as_ref());
                let encoded = Zeroizing::new(result.to_be_bytes());
                // SharedSecret owns and zeroizes its copy. The local encoded
                // value and the consumed private exponent drop on every path.
                Ok(SharedSecret::from(encoded.as_slice()))
            }

            fn complete_for_tls_version(
                self: Box<Self>,
                peer: &[u8],
                version: &SupportedProtocolVersion,
            ) -> Result<SharedSecret, Error> {
                if version.version != ProtocolVersion::TLSv1_3 {
                    return Err(Error::General("these FFDHE groups require TLS 1.3".into()));
                }
                self.complete(peer)
            }

            fn pub_key(&self) -> &[u8] {
                &self.public
            }

            fn group(&self) -> NamedGroup {
                NamedGroup::$public
            }

            fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
                Some(rustls::ffdhe_groups::$public)
            }
        }
    };
}

group!(
    FFDHE2048,
    Ffdhe2048,
    Exchange2048,
    params::Modulus2048,
    U2048,
    32
);
group!(
    FFDHE3072,
    Ffdhe3072,
    Exchange3072,
    params::Modulus3072,
    U3072,
    48
);

#[cfg(test)]
mod tests;
