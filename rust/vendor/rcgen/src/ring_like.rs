#[cfg(all(feature = "crypto", feature = "aws_lc_rs"))]
pub(crate) use aws_lc_rs::*;
#[cfg(all(feature = "crypto", feature = "ring", not(feature = "aws_lc_rs")))]
pub(crate) use ring::*;

#[cfg(all(feature = "crypto", not(feature = "rustcrypto")))]
use crate::error::ExternalError;
#[cfg(all(feature = "crypto", not(feature = "rustcrypto")))]
use crate::Error;

#[cfg(all(feature = "crypto", not(feature = "rustcrypto")))]
pub(crate) fn ecdsa_from_pkcs8(
	alg: &'static signature::EcdsaSigningAlgorithm,
	pkcs8: &[u8],
	_rng: &dyn rand::SecureRandom,
) -> Result<signature::EcdsaKeyPair, Error> {
	#[cfg(all(feature = "ring", not(feature = "aws_lc_rs")))]
	{
		signature::EcdsaKeyPair::from_pkcs8(alg, pkcs8, _rng)._err()
	}

	#[cfg(feature = "aws_lc_rs")]
	{
		signature::EcdsaKeyPair::from_pkcs8(alg, pkcs8)._err()
	}
}

#[cfg(all(feature = "crypto", feature = "aws_lc_rs"))]
pub(crate) fn ecdsa_from_private_key_der(
	alg: &'static signature::EcdsaSigningAlgorithm,
	key: &[u8],
) -> Result<signature::EcdsaKeyPair, Error> {
	signature::EcdsaKeyPair::from_private_key_der(alg, key)._err()
}

#[cfg(all(feature = "crypto", not(feature = "rustcrypto")))]
pub(crate) fn rsa_key_pair_public_modulus_len(kp: &signature::RsaKeyPair) -> usize {
	#[cfg(all(feature = "ring", not(feature = "aws_lc_rs")))]
	{
		kp.public().modulus_len()
	}

	#[cfg(feature = "aws_lc_rs")]
	{
		kp.public_modulus_len()
	}
}

#[cfg(all(feature = "crypto", not(any(feature = "ring", feature = "aws_lc_rs", feature = "rustcrypto"))))]
compile_error!("At least one of the 'ring' or 'aws_lc_rs' features must be activated when the 'crypto' feature is enabled");

#[cfg(feature = "rustcrypto")]
pub(crate) use aerobox_primitives::digest;
