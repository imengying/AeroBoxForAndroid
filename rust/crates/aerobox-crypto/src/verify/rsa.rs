//! RSA signature verification with an explicit 2048..8192-bit bound. The
//! upstream alpha decodes via rsa's default 4096-bit constructor, accidentally
//! rejecting larger TLS keys before checking their signatures.
use p256::ecdsa::signature::Verifier;
use rsa::{BigUint, RsaPublicKey, pkcs1::der::Decode, traits::PublicKeyParts};
use rustls::pki_types::{
    AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm, alg_id,
};

fn key(der: &[u8]) -> Result<RsaPublicKey, InvalidSignature> {
    // A bounded DER RSA modulus plus exponent, before allocating big integers.
    if der.len() > 1100 {
        return Err(InvalidSignature);
    }
    let key = rsa::pkcs1::RsaPublicKey::from_der(der).map_err(|_| InvalidSignature)?;
    let key = RsaPublicKey::new_with_max_size(
        BigUint::from_bytes_be(key.modulus.as_bytes()),
        BigUint::from_bytes_be(key.public_exponent.as_bytes()),
        8192,
    )
    .map_err(|_| InvalidSignature)?;
    if key.n().bits() < 2048 {
        return Err(InvalidSignature);
    }
    Ok(key)
}

macro_rules! verifier {
    ($name:ident, $hash:ty, $kind:ident, $algorithm:ident) => {
        #[derive(Debug)]
        pub(super) struct $name;
        impl SignatureVerificationAlgorithm for $name {
            fn public_key_alg_id(&self) -> AlgorithmIdentifier {
                alg_id::RSA_ENCRYPTION
            }
            fn signature_alg_id(&self) -> AlgorithmIdentifier {
                alg_id::$algorithm
            }
            fn verify_signature(
                &self,
                public: &[u8],
                message: &[u8],
                signature: &[u8],
            ) -> Result<(), InvalidSignature> {
                let key = key(public)?;
                if signature.len() != key.size() {
                    return Err(InvalidSignature);
                }
                let signature =
                    rsa::$kind::Signature::try_from(signature).map_err(|_| InvalidSignature)?;
                rsa::$kind::VerifyingKey::<$hash>::new(key)
                    .verify(message, &signature)
                    .map_err(|_| InvalidSignature)
            }
        }
    };
}
verifier!(Pkcs1Sha256, sha2::Sha256, pkcs1v15, RSA_PKCS1_SHA256);
verifier!(Pkcs1Sha384, sha2::Sha384, pkcs1v15, RSA_PKCS1_SHA384);
verifier!(Pkcs1Sha512, sha2::Sha512, pkcs1v15, RSA_PKCS1_SHA512);
verifier!(PssSha256, sha2::Sha256, pss, RSA_PSS_SHA256);
verifier!(PssSha384, sha2::Sha384, pss, RSA_PSS_SHA384);
verifier!(PssSha512, sha2::Sha512, pss, RSA_PSS_SHA512);

pub(super) fn replacement(
    id: AlgorithmIdentifier,
) -> Option<&'static dyn SignatureVerificationAlgorithm> {
    [
        &Pkcs1Sha256 as &dyn SignatureVerificationAlgorithm,
        &Pkcs1Sha384,
        &Pkcs1Sha512,
        &PssSha256,
        &PssSha384,
        &PssSha512,
    ]
    .into_iter()
    .find(|algorithm| algorithm.signature_alg_id() == id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs1::der::{Encode, asn1::UintRef};

    fn der(bits: usize, exponent: &[u8]) -> Vec<u8> {
        let mut modulus = vec![0; bits.div_ceil(8)];
        modulus[0] = 1 << ((bits - 1) % 8);
        *modulus.last_mut().unwrap() |= 1;
        rsa::pkcs1::RsaPublicKey {
            modulus: UintRef::new(&modulus).unwrap(),
            public_exponent: UintRef::new(exponent).unwrap(),
        }
        .to_der()
        .unwrap()
    }

    #[test]
    fn rsa_verification_decoder_rejects_out_of_range_and_malformed_public_keys() {
        for bits in [2048, 4096, 8192] {
            assert_eq!(key(&der(bits, &[1, 0, 1])).unwrap().n().bits(), bits);
        }
        for bits in [1024, 2047, 8193, 16384] {
            assert!(key(&der(bits, &[1, 0, 1])).is_err(), "accepted {bits} bits");
        }
        assert!(key(&der(2048, &[2])).is_err());
        let mut trailing = der(2048, &[1, 0, 1]);
        trailing.push(0);
        assert!(key(&trailing).is_err());
        assert!(key(&trailing[..100]).is_err());
    }
}
