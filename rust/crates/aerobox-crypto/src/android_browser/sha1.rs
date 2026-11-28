//! TLS1.2 ECDSA/SHA1 verifiers, deliberately excluded from X.509 chain policy.
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use rustls::pki_types::{
    AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm, alg_id,
};
use sha1::Digest;

// RFC3279 section 2.2.3: ecdsa-with-SHA1 (1.2.840.10045.4.1), absent params.
const ECDSA_SHA1: AlgorithmIdentifier =
    AlgorithmIdentifier::from_slice(&[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x01]);

macro_rules! verifier {
    ($name:ident, $curve:ident, $public_id:ident, $field:expr) => {
        #[derive(Debug)]
        struct $name;
        impl SignatureVerificationAlgorithm for $name {
            fn public_key_alg_id(&self) -> AlgorithmIdentifier {
                alg_id::$public_id
            }
            fn signature_alg_id(&self) -> AlgorithmIdentifier {
                ECDSA_SHA1
            }
            fn verify_signature(
                &self,
                public_key: &[u8],
                message: &[u8],
                signature: &[u8],
            ) -> Result<(), InvalidSignature> {
                let key = $curve::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
                    .map_err(|_| InvalidSignature)?;
                let signature =
                    $curve::ecdsa::Signature::from_der(signature).map_err(|_| InvalidSignature)?;
                // ECDSA interprets the digest as an integer. Leading zeroes
                // preserve that integer and satisfy RustCrypto's prehash API.
                let mut hash = [0u8; $field];
                hash[$field - 20..].copy_from_slice(&sha1::Sha1::digest(message));
                key.verify_prehash(&hash, &signature)
                    .map_err(|_| InvalidSignature)
            }
        }
    };
}
verifier!(P256Sha1, p256, ECDSA_P256, 32);
verifier!(P384Sha1, p384, ECDSA_P384, 48);
verifier!(P521Sha1, p521, ECDSA_P521, 66);

pub(super) const VERIFIERS: &[&dyn SignatureVerificationAlgorithm] =
    &[&P256Sha1, &P384Sha1, &P521Sha1];
