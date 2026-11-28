//! Opt-in pure ML-DSA verification for TLS 1.3 signatures and X.509 chains.
//!
//! These algorithms are deliberately absent from [`crate::provider`] and every
//! existing browser profile. [`ALGORITHMS`] contains only ML-DSA; a future caller
//! must explicitly choose its certificate-chain algorithms and advertised TLS
//! signature schemes. It is not a ready-to-use browser configuration.
//!
//! The verifier accepts a raw public key and an ordinary message with the empty
//! FIPS 204 context. It does not use HashML-DSA or `ML-DSA.Verify_internal`.
//! For TLS 1.3, rustls constructs the CertificateVerify message; for X.509, WebPKI
//! supplies the original signed DER. Do not prehash or add the TLS context twice.
//!
//! Both AlgorithmIdentifiers are the exact parameter-absent PKIX encodings.
//! WebPKI matches them before passing the BIT STRING contents to these verifiers,
//! rejecting NULL parameters, wrong OIDs and nonzero unused bits. Raw-key
//! verification alone does not validate a certificate chain, hostname, usage,
//! validity period or pin. Callers must retain those checks.
//!
//! The vendored rustls TLS 1.2 verification entry point rejects all three ML-DSA
//! SignatureSchemes, even when this explicit mapping is supplied. This module
//! provides no signing-key loader and makes no FIPS validation claim.

use ml_dsa::{EncodedVerifyingKey, MlDsaParams, Signature, Verifier as _, VerifyingKey};
use rustls::{
    SignatureScheme,
    crypto::WebPkiSupportedAlgorithms,
    pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm, alg_id},
};

fn verify<P: MlDsaParams>(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), InvalidSignature> {
    // Validate both encoded lengths and the signature's canonical form before
    // expanding the public key's matrix. These are public, untrusted inputs.
    let encoded = EncodedVerifyingKey::<P>::try_from(public_key).map_err(|_| InvalidSignature)?;
    let signature = Signature::<P>::try_from(signature).map_err(|_| InvalidSignature)?;
    let key = VerifyingKey::<P>::decode(&encoded);
    key.verify(message, &signature)
        .map_err(|_| InvalidSignature)
}

macro_rules! verifier {
    ($name:ident, $parameter:ident, $identifier:ident) => {
        #[derive(Debug)]
        struct $name;

        impl SignatureVerificationAlgorithm for $name {
            fn public_key_alg_id(&self) -> AlgorithmIdentifier {
                alg_id::$identifier
            }

            fn signature_alg_id(&self) -> AlgorithmIdentifier {
                alg_id::$identifier
            }

            fn verify_signature(
                &self,
                public_key: &[u8],
                message: &[u8],
                signature: &[u8],
            ) -> Result<(), InvalidSignature> {
                verify::<ml_dsa::$parameter>(public_key, message, signature)
            }
        }
    };
}

verifier!(MlDsa44Verifier, MlDsa44, ML_DSA_44);
verifier!(MlDsa65Verifier, MlDsa65, ML_DSA_65);
verifier!(MlDsa87Verifier, MlDsa87, ML_DSA_87);

/// ML-DSA-44: 1312-byte public key and 2420-byte signature, empty context.
pub static ML_DSA_44: &dyn SignatureVerificationAlgorithm = &MlDsa44Verifier;
/// ML-DSA-65: 1952-byte public key and 3309-byte signature, empty context.
pub static ML_DSA_65: &dyn SignatureVerificationAlgorithm = &MlDsa65Verifier;
/// ML-DSA-87: 2592-byte public key and 4627-byte signature, empty context.
pub static ML_DSA_87: &dyn SignatureVerificationAlgorithm = &MlDsa87Verifier;

/// An explicit, ML-DSA-only collection for WebPKI chains and TLS 1.3 signatures.
///
/// `all` controls certificate-chain signatures; `mapping` controls advertised
/// TLS signature schemes. No global/default provider is changed by accessing
/// this constant. A caller adding classical algorithms must do so explicitly.
pub const ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[ML_DSA_44, ML_DSA_65, ML_DSA_87],
    mapping: &[
        (SignatureScheme::ML_DSA_44, &[ML_DSA_44]),
        (SignatureScheme::ML_DSA_65, &[ML_DSA_65]),
        (SignatureScheme::ML_DSA_87, &[ML_DSA_87]),
    ],
};
