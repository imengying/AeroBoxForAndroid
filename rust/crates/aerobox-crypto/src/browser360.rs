//! Explicit cryptographic capabilities of Android's pinned 360 7.5 profile.
//!
//! The wire template advertises 20 suites and eight signatures. The fixed
//! upstream default implements only these 13 suites and six signatures; fake
//! DHE/DSS/RC4-MD5 and opt-in-only 003d are deliberately absent. This module
//! must be paired with the matching layout and TLS1.0..1.2 version policy.
//! SHA1 is confined to legacy handshake signatures, never certificate chains.
use std::sync::OnceLock;

use rustls::{
    CipherSuite, Error, NamedGroup, ProtocolVersion, SignatureAlgorithm, SignatureScheme,
    SupportedCipherSuite, Tls12CipherSuite,
    client::{LegacyTlsProvider, danger::HandshakeSignatureValid},
    crypto::{CryptoProvider, WebPkiSupportedAlgorithms},
    pki_types::CertificateDer,
};

/// Real suite order, distinct from the 20 advertised wire values.
pub const CIPHER_IDS: &[u16] = &[
    0xc00a, 0xc014, 0x0035, 0xc007, 0xc009, 0xc023, 0xc011, 0xc013, 0xc027, 0x0005, 0x002f, 0x003c,
    0x000a,
];
const SIGNATURE_IDS: &[u16] = &[0x0401, 0x0501, 0x0201, 0x0403, 0x0503, 0x0203];
const RSA_SIGNATURES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PKCS1_SHA256,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA1,
];
const ECDSA_SIGNATURES: &[SignatureScheme] = &[
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_SHA1_Legacy,
];

/// An opt-in provider. The normal provider, random's five-template pool and
/// certificate-chain algorithm set are unchanged. No TLS1.3 suite is present.
pub fn provider() -> CryptoProvider {
    let mut provider = crate::android_browser::provider(crate::android_browser::Profile::Ios14);
    static SUITES: OnceLock<Vec<SupportedCipherSuite>> = OnceLock::new();
    provider.cipher_suites = SUITES
        .get_or_init(|| {
            let available = provider
                .cipher_suites
                .iter()
                .copied()
                .chain(crate::legacy_rc4::suites())
                .collect::<Vec<_>>();
            let suites = CIPHER_IDS
                .iter()
                .map(|id| {
                    let SupportedCipherSuite::Tls12(base) = *available
                        .iter()
                        .find(|suite| u16::from(suite.suite()) == *id)
                        .expect("360 real cipher implementation")
                    else {
                        unreachable!("360 contains only real TLS1.2 suites");
                    };
                    let sign = if matches!(*id, 0xc00a | 0xc007 | 0xc009 | 0xc023) {
                        ECDSA_SIGNATURES
                    } else {
                        RSA_SIGNATURES
                    };
                    Tls12CipherSuite {
                        common: rustls::crypto::CipherSuiteCommon {
                            suite: base.common.suite,
                            hash_provider: base.common.hash_provider,
                            confidentiality_limit: base.common.confidentiality_limit,
                        },
                        prf_provider: base.prf_provider,
                        kx: base.kx,
                        sign,
                        aead_alg: base.aead_alg,
                    }
                })
                .collect::<Vec<_>>();
            // One bounded process table; no per-connection allocation is leaked.
            Box::leak(suites.into_boxed_slice())
                .iter()
                .map(SupportedCipherSuite::Tls12)
                .collect()
        })
        .clone();
    provider.kx_groups.retain(|group| {
        matches!(
            group.name(),
            NamedGroup::secp256r1 | NamedGroup::secp384r1 | NamedGroup::secp521r1
        )
    });
    static ALGORITHMS: OnceLock<WebPkiSupportedAlgorithms> = OnceLock::new();
    provider.signature_verification_algorithms = *ALGORITHMS.get_or_init(|| {
        let base = provider.signature_verification_algorithms;
        let mapping = SIGNATURE_IDS
            .iter()
            .map(|id| {
                let scheme = SignatureScheme::from(*id);
                let implementation = base
                    .mapping
                    .iter()
                    .find(|(s, _)| *s == scheme)
                    .expect("360 real signature implementation")
                    .1;
                (scheme, implementation)
            })
            .collect::<Vec<_>>();
        WebPkiSupportedAlgorithms {
            all: base.all,
            mapping: Box::leak(mapping.into_boxed_slice()),
        }
    });
    provider
}

/// Only explicitly enabled old versions use implicit MD5/SHA1 legacy handshake
/// signatures and old record construction. TLS1.2 SHA2-CBC suites stay 1.2-only.
#[derive(Debug)]
pub struct Legacy360;
pub static LEGACY_TLS: Legacy360 = Legacy360;
impl LegacyTlsProvider for Legacy360 {
    fn cipher_suite(
        &self,
        id: CipherSuite,
        version: ProtocolVersion,
    ) -> Option<&'static Tls12CipherSuite> {
        if !CIPHER_IDS.contains(&u16::from(id)) {
            return None;
        }
        crate::legacy_rc4::LEGACY_TLS_WITH_RC4
            .cipher_suite(id, version)
            .or_else(|| crate::legacy_tdes::LEGACY_TLS_WITH_TDES.cipher_suite(id, version))
    }

    fn verify_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        algorithm: SignatureAlgorithm,
        signature: &[u8],
    ) -> Result<HandshakeSignatureValid, Error> {
        crate::legacy_provider::LEGACY_TLS.verify_signature(message, cert, algorithm, signature)
    }
}
