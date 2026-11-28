//! Bounded cryptographic selection for the pinned Android randomized plan.
//!
//! This is an explicit capability constructor. The connection adapter must
//! install the corresponding ClientHello, version/group policy and actual-offer
//! signature checks. It neither samples a seed nor changes the default provider.
use rustls::{
    CipherSuite, Error, ProtocolVersion, SignatureScheme, SupportedCipherSuite, Tls12CipherSuite,
    client::LegacyTlsProvider, crypto::CryptoProvider,
};

const CIPHERS: &[u16] = &[
    0x1301, 0x1302, 0x1303, 0xcca8, 0xcca9, 0xc02f, 0xc02b, 0xc030, 0xc02c, 0xc027, 0xc013, 0xc023,
    0xc009, 0xc014, 0xc00a, 0x009c, 0x009d, 0x003c, 0x002f, 0x0035, 0xc012, 0x000a, 0x0005, 0xc011,
    0xc007,
];

/// Preserve the generated suite order while supplying only real
/// algorithms. An unrecognized or duplicate ID fails before connection setup.
/// SHA1 remains restricted to handshake mappings; it is never a certificate
/// chain algorithm. Dynamic signatures are enforced from the final sent offer.
pub fn provider(suites: &[u16]) -> Result<CryptoProvider, Error> {
    if suites.is_empty() || suites.len() > 22 {
        return Err(invalid());
    }
    for (index, id) in suites.iter().enumerate() {
        if !CIPHERS.contains(id) || suites[..index].contains(id) {
            return Err(invalid());
        }
    }
    let mut result = crate::android_browser::provider(crate::android_browser::Profile::Ios14);
    let available_suites: Vec<_> = result
        .cipher_suites
        .iter()
        .copied()
        .chain(RC4_SUITES.iter().map(SupportedCipherSuite::Tls12))
        .collect();
    result.cipher_suites = suites
        .iter()
        .map(|id| {
            available_suites
                .iter()
                .find(|suite| u16::from(suite.suite()) == *id)
                .copied()
                .ok_or_else(invalid)
        })
        .collect::<Result<_, _>>()?;
    // The transport selects the generated group list from its existing
    // classical/hybrid implementations. Keeping hybrid key ownership there
    // avoids duplicating the production ML-KEM implementation in this crate.
    // Firefox's fixed bounded mapping contains exactly the 11 possible
    // randomized handshake signature algorithms, including P521 and legacy
    // SHA1, with a separate strong certificate-chain algorithm set. It is
    // allocated once per process, never once per generated plan/connection.
    result.signature_verification_algorithms =
        crate::firefox::provider().signature_verification_algorithms;
    Ok(result)
}

fn invalid() -> Error {
    Error::General("randomized crypto plan contains invalid or unavailable capabilities".into())
}

const RSA_SIGNATURES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA256,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA1,
];
const ECDSA_SIGNATURES: &[SignatureScheme] = &[
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_NISTP521_SHA512,
    SignatureScheme::ECDSA_SHA1_Legacy,
];
const fn rc4(base: &'static Tls12CipherSuite, rsa: bool) -> Tls12CipherSuite {
    Tls12CipherSuite {
        common: rustls::crypto::CipherSuiteCommon {
            suite: base.common.suite,
            hash_provider: base.common.hash_provider,
            confidentiality_limit: base.common.confidentiality_limit,
        },
        prf_provider: base.prf_provider,
        kx: base.kx,
        aead_alg: base.aead_alg,
        sign: if rsa {
            RSA_SIGNATURES
        } else {
            ECDSA_SIGNATURES
        },
    }
}
static RC4_SUITES: [Tls12CipherSuite; 3] = [
    rc4(&crate::legacy_rc4::TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, false),
    rc4(&crate::legacy_rc4::TLS_ECDHE_RSA_WITH_RC4_128_SHA, true),
    rc4(&crate::legacy_rc4::TLS_RSA_WITH_RC4_128_SHA, true),
];

/// The explicit old-version dispatcher for the possible generated suite pool.
/// Calling `provider` alone does not enable TLS1.0/1.1. The transport must opt in
/// with only the versions present in its final validated structural plan.
pub static LEGACY_TLS: Legacy = Legacy;
#[derive(Debug)]
pub struct Legacy;
impl LegacyTlsProvider for Legacy {
    fn cipher_suite(
        &self,
        id: CipherSuite,
        version: ProtocolVersion,
    ) -> Option<&'static Tls12CipherSuite> {
        if !CIPHERS.contains(&u16::from(id)) {
            return None;
        }
        crate::legacy_rc4::LEGACY_TLS_WITH_RC4
            .cipher_suite(id, version)
            .or_else(|| crate::legacy_tdes::LEGACY_TLS_WITH_TDES.cipher_suite(id, version))
    }
    fn verify_signature(
        &self,
        message: &[u8],
        certificate: &rustls::pki_types::CertificateDer<'_>,
        algorithm: rustls::SignatureAlgorithm,
        signature: &[u8],
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        crate::legacy_provider::LEGACY_TLS.verify_signature(
            message,
            certificate,
            algorithm,
            signature,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn every_generated_cipher_has_a_real_provider_and_version_builder() {
        for id in CIPHERS {
            let selected = provider(&[*id]).unwrap();
            assert_eq!(u16::from(selected.cipher_suites[0].suite()), *id);
            let version = if (0x1301..=0x1303).contains(id) {
                &rustls::version::TLS13
            } else {
                &rustls::version::TLS12
            };
            assert!(
                rustls::ClientConfig::builder_with_provider(Arc::new(selected))
                    .with_protocol_versions(&[version])
                    .is_ok(),
                "suite {id:04x}"
            );
        }
    }

    #[test]
    fn unknown_duplicate_and_non_generator_algorithms_are_rejected_without_fallback() {
        for suites in [
            vec![],
            vec![0x1301, 0x1301],
            vec![0xffff],
            vec![0x003d],
            vec![0xc008],
            vec![0xc024],
            vec![0xc028],
        ] {
            assert!(provider(&suites).is_err());
        }
        let selected = provider(&[0xc013, 0x1303, 0xc02f]).unwrap();
        assert_eq!(
            selected
                .cipher_suites
                .iter()
                .map(|s| u16::from(s.suite()))
                .collect::<Vec<_>>(),
            [0xc013, 0x1303, 0xc02f]
        );
    }

    #[test]
    fn legacy_dispatch_does_not_promote_tls12_aead_or_sha2_cbc_to_old_versions() {
        for version in [ProtocolVersion::TLSv1_0, ProtocolVersion::TLSv1_1] {
            for id in [
                0xc013, 0xc009, 0xc014, 0xc00a, 0x002f, 0x0035, 0xc012, 0x000a, 5, 0xc011, 0xc007,
            ] {
                assert_eq!(
                    LEGACY_TLS
                        .cipher_suite(CipherSuite::from(id), version)
                        .unwrap()
                        .common
                        .suite,
                    CipherSuite::from(id)
                );
            }
            for id in [
                0x1301, 0xc02f, 0xc027, 0xc023, 0x009c, 0x003c, 0xc008, 0xffff,
            ] {
                assert!(
                    LEGACY_TLS
                        .cipher_suite(CipherSuite::from(id), version)
                        .is_none()
                );
            }
        }
        assert!(
            LEGACY_TLS
                .cipher_suite(
                    CipherSuite::TLS_RSA_WITH_RC4_128_SHA,
                    ProtocolVersion::TLSv1_3
                )
                .is_none()
        );
    }

    #[test]
    fn signature_capability_is_bounded_and_strong_chain_policy_is_preserved() {
        let selected = provider(&[0xc007, 0xc011]).unwrap();
        let algorithms = selected.signature_verification_algorithms;
        let ids = algorithms
            .supported_schemes()
            .iter()
            .copied()
            .map(u16::from)
            .collect::<Vec<_>>();
        assert_eq!(
            ids,
            [
                0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203,
                0x0201
            ]
        );
        assert!(std::ptr::eq(
            algorithms.all,
            crate::provider().signature_verification_algorithms.all
        ));
        let again = provider(&[0x1301])
            .unwrap()
            .signature_verification_algorithms;
        assert!(std::ptr::eq(algorithms.mapping, again.mapping));
        let ordinary = crate::provider();
        assert!(
            !ordinary
                .cipher_suites
                .iter()
                .any(|s| [5, 0xc011, 0xc007].contains(&u16::from(s.suite())))
        );
        assert!(
            !ordinary
                .signature_verification_algorithms
                .supported_schemes()
                .contains(&SignatureScheme::ECDSA_SHA1_Legacy)
        );
    }
}
