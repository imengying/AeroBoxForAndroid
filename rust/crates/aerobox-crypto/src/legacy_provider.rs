//! Explicit Android 11 TLS provider. Selecting this provider is separate from
//! enabling old protocol versions through `ClientConfig::enable_legacy_tls`.
//! The normal provider retains its current version, cipher and signature policy.
use rustls::{
    CipherSuite, Error, NamedGroup, ProtocolVersion, SignatureAlgorithm, SignatureScheme,
    SupportedCipherSuite, Tls12CipherSuite,
    client::{LegacyTlsProvider, danger::HandshakeSignatureValid},
    crypto::{CipherSuiteCommon, CryptoProvider},
    pki_types::CertificateDer,
};

/// The implementation selected only by the explicit legacy client builder.
pub static LEGACY_TLS: Android11LegacyTls = Android11LegacyTls;

/// Pure Rust pre-TLS-1.2 handshake cryptography for Android11 compatibility.
#[derive(Debug)]
pub struct Android11LegacyTls;

const RSA_TLS12_SIGNATURES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA256,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA1,
];
const ECDSA_TLS12_SIGNATURES: &[SignatureScheme] = &[
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::ECDSA_NISTP384_SHA384,
];

/// Construct the exact Android11 cipher/signature/group choices from fixed
/// uTLS v1.8.7. This does not install a process-global default provider.
pub fn provider() -> CryptoProvider {
    let mut provider = crate::provider();
    provider.cipher_suites = ANDROID11_TLS12
        .iter()
        .map(SupportedCipherSuite::Tls12)
        .collect();
    provider.kx_groups.retain(|group| {
        matches!(
            group.name(),
            NamedGroup::X25519 | NamedGroup::secp256r1 | NamedGroup::secp384r1
        )
    });
    provider.signature_verification_algorithms = crate::verify::android11_algorithms();
    provider.key_provider = &crate::signing::LegacyProvider;
    provider
}

const fn tls12_suite(base: &'static Tls12CipherSuite, rsa: bool) -> Tls12CipherSuite {
    Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: base.common.suite,
            hash_provider: base.common.hash_provider,
            confidentiality_limit: base.common.confidentiality_limit,
        },
        prf_provider: base.prf_provider,
        kx: base.kx,
        sign: if rsa {
            RSA_TLS12_SIGNATURES
        } else {
            ECDSA_TLS12_SIGNATURES
        },
        aead_alg: base.aead_alg,
    }
}

// The provider's TLS 1.2 records deliberately remain separate from old-version
// records. In particular, the same CBC suite ID changes its PRF and IV shape
// only after the explicitly enabled legacy client negotiates TLS 1.0/1.1.
static ANDROID11_TLS12: [Tls12CipherSuite; 12] = [
    tls12_suite(&crate::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, false),
    tls12_suite(&crate::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, false),
    tls12_suite(&crate::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, false),
    tls12_suite(&crate::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, true),
    tls12_suite(&crate::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, true),
    tls12_suite(&crate::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, true),
    tls12_suite(&crate::legacy_cbc::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, true),
    tls12_suite(&crate::legacy_cbc::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, true),
    tls12_suite(&crate::legacy_rsa::TLS_RSA_WITH_AES_128_GCM_SHA256, true),
    tls12_suite(&crate::legacy_rsa::TLS_RSA_WITH_AES_256_GCM_SHA384, true),
    tls12_suite(&crate::legacy_rsa::TLS_RSA_WITH_AES_128_CBC_SHA, true),
    tls12_suite(&crate::legacy_rsa::TLS_RSA_WITH_AES_256_CBC_SHA, true),
];

const fn legacy_suite(
    base: &'static Tls12CipherSuite,
    version: ProtocolVersion,
    key_len: usize,
    rsa: bool,
) -> Tls12CipherSuite {
    Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: base.common.suite,
            hash_provider: &crate::legacy_hash::MD5_SHA1,
            confidentiality_limit: base.common.confidentiality_limit,
        },
        prf_provider: &crate::legacy_prf::TLS10_PRF,
        kx: base.kx,
        sign: if rsa {
            &[SignatureScheme::RSA_PKCS1_MD5_SHA1_Legacy]
        } else {
            &[SignatureScheme::ECDSA_SHA1_Legacy]
        },
        aead_alg: match crate::legacy_cbc::algorithm_for_version(key_len, version) {
            Some(algorithm) => algorithm,
            None => panic!("legacy suites require implemented AES-CBC versions"),
        },
    }
}

macro_rules! legacy_suites {
    ($version:expr) => {
        [
            legacy_suite(
                &crate::legacy_cbc::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                $version,
                16,
                true,
            ),
            legacy_suite(
                &crate::legacy_cbc::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                $version,
                32,
                true,
            ),
            legacy_suite(
                &crate::legacy_cbc::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                $version,
                16,
                false,
            ),
            legacy_suite(
                &crate::legacy_cbc::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
                $version,
                32,
                false,
            ),
            legacy_suite(
                &crate::legacy_rsa::TLS_RSA_WITH_AES_128_CBC_SHA,
                $version,
                16,
                true,
            ),
            legacy_suite(
                &crate::legacy_rsa::TLS_RSA_WITH_AES_256_CBC_SHA,
                $version,
                32,
                true,
            ),
        ]
    };
}
static TLS10: [Tls12CipherSuite; 6] = legacy_suites!(ProtocolVersion::TLSv1_0);
static TLS11: [Tls12CipherSuite; 6] = legacy_suites!(ProtocolVersion::TLSv1_1);

impl LegacyTlsProvider for Android11LegacyTls {
    fn cipher_suite(
        &self,
        suite: CipherSuite,
        version: ProtocolVersion,
    ) -> Option<&'static Tls12CipherSuite> {
        let suites = match version {
            ProtocolVersion::TLSv1_0 => &TLS10,
            ProtocolVersion::TLSv1_1 => &TLS11,
            _ => return None,
        };
        suites
            .iter()
            .find(|candidate| candidate.common.suite == suite)
    }

    fn verify_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        algorithm: SignatureAlgorithm,
        signature: &[u8],
    ) -> Result<HandshakeSignatureValid, Error> {
        match algorithm {
            SignatureAlgorithm::RSA => {
                crate::legacy_sign::verify_rsa_certificate(cert, &[message], signature)?
            }
            SignatureAlgorithm::ECDSA => {
                crate::legacy_sign::verify_ecdsa_sha1_certificate(cert, message, signature)?
            }
            _ => {
                return Err(Error::General(
                    "unsupported legacy handshake signature algorithm".into(),
                ));
            }
        }
        Ok(HandshakeSignatureValid::assertion())
    }
}

#[cfg(test)]
mod tests;
