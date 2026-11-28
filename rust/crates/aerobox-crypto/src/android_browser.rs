//! Cryptographic choices for the Android application's `safari` and `ios`
//! fingerprint options (fixed uTLS v1.8.7 Safari16 / iOS14 templates).
//!
//! This selects real algorithms, not a ClientHello wire layout or protocol
//! version policy. A caller must separately configure those rustls settings.
//! SHA-1 signatures are allowed only for explicitly selected old handshakes;
//! the certificate-chain algorithm set and the ordinary provider stay intact.
use std::sync::{Arc, OnceLock};

use rustls::{
    Error, NamedGroup, SignatureAlgorithm, SignatureScheme, SupportedCipherSuite, Tls12CipherSuite,
    crypto::{CryptoProvider, KeyProvider, WebPkiSupportedAlgorithms},
    pki_types::{PrivateKeyDer, SubjectPublicKeyInfoDer},
    sign::{Signer, SigningKey},
};

mod sha1;

/// These are Android configuration values, not supported client platforms.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Profile {
    Safari16,
    Ios14,
}

/// Explicit provider for the exact cipher, group, and signature choices.
/// Neither calling this function nor selecting TLS1.2 enables TLS1.0/1.1.
pub fn provider(profile: Profile) -> CryptoProvider {
    let mut provider = crate::provider();
    provider.cipher_suites.truncate(3);
    provider.cipher_suites.extend(
        TLS12_SUITES
            .iter()
            .filter(|suite| {
                profile == Profile::Ios14
                    || !matches!(
                        u16::from(suite.common.suite),
                        0xc024 | 0xc023 | 0xc028 | 0xc027 | 0x003d | 0x003c
                    )
            })
            .map(SupportedCipherSuite::Tls12),
    );
    provider.kx_groups.retain(|group| {
        matches!(
            group.name(),
            NamedGroup::X25519
                | NamedGroup::secp256r1
                | NamedGroup::secp384r1
                | NamedGroup::secp521r1
        )
    });
    provider.signature_verification_algorithms = signature_algorithms();
    provider.key_provider = &BrowserKeys;
    provider
}

// The repeated RSA_PSS_SHA384 is present in both upstream templates. The
// mapping and supported_schemes() must preserve its position and multiplicity.
const SIGNATURE_SCHEMES: [SignatureScheme; 11] = [
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA256,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_SHA1_Legacy,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA1,
];

fn signature_algorithms() -> WebPkiSupportedAlgorithms {
    static ALGORITHMS: OnceLock<WebPkiSupportedAlgorithms> = OnceLock::new();
    *ALGORITHMS.get_or_init(|| {
        let base = crate::verify::android11_algorithms();
        let mapping = SIGNATURE_SCHEMES
            .into_iter()
            .map(|scheme| {
                let implementations = if scheme == SignatureScheme::ECDSA_SHA1_Legacy {
                    sha1::VERIFIERS
                } else {
                    base.mapping
                        .iter()
                        .find(|(candidate, _)| *candidate == scheme)
                        .expect("browser signature algorithms have real implementations")
                        .1
                };
                (scheme, implementations)
            })
            .collect::<Vec<_>>();
        WebPkiSupportedAlgorithms {
            // In particular, none of the SHA-1 implementations enter `all`.
            all: base.all,
            mapping: Box::leak(mapping.into_boxed_slice()),
        }
    })
}

#[derive(Debug)]
struct BrowserKeys;
impl KeyProvider for BrowserKeys {
    fn supports_rsa_key_exchange(&self) -> bool {
        true
    }
    fn encrypt_tls12_rsa_premaster(
        &self,
        certificate: &rustls::pki_types::CertificateDer<'_>,
        version: rustls::ProtocolVersion,
    ) -> Result<(Vec<u8>, rustls::crypto::SharedSecret), Error> {
        crate::legacy_rsa::encrypt(certificate, version)
    }
    fn load_private_key(&self, der: PrivateKeyDer<'static>) -> Result<Arc<dyn SigningKey>, Error> {
        let key = crate::signing::LegacyProvider.load_private_key(der)?;
        if key.algorithm() == SignatureAlgorithm::ECDSA {
            Ok(Arc::new(BrowserEcdsaKey(key)))
        } else {
            Ok(key)
        }
    }
}

#[derive(Debug)]
struct BrowserEcdsaKey(Arc<dyn SigningKey>);
impl SigningKey for BrowserEcdsaKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        // Prefer the normal SHA-2 signer. The SHA-1 fallback requires an
        // explicit peer offer and never replaces an unsupported modern scheme.
        self.0.choose_scheme(offered).or_else(|| {
            offered
                .contains(&SignatureScheme::ECDSA_SHA1_Legacy)
                .then(|| self.0.choose_legacy_scheme())
                .flatten()
        })
    }
    fn choose_legacy_scheme(&self) -> Option<Box<dyn Signer>> {
        self.0.choose_legacy_scheme()
    }
    fn algorithm(&self) -> SignatureAlgorithm {
        self.0.algorithm()
    }
    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        self.0.public_key()
    }
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

const fn suite(base: &'static Tls12CipherSuite, rsa: bool) -> Tls12CipherSuite {
    Tls12CipherSuite {
        common: rustls::crypto::CipherSuiteCommon {
            suite: base.common.suite,
            hash_provider: base.common.hash_provider,
            confidentiality_limit: base.common.confidentiality_limit,
        },
        prf_provider: base.prf_provider,
        kx: base.kx,
        sign: if rsa {
            RSA_SIGNATURES
        } else {
            ECDSA_SIGNATURES
        },
        aead_alg: base.aead_alg,
    }
}

static TLS12_SUITES: [Tls12CipherSuite; 23] = [
    suite(&crate::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, false),
    suite(&crate::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, false),
    suite(&crate::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, false),
    suite(&crate::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, true),
    suite(&crate::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, true),
    suite(&crate::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, true),
    suite(
        &crate::legacy_cbc_sha2::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
        false,
    ),
    suite(
        &crate::legacy_cbc_sha2::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
        false,
    ),
    suite(
        &crate::legacy_cbc::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
        false,
    ),
    suite(
        &crate::legacy_cbc::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
        false,
    ),
    suite(
        &crate::legacy_cbc_sha2::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
        true,
    ),
    suite(
        &crate::legacy_cbc_sha2::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
        true,
    ),
    suite(&crate::legacy_cbc::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, true),
    suite(&crate::legacy_cbc::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, true),
    suite(&crate::legacy_rsa::TLS_RSA_WITH_AES_256_GCM_SHA384, true),
    suite(&crate::legacy_rsa::TLS_RSA_WITH_AES_128_GCM_SHA256, true),
    suite(
        &crate::legacy_cbc_sha2::TLS_RSA_WITH_AES_256_CBC_SHA256,
        true,
    ),
    suite(
        &crate::legacy_cbc_sha2::TLS_RSA_WITH_AES_128_CBC_SHA256,
        true,
    ),
    suite(&crate::legacy_rsa::TLS_RSA_WITH_AES_256_CBC_SHA, true),
    suite(&crate::legacy_rsa::TLS_RSA_WITH_AES_128_CBC_SHA, true),
    suite(
        &crate::legacy_tdes::TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
        false,
    ),
    suite(
        &crate::legacy_tdes::TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
        true,
    ),
    suite(&crate::legacy_tdes::TLS_RSA_WITH_3DES_EDE_CBC_SHA, true),
];

#[cfg(test)]
mod tests;
