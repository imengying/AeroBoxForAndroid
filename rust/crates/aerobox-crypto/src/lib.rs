//! An explicit RustCrypto provider for rustls 0.23, including QUIC protection.
//!
//! TLS signatures, key exchange and record protection reuse rustls-rustcrypto.
//! This crate supplies the QUIC packet/header protection absent from that
//! provider. Callers must select this provider explicitly with rustls builders;
//! installing it does not remove native crypto enabled by other dependencies.

use std::sync::{Arc, OnceLock};

use rustls::{SupportedCipherSuite, Tls12CipherSuite, Tls13CipherSuite, crypto::CryptoProvider};

pub mod android_browser;
pub mod browser360;
pub mod delegated_credentials;
pub mod ffdhe;
pub mod firefox;
pub mod hpke;
mod kx;
pub mod mldsa;
pub mod legacy_cbc;
pub mod legacy_cbc_sha2;
pub mod legacy_hash;
pub mod legacy_prf;
pub mod legacy_provider;
pub mod legacy_rc4;
pub mod randomized;
pub mod legacy_rsa;
pub mod legacy_sign;
pub mod legacy_tdes;
mod quic;
mod record;
mod signing;
mod verify;

/// Construct a provider without ring, AWS-LC, OpenSSL or native TLS backends.
///
/// The underlying provider is an upstream alpha. Its validation and compatibility
/// status must remain visible to applications choosing the strict Rust backend.
pub fn provider() -> CryptoProvider {
    let mut provider = rustls_rustcrypto::provider();
    provider.kx_groups = kx::groups();
    provider.key_provider = &signing::Provider;
    provider.signature_verification_algorithms = verify::algorithms();
    // Prefer TLS 1.3. All TLS 1.3 suites include QUIC support; rustls omits TLS
    // 1.2 automatically for QUIC connections.
    provider.cipher_suites = vec![
        SupportedCipherSuite::Tls13(&TLS13_AES_128_GCM_SHA256),
        SupportedCipherSuite::Tls13(&TLS13_AES_256_GCM_SHA384),
        SupportedCipherSuite::Tls13(&TLS13_CHACHA20_POLY1305_SHA256),
        SupportedCipherSuite::Tls12(&TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
        SupportedCipherSuite::Tls12(&TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384),
        SupportedCipherSuite::Tls12(&TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256),
        SupportedCipherSuite::Tls12(&TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
        SupportedCipherSuite::Tls12(&TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384),
        SupportedCipherSuite::Tls12(&TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256),
    ];
    provider
}

/// A shared provider for configuring multiple TLS clients and servers.
pub fn shared_provider() -> Arc<CryptoProvider> {
    static PROVIDER: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
    PROVIDER.get_or_init(|| Arc::new(provider())).clone()
}

pub static TLS13_AES_128_GCM_SHA256: Tls13CipherSuite = with_quic(
    rustls_rustcrypto::TLS13_AES_128_GCM_SHA256,
    &quic::AES_128_GCM,
    &record::TLS13_AES128,
    1 << 24,
);

pub static TLS13_AES_256_GCM_SHA384: Tls13CipherSuite = with_quic(
    rustls_rustcrypto::TLS13_AES_256_GCM_SHA384,
    &quic::AES_256_GCM,
    &record::TLS13_AES256,
    1 << 24,
);

pub static TLS13_CHACHA20_POLY1305_SHA256: Tls13CipherSuite = with_quic(
    rustls_rustcrypto::TLS13_CHACHA20_POLY1305_SHA256,
    &quic::CHACHA20_POLY1305,
    &record::TLS13_CHACHA,
    u64::MAX,
);

// Use the same conservative AES-GCM record limits as rustls's built-in
// providers. The upstream alpha leaves every cipher's limit at u64::MAX.
pub static TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: Tls12CipherSuite = tls12_adapt(
    rustls_rustcrypto::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    &record::TLS12_AES128,
    1 << 24,
);
pub static TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: Tls12CipherSuite = tls12_adapt(
    rustls_rustcrypto::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    &record::TLS12_AES256,
    1 << 24,
);
pub static TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: Tls12CipherSuite = tls12_adapt(
    rustls_rustcrypto::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    &record::TLS12_AES128,
    1 << 24,
);
pub static TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: Tls12CipherSuite = tls12_adapt(
    rustls_rustcrypto::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    &record::TLS12_AES256,
    1 << 24,
);
pub static TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: Tls12CipherSuite = tls12_adapt(
    rustls_rustcrypto::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    &record::TLS12_CHACHA,
    u64::MAX,
);
pub static TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: Tls12CipherSuite = tls12_adapt(
    rustls_rustcrypto::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    &record::TLS12_CHACHA,
    u64::MAX,
);

const fn tls12_adapt(
    suite: SupportedCipherSuite,
    aead: &'static dyn rustls::crypto::cipher::Tls12AeadAlgorithm,
    confidentiality_limit: u64,
) -> Tls12CipherSuite {
    let SupportedCipherSuite::Tls12(suite) = suite else {
        panic!("expected a TLS 1.2 cipher suite");
    };
    Tls12CipherSuite {
        common: rustls::crypto::CipherSuiteCommon {
            suite: suite.common.suite,
            hash_provider: suite.common.hash_provider,
            confidentiality_limit,
        },
        prf_provider: suite.prf_provider,
        kx: suite.kx,
        sign: match suite.common.suite {
            rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            | rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            | rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => &[
                rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
                rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            ],
            _ => suite.sign,
        },
        aead_alg: aead,
    }
}

const fn with_quic(
    suite: SupportedCipherSuite,
    quic: &'static dyn rustls::quic::Algorithm,
    aead: &'static dyn rustls::crypto::cipher::Tls13AeadAlgorithm,
    confidentiality_limit: u64,
) -> Tls13CipherSuite {
    let SupportedCipherSuite::Tls13(suite) = suite else {
        panic!("expected a TLS 1.3 cipher suite");
    };
    Tls13CipherSuite {
        common: rustls::crypto::CipherSuiteCommon {
            suite: suite.common.suite,
            hash_provider: suite.common.hash_provider,
            confidentiality_limit,
        },
        hkdf_provider: suite.hkdf_provider,
        aead_alg: aead,
        quic: Some(quic),
    }
}
