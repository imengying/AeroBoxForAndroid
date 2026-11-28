//! Exact cryptographic choices for the Android Firefox120 fingerprint.
//!
//! Select this explicitly with the matching rustls ClientHello layout and
//! TLS1.2/1.3 policy. The ordinary provider and certificate-chain verification
//! remain unchanged. FFDHE groups are available only for TLS1.3 key exchange.
use std::sync::OnceLock;

use rustls::{
    SignatureScheme,
    crypto::{CryptoProvider, WebPkiSupportedAlgorithms},
};

const CIPHERS: &[u16] = &[
    0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc009, 0xc013,
    0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
];
const SIGNATURES: &[u16] = &[
    0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201,
];

/// Reuse the independently tested record/signature implementations, selecting
/// exactly Firefox's algorithms and order. No TLS1.0, TLS1.1 or 3DES is enabled.
pub fn provider() -> CryptoProvider {
    let mut provider = crate::android_browser::provider(crate::android_browser::Profile::Safari16);
    provider.cipher_suites = CIPHERS
        .iter()
        .map(|id| {
            *provider
                .cipher_suites
                .iter()
                .find(|suite| u16::from(suite.suite()) == *id)
                .expect("Firefox cipher has a real implementation")
        })
        .collect();
    provider.kx_groups.extend([
        &crate::ffdhe::FFDHE2048 as &'static dyn rustls::crypto::SupportedKxGroup,
        &crate::ffdhe::FFDHE3072,
    ]);
    provider.signature_verification_algorithms = algorithms();
    provider
}

fn algorithms() -> WebPkiSupportedAlgorithms {
    static ALGORITHMS: OnceLock<WebPkiSupportedAlgorithms> = OnceLock::new();
    *ALGORITHMS.get_or_init(|| {
        let modern = crate::verify::algorithms();
        let legacy = crate::android_browser::provider(crate::android_browser::Profile::Safari16)
            .signature_verification_algorithms;
        let mapping = SIGNATURES
            .iter()
            .map(|id| {
                let scheme = SignatureScheme::from(*id);
                let implementations = modern
                    .mapping
                    .iter()
                    .chain(legacy.mapping.iter())
                    .find(|(candidate, _)| *candidate == scheme)
                    .expect("Firefox signature has a real implementation")
                    .1;
                (scheme, implementations)
            })
            .collect::<Vec<_>>();
        WebPkiSupportedAlgorithms {
            // SHA1 is deliberately confined to the handshake mapping.
            all: modern.all,
            // The process owns one bounded table, never one table per connection.
            mapping: Box::leak(mapping.into_boxed_slice()),
        }
    })
}
