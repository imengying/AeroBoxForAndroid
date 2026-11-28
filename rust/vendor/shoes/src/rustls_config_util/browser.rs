//! Explicit, version-pinned browser policy shared by stream TLS and REALITY.
use std::io;

pub(crate) mod randomized;

use crate::config::tls::{
    TlsClientFingerprint, TlsClientOptions, TlsKeyExchangeGroup, TlsKeyExchangeGroups, TlsVersion,
};
use rustls::{
    ClientConfig, NamedGroup,
    client::{ApplicationSettings, ApplicationSettingsCodepoint, ClientHelloLayout},
};

pub(super) const CIPHERS: &[u16] = &[
    0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c,
    0x009d, 0x002f, 0x0035,
];

pub(super) fn validate_policy(
    groups: &TlsKeyExchangeGroups,
    options: &TlsClientOptions,
) -> io::Result<()> {
    if options.fingerprint == Some(TlsClientFingerprint::Randomized) {
        return randomized::validate_policy(groups, options);
    }
    if options.fingerprint == Some(TlsClientFingerprint::Browser360_7_5) {
        let expected = [
            TlsKeyExchangeGroup::SecP256r1,
            TlsKeyExchangeGroup::SecP384r1,
            TlsKeyExchangeGroup::SecP521r1,
        ];
        if options.min_version.is_some_and(|v| v != TlsVersion::V10)
            || options.max_version.is_some_and(|v| v != TlsVersion::V12)
            || options.ech.is_some()
            || groups.groups().is_some_and(|g| g != expected)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "360 7.5 conflicts with explicit TLS versions, groups, or ECH",
            ));
        }
        return Ok(());
    }
    if options.fingerprint == Some(TlsClientFingerprint::Firefox120) {
        let expected = [
            TlsKeyExchangeGroup::X25519,
            TlsKeyExchangeGroup::SecP256r1,
            TlsKeyExchangeGroup::SecP384r1,
            TlsKeyExchangeGroup::SecP521r1,
            TlsKeyExchangeGroup::FFDHE2048,
            TlsKeyExchangeGroup::FFDHE3072,
        ];
        if options.min_version.is_some_and(|v| v != TlsVersion::V12)
            || options.max_version.is_some_and(|v| v != TlsVersion::V13)
            || options.ech.is_some()
            || groups.groups().is_some_and(|g| g != expected)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Firefox120 conflicts with explicit TLS versions, groups, or ECH",
            ));
        }
        return Ok(());
    }
    if matches!(
        options.fingerprint,
        Some(
            TlsClientFingerprint::Android11
                | TlsClientFingerprint::Edge85
                | TlsClientFingerprint::Qq11_1
                | TlsClientFingerprint::Safari16
                | TlsClientFingerprint::Ios14
        )
    ) {
        let mut expected = vec![
            TlsKeyExchangeGroup::X25519,
            TlsKeyExchangeGroup::SecP256r1,
            TlsKeyExchangeGroup::SecP384r1,
        ];
        if matches!(
            options.fingerprint,
            Some(TlsClientFingerprint::Safari16 | TlsClientFingerprint::Ios14)
        ) {
            expected.push(TlsKeyExchangeGroup::SecP521r1);
        }
        if options.min_version.is_some_and(|v| v != TlsVersion::V10)
            || options.max_version.is_some_and(|v| {
                v != if options.fingerprint == Some(TlsClientFingerprint::Android11) {
                    TlsVersion::V12
                } else {
                    TlsVersion::V13
                }
            })
            || options.ech.is_some()
            || groups.groups().is_some_and(|g| g != expected)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "browser profile conflicts with explicit TLS policy or ECH",
            ));
        }
        return Ok(());
    }
    let expected = [
        TlsKeyExchangeGroup::X25519MLKEM768,
        TlsKeyExchangeGroup::X25519,
        TlsKeyExchangeGroup::SecP256r1,
        TlsKeyExchangeGroup::SecP384r1,
    ];
    if options.min_version.is_some_and(|v| v != TlsVersion::V12)
        || options.max_version.is_some_and(|v| v != TlsVersion::V13)
        || groups.groups().is_some_and(|g| g != expected)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Chrome133 conflicts with the explicit TLS version or key exchange policy",
        ));
    }
    Ok(())
}

pub(super) const ANDROID_CIPHERS: &[u16] = &[
    0xc02b, 0xc02c, 0xcca9, 0xc02f, 0xc030, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
];
const SAFARI_CIPHERS: &[u16] = &[
    0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8, 0xc00a, 0xc009, 0xc014,
    0xc013, 0x009d, 0x009c, 0x0035, 0x002f, 0xc008, 0xc012, 0x000a,
];
const IOS_CIPHERS: &[u16] = &[
    0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8, 0xc024, 0xc023, 0xc00a,
    0xc009, 0xc028, 0xc027, 0xc014, 0xc013, 0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f, 0xc008,
    0xc012, 0x000a,
];

const FIREFOX_CIPHERS: &[u16] = &[
    0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc009, 0xc013,
    0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
];

pub(super) fn ciphers(profile: TlsClientFingerprint) -> io::Result<&'static [u16]> {
    Ok(match profile {
        TlsClientFingerprint::Randomized => aerobox_fingerprint::randomized::process_plan()
            .map_err(io::Error::other)?
            .suites(),
        TlsClientFingerprint::Chrome133
        | TlsClientFingerprint::Edge85
        | TlsClientFingerprint::Qq11_1 => CIPHERS,
        TlsClientFingerprint::Android11 => ANDROID_CIPHERS,
        TlsClientFingerprint::Safari16 => SAFARI_CIPHERS,
        TlsClientFingerprint::Ios14 => IOS_CIPHERS,
        TlsClientFingerprint::Firefox120 => FIREFOX_CIPHERS,
        TlsClientFingerprint::Browser360_7_5 => aerobox_crypto::browser360::CIPHER_IDS,
    })
}

pub(crate) fn configure_profile(
    config: &mut ClientConfig,
    profile: TlsClientFingerprint,
    reality: bool,
    tls13_only: bool,
) -> io::Result<()> {
    if profile == TlsClientFingerprint::Randomized {
        return randomized::configure(config, reality, tls13_only);
    }
    if profile == TlsClientFingerprint::Browser360_7_5 {
        if reality || tls13_only || config.application_settings.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "360 7.5 cannot use REALITY, TLS1.3-only policy, or ALPS",
            ));
        }
        if config.alpn_protocols.is_empty() {
            config.alpn_protocols = [b"spdy/2".as_slice(), b"spdy/3", b"spdy/3.1", b"http/1.1"]
                .into_iter()
                .map(<[u8]>::to_vec)
                .collect();
        }
        config.cert_compressors.clear();
        config.cert_decompressors.clear();
        config.initial_key_share_groups.clear();
        config.enable_tls12_renegotiation = true;
        config.resumption = rustls::client::Resumption::disabled();
        config.enable_early_data = false;
        config.require_ems = false;
        config.enable_delegated_credentials = false;
        config.advertise_record_size_limit = false;
        config
            .enable_legacy_tls(
                &aerobox_crypto::browser360::LEGACY_TLS,
                &[
                    rustls::ProtocolVersion::TLSv1_0,
                    rustls::ProtocolVersion::TLSv1_1,
                    rustls::ProtocolVersion::TLSv1_2,
                ],
            )
            .map_err(io::Error::other)?;
        config.client_hello_layout = Some(ClientHelloLayout::Browser360_7_5);
        return Ok(());
    }
    if profile == TlsClientFingerprint::Firefox120 {
        if config.alpn_protocols.is_empty() {
            config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        }
        config.application_settings = None;
        config.cert_compressors.clear();
        config.cert_decompressors.clear();
        config.initial_key_share_groups = vec![NamedGroup::X25519, NamedGroup::secp256r1];
        config.enable_tls12_renegotiation = !reality && !tls13_only;
        config.resumption = rustls::client::Resumption::disabled();
        config.enable_early_data = false;
        config.advertise_record_size_limit = true;
        config.enable_delegated_credentials = true;
        config.client_hello_layout = Some(ClientHelloLayout::Firefox120);
        return Ok(());
    }
    if profile == TlsClientFingerprint::Chrome133 {
        return configure(config, reality);
    }
    if matches!(
        profile,
        TlsClientFingerprint::Edge85
            | TlsClientFingerprint::Qq11_1
            | TlsClientFingerprint::Safari16
            | TlsClientFingerprint::Ios14
    ) {
        return configure_classic(config, profile, reality, tls13_only);
    }
    if reality || !config.alpn_protocols.is_empty() || config.application_settings.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Android11 cannot use REALITY, ALPN, or ALPS",
        ));
    }
    config.cert_compressors.clear();
    config.cert_decompressors.clear();
    config.enable_tls12_renegotiation = false;
    config
        .enable_legacy_tls(
            &aerobox_crypto::legacy_provider::LEGACY_TLS,
            &[
                rustls::ProtocolVersion::TLSv1_0,
                rustls::ProtocolVersion::TLSv1_1,
                rustls::ProtocolVersion::TLSv1_2,
            ],
        )
        .map_err(io::Error::other)?;
    config.client_hello_layout = Some(ClientHelloLayout::Android11);
    Ok(())
}

/// Install this after all chain/name/pin policy wrappers. REALITY retains its
/// connection-owned HMAC verifier; its original certificate path is distinct.
pub(crate) fn profile_verifier(
    inner: std::sync::Arc<dyn rustls::client::danger::ServerCertVerifier>,
    profile: Option<TlsClientFingerprint>,
) -> std::sync::Arc<dyn rustls::client::danger::ServerCertVerifier> {
    if profile == Some(TlsClientFingerprint::Firefox120) {
        std::sync::Arc::new(aerobox_crypto::delegated_credentials::Verifier::new(inner))
    } else {
        inner
    }
}

pub(crate) fn profile_provider(
    profile: TlsClientFingerprint,
) -> io::Result<rustls::crypto::CryptoProvider> {
    profile_provider_for_stream(profile, false)
}

pub(crate) fn profile_provider_for_stream(
    profile: TlsClientFingerprint,
    reality: bool,
) -> io::Result<rustls::crypto::CryptoProvider> {
    if profile == TlsClientFingerprint::Randomized {
        return randomized::provider(reality);
    }
    if profile == TlsClientFingerprint::Browser360_7_5 {
        return Ok(aerobox_crypto::browser360::provider());
    }
    if profile == TlsClientFingerprint::Firefox120 {
        return Ok(aerobox_crypto::firefox::provider());
    }
    if matches!(
        profile,
        TlsClientFingerprint::Safari16 | TlsClientFingerprint::Ios14
    ) {
        return Ok(aerobox_crypto::android_browser::provider(
            if profile == TlsClientFingerprint::Safari16 {
                aerobox_crypto::android_browser::Profile::Safari16
            } else {
                aerobox_crypto::android_browser::Profile::Ios14
            },
        ));
    }
    if profile == TlsClientFingerprint::Android11 {
        return Ok(aerobox_crypto::legacy_provider::provider());
    }
    let mut provider = provider();
    if matches!(
        profile,
        TlsClientFingerprint::Edge85 | TlsClientFingerprint::Qq11_1
    ) {
        provider
            .kx_groups
            .retain(|group| group.name() != NamedGroup::X25519MLKEM768);
    }
    Ok(provider)
}

fn configure_classic(
    config: &mut ClientConfig,
    profile: TlsClientFingerprint,
    reality: bool,
    tls13_only: bool,
) -> io::Result<()> {
    if config.alpn_protocols.is_empty() {
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    }
    config.application_settings = if profile == TlsClientFingerprint::Qq11_1 {
        Some(
            ApplicationSettings::new(
                ApplicationSettingsCodepoint::Legacy,
                vec![(b"h2".to_vec(), vec![])],
            )
            .map_err(io::Error::other)?,
        )
    } else {
        None
    };
    config.cert_compressors.clear();
    config.cert_decompressors = match profile {
        TlsClientFingerprint::Safari16 => vec![rustls::compress::ZLIB_DECOMPRESSOR],
        TlsClientFingerprint::Ios14 => vec![],
        _ => vec![rustls::compress::BROTLI_DECOMPRESSOR],
    };
    config.initial_key_share_groups = vec![NamedGroup::X25519];
    config.enable_tls12_renegotiation = !reality && !tls13_only;
    config.resumption = rustls::client::Resumption::disabled();
    config.enable_early_data = false;
    if !reality && !tls13_only {
        config
            .enable_legacy_tls(
                if matches!(
                    profile,
                    TlsClientFingerprint::Safari16 | TlsClientFingerprint::Ios14
                ) {
                    &aerobox_crypto::legacy_tdes::LEGACY_TLS_WITH_TDES
                } else {
                    &aerobox_crypto::legacy_provider::LEGACY_TLS
                },
                &[
                    rustls::ProtocolVersion::TLSv1_0,
                    rustls::ProtocolVersion::TLSv1_1,
                    rustls::ProtocolVersion::TLSv1_2,
                    rustls::ProtocolVersion::TLSv1_3,
                ],
            )
            .map_err(io::Error::other)?;
    }
    config.client_hello_layout = Some(match profile {
        TlsClientFingerprint::Edge85 => ClientHelloLayout::Edge85,
        TlsClientFingerprint::Qq11_1 => ClientHelloLayout::Qq11_1,
        TlsClientFingerprint::Safari16 => ClientHelloLayout::Safari16,
        TlsClientFingerprint::Ios14 => ClientHelloLayout::Ios14,
        _ => unreachable!("fixed TLS1.0..1.3 browser profile"),
    });
    Ok(())
}

pub(crate) fn provider() -> rustls::crypto::CryptoProvider {
    let mut provider = aerobox_crypto::provider();
    let available: Vec<_> = provider
        .cipher_suites
        .iter()
        .copied()
        .chain(aerobox_crypto::legacy_cbc::suites())
        .chain(aerobox_crypto::legacy_rsa::suites())
        .collect();
    provider.cipher_suites = CIPHERS
        .iter()
        .map(|id| {
            *available
                .iter()
                .find(|suite| u16::from(suite.suite()) == *id)
                .expect("compiled Chrome133 cipher implementation")
        })
        .collect();
    provider.kx_groups = [
        NamedGroup::X25519MLKEM768,
        NamedGroup::X25519,
        NamedGroup::secp256r1,
        NamedGroup::secp384r1,
    ]
    .into_iter()
    .map(crate::crypto::rustcrypto_kx::group)
    .collect();
    provider
}

pub(crate) fn configure(config: &mut ClientConfig, reality: bool) -> io::Result<()> {
    if config.alpn_protocols.is_empty() {
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    }
    // The pinned uTLS wrapper overrides ALPN while retaining the h2 ALPS offer.
    config.application_settings = Some(
        ApplicationSettings::new(
            ApplicationSettingsCodepoint::Chrome,
            vec![(b"h2".to_vec(), vec![])],
        )
        .map_err(io::Error::other)?,
    );
    config.cert_compressors.clear();
    config.cert_decompressors = vec![rustls::compress::BROTLI_DECOMPRESSOR];
    config.initial_key_share_groups = if reality {
        vec![NamedGroup::X25519]
    } else {
        vec![NamedGroup::X25519MLKEM768, NamedGroup::X25519]
    };
    config.client_hello_layout = Some(ClientHelloLayout::Chrome133);
    config.enable_tls12_renegotiation = !reality;
    // sing-box's pinned wrapper does not configure a client session cache.
    config.resumption = rustls::client::Resumption::disabled();
    config.enable_early_data = false;
    Ok(())
}

#[cfg(test)]
mod tests;
