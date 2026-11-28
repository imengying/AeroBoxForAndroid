//! Controlled ClientHello construction before transcript hashing.
use super::{hs::ClientContext, ClientConfig};
use crate::crypto::SecureRandom;
use crate::msgs::base::{PayloadU16, PayloadU8};
use crate::msgs::enums::{ExtensionType, HpkeAead, HpkeKdf};
use crate::msgs::handshake::{
    ClientHelloPayload, ClientSessionTicket, EncryptedClientHello, EncryptedClientHelloOuter,
    HpkeSymmetricCipherSuite, KeyShareEntry,
};
use crate::{CipherSuite, Error, NamedGroup, ProtocolVersion, SignatureScheme};
use alloc::{vec, vec::Vec};

/// A wire construction policy, separate from certificate authentication.
///
/// This is not an application-level browser compatibility promise. TLS 1.2
/// renegotiation requires separate validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClientHelloLayout {
    /// The initial Chrome 133 ClientHello structure pinned by AeroBox.
    /// Requires all listed cryptographic capabilities, TLS 1.2/1.3, Brotli,
    /// ALPS 17613 for h2 and independent hybrid/X25519 initial shares.
    /// ECH keeps this outer layout and uses a TLS 1.3 inner hello. This does
    /// not prescribe the browser's private inner-hello encoding. REALITY
    /// authenticates with the independent X25519 share. QUIC is rejected.
    Chrome133,
    /// Fixed Naive/Chromium150 TCP TLS layout, including ML-DSA verification
    /// offers and BoringSSL's complete extension permutation. `aes_hardware`
    /// is the caller's actual CPU capability decision and also selects the
    /// GREASE ECH AEAD. Requires independent hybrid/X25519 shares, Brotli and
    /// h2 ALPS. Actual ECH uses the existing authenticated inner-hello path;
    /// its private inner encoding is not claimed byte-identical to BoringSSL.
    /// This Android fingerprint does not enable QUIC, REALITY or early data.
    Naive150 {
        /// Whether the host provides accelerated AES-GCM instructions.
        aes_hardware: bool,
    },
    /// Naive/Chromium150 QUIC TLS: TLS1.3 only, no TLS GREASE slots,
    /// nine signatures, independent hybrid/X25519 shares, Brotli and h3 ALPS.
    /// Transport parameters remain supplied by the QUIC implementation.
    Naive150Quic {
        /// Whether the host provides accelerated AES-GCM instructions.
        aes_hardware: bool,
    },
    /// Android11 OkHttp: TLS1.0..1.2, no ALPN/key share/version extension.
    /// Requires an explicit legacy provider and disables resumption.
    Android11,
    /// Edge 85: TLS1.0..1.3, one real X25519 share, Brotli, fixed extension
    /// order and BoringSSL conditional padding. ECH and QUIC are rejected.
    Edge85,
    /// QQ 11.1: the Edge85 capabilities plus ALPS 17513 for h2.
    Qq11_1,
    /// The Android application's Safari16 fingerprint: TLS1.0..1.3, real
    /// 3DES, SHA1 handshake signatures, P521, zlib certificate decompression.
    /// No tickets, ECH, ALPS, or QUIC. This is not an Apple client target.
    Safari16,
    /// The Android application's iOS14 fingerprint: Safari16's algorithms
    /// plus six TLS1.2 SHA2-CBC suites, without certificate compression.
    Ios14,
    /// Firefox120: TLS1.2/1.3, independent X25519/P256 shares, RFC8449 record
    /// limits and RFC9345 delegated credentials. No ALPS, compression or QUIC.
    Firefox120,
    /// Android's fixed 360 7.5 template. TLS1.0..1.2 only; the exact wire
    /// advert includes seven suites and two DSA signatures with no default
    /// implementation. NPN/old ChannelID are advertisements only and a server
    /// reply is rejected. No EMS, ECH, REALITY, QUIC or resumption.
    Browser360_7_5,
    /// The bounded process-stable structure supplied through randomized_client_hello.
    /// Fresh cryptographic entropy and actual-offer checks remain per connection.
    Randomized,
}

pub(super) const CIPHERS: &[u16] = &[
    0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c,
    0x009d, 0x002f, 0x0035,
];
const NAIVE150_SOFTWARE_CIPHERS: &[u16] = &[
    0x1303, 0x1301, 0x1302, 0xcca9, 0xcca8, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc013,
    0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
];
const NAIVE150_SIGNATURES: &[u16] = &[
    0x0904, 0x0905, 0x0906, 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806,
    0x0601,
];
// BoringSSL 3a9254f16eda7a4c5d2260039ff23456a0a34de4 extensions.cc kExtensions.
// Shuffle all31 registrations, including extensions not emitted in this mode.
// Cookie retains its original slot on HRR; PSK is outside this table and last.
const NAIVE150_EXTENSION_REGISTRY: &[u16] = &[
    0, 65037, 23, 65281, 10, 11, 35, 16, 5, 13, 13172, 18, 30032, 14, 51, 45, 42,
    43, 44, 57, 65445, 27, 34, 17613, 17513, 47, 35387, 51764, 19, 20, 4832,
];
const BROWSER360_CIPHERS: &[u16] = &[
    0xc00a, 0xc014, 0x0039, 0x006b, 0x0035, 0x003d, 0xc007, 0xc009, 0xc023, 0xc011,
    0xc013, 0xc027, 0x0033, 0x0067, 0x0032, 0x0005, 0x0004, 0x002f, 0x003c, 0x000a,
];
const BROWSER360_REAL_CIPHERS: &[u16] = &[
    0xc00a, 0xc014, 0x0035, 0xc007, 0xc009, 0xc023, 0xc011, 0xc013, 0xc027, 0x0005,
    0x002f, 0x003c, 0x000a,
];
const BROWSER360_SIGNATURES: &[u16] = &[
    0x0401, 0x0501, 0x0201, 0x0403, 0x0503, 0x0203, 0x0402, 0x0202,
];
const BROWSER360_REAL_SIGNATURES: &[u16] = &[
    0x0401, 0x0501, 0x0201, 0x0403, 0x0503, 0x0203,
];
const BROWSER360_GROUPS: &[u16] = &[23, 24, 25];
const BROWSER360_EXTENSIONS: &[u16] = &[0, 65281, 10, 11, 35, 13172, 16, 30031, 5, 13];
const ANDROID_CIPHERS: &[u16] = &[
    0xc02b, 0xc02c, 0xcca9, 0xc02f, 0xc030, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
];
const ANDROID_SIGNATURES: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
];
const ANDROID_GROUPS: &[u16] = &[29, 23, 24];
const ANDROID_EXTENSIONS: &[u16] = &[0, 23, 65281, 10, 11, 5, 13];
const CLASSIC_GROUPS: &[u16] = &[29, 23, 24];
const EDGE_EXTENSIONS: &[u16] = &[0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27];
const QQ_EXTENSIONS: &[u16] = &[
    0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17513,
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
const SAFARI_SIGNATURES: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0203, 0x0805, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
];
const SAFARI_GROUPS: &[u16] = &[29, 23, 24, 25];
const SAFARI_EXTENSIONS: &[u16] = &[0, 23, 65281, 10, 11, 16, 5, 13, 18, 51, 45, 43, 27];
const IOS_EXTENSIONS: &[u16] = &[0, 23, 65281, 10, 11, 16, 5, 13, 18, 51, 45, 43];

const FIREFOX_CIPHERS: &[u16] = &[
    0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc009, 0xc013,
    0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
];
const FIREFOX_GROUPS: &[u16] = &[29, 23, 24, 25, 256, 257];
const FIREFOX_SIGNATURES: &[u16] = &[
    0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201,
];
const FIREFOX_DELEGATED_SIGNATURES: &[u16] = &[0x0403, 0x0503, 0x0603, 0x0203];
const FIREFOX_EXTENSIONS: &[u16] = &[
    0, 23, 65281, 10, 11, 35, 16, 5, 34, 51, 43, 13, 45, 28, 65037,
];

const SIGNATURES: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
];
const GROUPS: &[u16] = &[4588, 29, 23, 24];
const EXTENSIONS: &[u16] = &[
    0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17613, 65037,
];

fn invalid() -> Error {
    Error::General("Chrome133 ClientHello layout conflicts with configured TLS capabilities".into())
}
impl ClientHelloLayout {
    pub(super) fn permits_group(self, group: NamedGroup) -> bool {
        match self {
            Self::Randomized => super::randomized_hello::GROUPS,
            Self::Chrome133 | Self::Naive150 { .. } | Self::Naive150Quic { .. } => GROUPS,
            Self::Android11 => ANDROID_GROUPS,
            Self::Edge85 | Self::Qq11_1 => CLASSIC_GROUPS,
            Self::Safari16 | Self::Ios14 => SAFARI_GROUPS,
            Self::Firefox120 => FIREFOX_GROUPS,
            Self::Browser360_7_5 => BROWSER360_GROUPS,
        }
        .contains(&u16::from(group))
    }

    pub(super) fn permits_signature(self, scheme: SignatureScheme) -> bool {
        match self {
            Self::Randomized => super::randomized_hello::SIGNATURES,
            Self::Chrome133 => SIGNATURES,
            Self::Naive150 { .. } => NAIVE150_SIGNATURES,
            Self::Naive150Quic { .. } => ANDROID_SIGNATURES,
            Self::Android11 => ANDROID_SIGNATURES,
            Self::Edge85 | Self::Qq11_1 => SIGNATURES,
            Self::Safari16 | Self::Ios14 => SAFARI_SIGNATURES,
            Self::Firefox120 => FIREFOX_SIGNATURES,
            Self::Browser360_7_5 => BROWSER360_REAL_SIGNATURES,
        }
        .contains(&u16::from(scheme))
    }

    fn fixed_browser(self) -> Option<FixedBrowser> {
        let (ciphers, groups, signatures, extensions, compression, tickets) = match self {
            Self::Edge85 => (
                CIPHERS,
                CLASSIC_GROUPS,
                SIGNATURES,
                EDGE_EXTENSIONS,
                Some(2),
                true,
            ),
            Self::Qq11_1 => (
                CIPHERS,
                CLASSIC_GROUPS,
                SIGNATURES,
                QQ_EXTENSIONS,
                Some(2),
                true,
            ),
            Self::Safari16 => (
                SAFARI_CIPHERS,
                SAFARI_GROUPS,
                SAFARI_SIGNATURES,
                SAFARI_EXTENSIONS,
                Some(1),
                false,
            ),
            Self::Ios14 => (
                IOS_CIPHERS,
                SAFARI_GROUPS,
                SAFARI_SIGNATURES,
                IOS_EXTENSIONS,
                None,
                false,
            ),
            _ => return None,
        };
        Some(FixedBrowser {
            ciphers,
            groups,
            signatures,
            extensions,
            compression,
            tickets,
        })
    }
}

struct FixedBrowser {
    ciphers: &'static [u16],
    groups: &'static [u16],
    signatures: &'static [u16],
    extensions: &'static [u16],
    compression: Option<u16>,
    tickets: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct WireEncoding {
    pub(crate) grease: [u16; 5],
    pub(crate) has_grease: bool,
    pub(crate) boring_padding: bool,
    pub(crate) padding_len: Option<u16>,
    /// Object-list index selected when a TLS retry contains a cookie.
    /// It includes an omitted SNI object's slot.
    pub(crate) cookie_index: Option<usize>,
    pub(crate) extensions: Vec<ExtensionType>,
}

pub(super) struct LayoutState {
    profile: ClientHelloLayout,
    encoding: WireEncoding,
    ech: Option<EncryptedClientHello>,
    reality: bool,
    randomized: Option<alloc::sync::Arc<super::RandomizedClientHello>>,
}
impl LayoutState {
    pub(super) fn new(
        config: &ClientConfig,
        cx: &ClientContext<'_>,
    ) -> Result<Option<Self>, Error> {
        if config.randomized_client_hello.is_some() != (config.client_hello_layout == Some(ClientHelloLayout::Randomized)) {
            return Err(super::randomized_hello::invalid());
        }
        let Some(profile) = config.client_hello_layout else { return Ok(None); };
        if profile == ClientHelloLayout::Randomized {
            #[cfg(feature = "tls12")]
            {
                let plan = super::RandomizedClientHello::validate_config(config, cx)?;
                return Ok(Some(Self {
                    profile,
                    encoding: WireEncoding {
                        grease: [0; 5], has_grease: false,
                        boring_padding: plan.extensions.contains(&21), padding_len: None,
                        cookie_index: None,
                        extensions: plan.extensions.iter().copied().map(ExtensionType::from).collect(),
                    },
                    ech: None, reality: cx.data.reality.is_some(), randomized: Some(plan),
                }));
            }
            #[cfg(not(feature = "tls12"))]
            return Err(super::randomized_hello::invalid());
        }
        if let ClientHelloLayout::Naive150 { aes_hardware } | ClientHelloLayout::Naive150Quic { aes_hardware } = profile {
            #[cfg(feature = "tls12")]
            return Self::naive150(config, cx, aes_hardware, matches!(profile, ClientHelloLayout::Naive150Quic { .. })).map(Some);
            #[cfg(not(feature = "tls12"))]
            return Err(naive150_invalid());
        }
        if profile == ClientHelloLayout::Browser360_7_5 {
            #[cfg(feature = "tls12")]
            return Self::browser360(config, cx).map(Some);
            #[cfg(not(feature = "tls12"))]
            return Err(browser360_invalid());
        }
        if profile == ClientHelloLayout::Android11 {
            #[cfg(feature = "tls12")]
            return Self::android11(config, cx).map(Some);
            #[cfg(not(feature = "tls12"))]
            return Err(invalid());
        }
        if profile == ClientHelloLayout::Firefox120 {
            #[cfg(feature = "tls12")]
            return Self::firefox(config, cx).map(Some);
            #[cfg(not(feature = "tls12"))]
            return Err(invalid());
        }
        if profile.fixed_browser().is_some() {
            #[cfg(feature = "tls12")]
            return Self::fixed_browser(config, cx, profile).map(Some);
            #[cfg(not(feature = "tls12"))]
            return Err(invalid());
        }
        let signatures = config.verifier.supported_verify_schemes();
        let reality = cx.data.reality.is_some();
        let initial_groups: &[NamedGroup] = if reality {
            &[NamedGroup::X25519]
        } else {
            &[NamedGroup::X25519MLKEM768, NamedGroup::X25519]
        };
        if cx.common.is_quic()
            || matches!(config.ech_mode, Some(super::EchMode::Grease(_)))
            || !config.versions.contains(ProtocolVersion::TLSv1_3)
            || config.initial_key_share_groups != initial_groups
            || CIPHERS.iter().any(|suite| {
                !config
                    .provider
                    .cipher_suites
                    .iter()
                    .any(|s| u16::from(s.suite()) == *suite)
            })
            || SIGNATURES
                .iter()
                .any(|scheme| !signatures.contains(&SignatureScheme::from(*scheme)))
            || GROUPS.iter().any(|group| {
                if reality && *group == 4588 {
                    return false;
                }
                config
                    .find_kx_group(NamedGroup::from(*group), ProtocolVersion::TLSv1_3)
                    .is_none()
            })
            || config.cert_decompressors.len() != 1
            || u16::from(config.cert_decompressors[0].algorithm()) != 2
            || !config.application_settings.as_ref().is_some_and(|s| {
                s.codepoint == super::ApplicationSettingsCodepoint::Chrome
                    && s.settings(b"h2").is_some()
            })
            || config.alpn_protocols.is_empty()
            || config.send_ticket_request.is_some()
        {
            return Err(invalid());
        }
        let rng = config.provider.secure_random;
        let mut random = [0; 7];
        rng.fill(&mut random)?;
        let mut grease = [0; 5];
        for (value, byte) in grease.iter_mut().zip(&random) {
            let byte = u16::from((byte & 0xf0) | 0x0a);
            *value = byte | (byte << 8);
        }
        if grease[2] == grease[3] {
            grease[3] ^= 0x1010;
        }
        let mut extensions: Vec<_> = EXTENSIONS.iter().map(|v| ExtensionType::from(*v)).collect();
        // Match the pinned uTLS shuffle's fixed first/last GREASE slots: a
        // sampled swap involving slot zero is skipped. Entropy errors fail.
        for slot in (1..=extensions.len()).rev() {
            let next = choose(rng, slot + 1)?;
            if next != 0 {
                extensions.swap(slot - 1, next - 1);
            }
        }
        let ech = if config.ech_mode.is_none() {
            let group = config
                .find_kx_group(NamedGroup::X25519, ProtocolVersion::TLSv1_3)
                .ok_or_else(invalid)?;
            let encapsulated = group.start()?.pub_key().to_vec();
            let mut payload = vec![0; 144 + usize::from(random[5] & 3) * 32];
            rng.fill(&mut payload)?;
            Some(EncryptedClientHello::Outer(EncryptedClientHelloOuter {
                cipher_suite: HpkeSymmetricCipherSuite {
                    kdf_id: HpkeKdf::from(1),
                    aead_id: HpkeAead::from(1),
                },
                config_id: random[6],
                enc: PayloadU16::new(encapsulated),
                payload: PayloadU16::new(payload),
            }))
        } else {
            None
        };
        Ok(Some(Self {
            profile,
            encoding: WireEncoding {
                grease,
                extensions,
                has_grease: true,
                boring_padding: false,
                padding_len: None,
                cookie_index: None,
            },
            ech,
            reality,
            randomized: None,
        }))
    }

    #[cfg(feature = "tls12")]
    fn naive150(
        config: &ClientConfig,
        cx: &ClientContext<'_>,
        aes_hardware: bool,
        quic: bool,
    ) -> Result<Self, Error> {
        let real_ech = matches!(config.ech_mode, Some(super::EchMode::Enable(_)));
        let signatures = config.verifier.supported_verify_schemes();
        let ciphers = if quic { &CIPHERS[..3] } else { CIPHERS };
        let signature_ids = if quic { ANDROID_SIGNATURES } else { NAIVE150_SIGNATURES };
        let alps = if quic { b"h3" } else { b"h2" };
        if cx.common.is_quic() != quic || cx.data.reality.is_some()
            || config.legacy_enabled()
            || matches!(config.ech_mode, Some(super::EchMode::Grease(_)))
            || !config.supports_version(ProtocolVersion::TLSv1_3, cx.common.protocol)
            || (!quic && !real_ech && !config.supports_version(ProtocolVersion::TLSv1_2, cx.common.protocol))
            || (quic && (config.versions.contains(ProtocolVersion::TLSv1_2)
                || config.alpn_protocols != [b"h3".to_vec()]))
            || config.initial_key_share_groups != [NamedGroup::X25519MLKEM768, NamedGroup::X25519]
            || ciphers.iter().any(|id| !config.provider.cipher_suites.iter().any(|s| u16::from(s.suite()) == *id))
            || signature_ids.iter().any(|id| !signatures.contains(&SignatureScheme::from(*id)))
            || GROUPS.iter().any(|id| config.find_kx_group(NamedGroup::from(*id), ProtocolVersion::TLSv1_3).is_none())
            || config.cert_decompressors.len() != 1
            || u16::from(config.cert_decompressors[0].algorithm()) != 2
            || !config.application_settings.as_ref().is_some_and(|s| {
                s.codepoint == super::ApplicationSettingsCodepoint::Chrome
                    && s.settings(alps).is_some_and(|settings| settings.is_empty())
            })
            || config.alpn_protocols.is_empty()
            || config.send_ticket_request.is_some()
            || config.enable_early_data || config.enable_delegated_credentials
            || config.advertise_record_size_limit
            || config.verifier.requires_raw_public_keys()
            || config.client_auth_cert_resolver.only_raw_public_keys()
        {
            return Err(naive150_invalid());
        }
        let rng = config.provider.secure_random;
        let mut seed = [0u8; 7];
        rng.fill(&mut seed)?;
        let mut grease = [0u16; 5];
        for (value, byte) in grease.iter_mut().zip(seed) {
            let byte = u16::from((byte & 0xf0) | 0x0a);
            *value = byte | (byte << 8);
        }
        if grease[2] == grease[3] { grease[3] ^= 0x1010; }
        // Fixed Android ABIs and the independent linux_amd64 reference are LE.
        // BoringSSL draws30 native uint32 values and uses modulo (not rejection).
        let mut entropy = [0u8; 30 * 4];
        rng.fill(&mut entropy)?;
        let mut extensions: Vec<_> = NAIVE150_EXTENSION_REGISTRY.iter()
            .copied().map(ExtensionType::from).collect();
        for slot in (1..extensions.len()).rev() {
            let start = (slot - 1) * 4;
            let value = u32::from_le_bytes(entropy[start..start + 4].try_into().unwrap());
            extensions.swap(slot, (value % (slot as u32 + 1)) as usize);
        }
        let ech = if real_ech {
            None
        } else {
            let group = config.find_kx_group(NamedGroup::X25519, ProtocolVersion::TLSv1_3)
                .ok_or_else(naive150_invalid)?;
            let encapsulated = group.start()?.pub_key().to_vec();
            if encapsulated.len() != 32 { return Err(naive150_invalid()); }
            let mut size_seed = [0u8; size_of::<usize>()];
            rng.fill(&mut size_seed)?;
            let mut payload = vec![0; 144 + (usize::from_ne_bytes(size_seed) % 4) * 32];
            rng.fill(&mut payload)?;
            Some(EncryptedClientHello::Outer(EncryptedClientHelloOuter {
                cipher_suite: HpkeSymmetricCipherSuite {
                    kdf_id: HpkeKdf::from(1),
                    aead_id: HpkeAead::from(if aes_hardware { 1 } else { 3 }),
                },
                config_id: seed[6],
                enc: PayloadU16::new(encapsulated),
                payload: PayloadU16::new(payload),
            }))
        };
        Ok(Self {
            profile: if quic { ClientHelloLayout::Naive150Quic { aes_hardware } }
                else { ClientHelloLayout::Naive150 { aes_hardware } },
            encoding: WireEncoding {
                grease, has_grease: !quic, boring_padding: !quic,
                padding_len: None, cookie_index: None, extensions,
            },
            ech, reality: false, randomized: None,
        })
    }

    fn apply_naive150(
        &self,
        hello: &mut ClientHelloPayload,
        changed_group: bool,
        aes_hardware: bool,
    ) -> Result<(), Error> {
        let ciphers = if aes_hardware { CIPHERS } else { NAIVE150_SOFTWARE_CIPHERS };
        hello.cipher_suites = core::iter::once(CipherSuite::from(self.encoding.grease[0]))
            .chain(ciphers.iter().copied().map(CipherSuite::from)).collect();
        hello.named_groups = Some(core::iter::once(NamedGroup::from(self.encoding.grease[1]))
            .chain(GROUPS.iter().copied().map(NamedGroup::from)).collect());
        hello.signature_schemes = Some(NAIVE150_SIGNATURES.iter().copied().map(SignatureScheme::from).collect());
        hello.renegotiation_info = Some(PayloadU8::new(vec![]));
        hello.sct_request = Some(());
        if hello.session_ticket.is_none() { hello.session_ticket = Some(ClientSessionTicket::Request); }
        if !hello.application_settings.as_ref().is_some_and(|names| names.len() == 1 && names[0].as_ref() == b"h2") {
            return Err(naive150_invalid());
        }
        let shares = hello.key_shares.as_mut().ok_or_else(naive150_invalid)?;
        if changed_group {
            if shares.len() != 1 || !self.profile.permits_group(shares[0].group) {
                return Err(naive150_invalid());
            }
        } else {
            if !shares.iter().map(|s| s.group).eq([NamedGroup::X25519MLKEM768, NamedGroup::X25519]) {
                return Err(naive150_invalid());
            }
            // Cookie-only HRR reuses all original shares, including GREASE.
            shares.insert(0, KeyShareEntry::new(NamedGroup::from(self.encoding.grease[1]), &[0]));
        }
        let versions = hello.supported_versions.as_mut().ok_or_else(naive150_invalid)?;
        versions.tls13 = true;
        versions.tls12 = true;
        versions.tls11 = false;
        versions.tls10 = false;
        if let Some(ech) = &self.ech { hello.encrypted_client_hello = Some(ech.clone()); }
        if hello.collect_used().iter().any(|typ| {
            !EXTENSIONS.contains(&u16::from(*typ))
                && !matches!(typ, ExtensionType::Cookie | ExtensionType::PreSharedKey)
        }) {
            return Err(naive150_invalid());
        }
        let mut encoding = self.encoding.clone();
        // BoringSSL applies F5 padding only before HRR. A legal HRR changes
        // the group or supplies a cookie; cookie-only retries keep key shares.
        encoding.boring_padding = !changed_group && hello.cookie.is_none();
        hello.wire_encoding = Some(encoding);
        hello.update_boring_padding()
    }

    fn apply_naive150_quic(
        &self,
        hello: &mut ClientHelloPayload,
        changed_group: bool,
        aes_hardware: bool,
    ) -> Result<(), Error> {
        let ciphers = if aes_hardware { &CIPHERS[..3] } else { &NAIVE150_SOFTWARE_CIPHERS[..3] };
        hello.cipher_suites = ciphers.iter().copied().map(CipherSuite::from).collect();
        hello.named_groups = Some(GROUPS.iter().copied().map(NamedGroup::from).collect());
        hello.signature_schemes = Some(ANDROID_SIGNATURES.iter().copied().map(SignatureScheme::from).collect());
        hello.renegotiation_info = None;
        hello.extended_master_secret_request = None;
        hello.ec_point_formats = None;
        hello.session_ticket = None;
        hello.sct_request = None;
        hello.certificate_status_request = None;
        if !hello.session_id.as_ref().is_empty()
            || !hello.application_settings.as_ref().is_some_and(|names| names.len() == 1 && names[0].as_ref() == b"h3") {
            return Err(naive150_invalid());
        }
        let shares = hello.key_shares.as_ref().ok_or_else(naive150_invalid)?;
        if changed_group {
            if shares.len() != 1 || !self.profile.permits_group(shares[0].group) {
                return Err(naive150_invalid());
            }
        } else if !shares.iter().map(|s| s.group).eq([NamedGroup::X25519MLKEM768, NamedGroup::X25519]) {
            return Err(naive150_invalid());
        }
        let versions = hello.supported_versions.as_mut().ok_or_else(naive150_invalid)?;
        versions.tls13 = true;
        versions.tls12 = false;
        versions.tls11 = false;
        versions.tls10 = false;
        if let Some(ech) = &self.ech { hello.encrypted_client_hello = Some(ech.clone()); }
        if hello.collect_used().iter().any(|typ| {
            ![0, 10, 13, 16, 27, 43, 45, 51, 57, 17613, 65037].contains(&u16::from(*typ))
                && !matches!(typ, ExtensionType::Cookie | ExtensionType::PreSharedKey)
        }) {
            return Err(naive150_invalid());
        }
        hello.wire_encoding = Some(self.encoding.clone());
        Ok(())
    }

    #[cfg(feature = "tls12")]
    fn browser360(config: &ClientConfig, cx: &ClientContext<'_>) -> Result<Self, Error> {
        if !config.legacy_enabled()
            || ![ProtocolVersion::TLSv1_0, ProtocolVersion::TLSv1_1, ProtocolVersion::TLSv1_2]
                .iter().all(|v| config.supports_version(*v, cx.common.protocol))
            || config.versions.contains(ProtocolVersion::TLSv1_3)
            || cx.common.is_quic() || cx.data.reality.is_some() || config.ech_mode.is_some()
            || config.require_ems || !config.enable_tls12_renegotiation
            || config.alpn_protocols.is_empty() || config.application_settings.is_some()
            || !config.initial_key_share_groups.is_empty() || !config.cert_decompressors.is_empty()
            || config.send_ticket_request.is_some() || config.enable_early_data
            || config.enable_delegated_credentials || config.advertise_record_size_limit
            || !config.provider.cipher_suites.iter().map(|s| u16::from(s.suite()))
                .eq(BROWSER360_REAL_CIPHERS.iter().copied())
            || !config.verifier.supported_verify_schemes().iter().map(|s| u16::from(*s))
                .eq(BROWSER360_REAL_SIGNATURES.iter().copied())
            || !config.provider.kx_groups.iter().map(|g| u16::from(g.name()))
                .eq(BROWSER360_GROUPS.iter().copied())
            || BROWSER360_GROUPS.iter().any(|id|
                config.find_kx_group(NamedGroup::from(*id), ProtocolVersion::TLSv1_2).is_none())
        {
            return Err(browser360_invalid());
        }
        Ok(Self {
            profile: ClientHelloLayout::Browser360_7_5,
            encoding: WireEncoding {
                grease: [0; 5], has_grease: false, boring_padding: false,
                padding_len: None, cookie_index: None,
                extensions: BROWSER360_EXTENSIONS.iter().map(|v| ExtensionType::from(*v)).collect(),
            },
            ech: None, reality: false, randomized: None,
        })
    }

    fn apply_browser360(&self, hello: &mut ClientHelloPayload, changed_group: bool) -> Result<(), Error> {
        if changed_group || hello.supported_versions.is_some() || hello.key_shares.is_some() {
            return Err(browser360_invalid());
        }
        hello.cipher_suites = BROWSER360_CIPHERS.iter().map(|v| CipherSuite::from(*v)).collect();
        hello.named_groups = Some(BROWSER360_GROUPS.iter().map(|v| NamedGroup::from(*v)).collect());
        hello.signature_schemes = Some(BROWSER360_SIGNATURES.iter().map(|v| SignatureScheme::from(*v)).collect());
        // This changes the actual offer before transcript hashing and sent-extension
        // tracking. A server EMS response is consequently unsolicited and rejected.
        hello.extended_master_secret_request = None;
        hello.renegotiation_info = Some(PayloadU8::new(vec![]));
        hello.session_ticket = Some(ClientSessionTicket::Request);
        hello.npn_advertisement = Some(());
        hello.channel_id_advertisement = Some(());
        if hello.collect_used().iter().any(|typ| !self.encoding.extensions.contains(typ)) {
            return Err(browser360_invalid());
        }
        hello.wire_encoding = Some(self.encoding.clone());
        Ok(())
    }

    #[cfg(feature = "tls12")]
    fn android11(config: &ClientConfig, cx: &ClientContext<'_>) -> Result<Self, Error> {
        let signatures = config.verifier.supported_verify_schemes();
        if !config.legacy_enabled()
            || ![
                ProtocolVersion::TLSv1_0,
                ProtocolVersion::TLSv1_1,
                ProtocolVersion::TLSv1_2,
            ]
            .iter()
            .all(|v| config.supports_version(*v, cx.common.protocol))
            || config.versions.contains(ProtocolVersion::TLSv1_3)
            || cx.common.is_quic()
            || cx.data.reality.is_some()
            || config.ech_mode.is_some()
            || config.enable_tls12_renegotiation
            || !config.alpn_protocols.is_empty()
            || config.application_settings.is_some()
            || !config.initial_key_share_groups.is_empty()
            || !config.cert_decompressors.is_empty()
            || config.send_ticket_request.is_some()
            || ANDROID_CIPHERS.iter().any(|id| {
                !config
                    .provider
                    .cipher_suites
                    .iter()
                    .any(|s| u16::from(s.suite()) == *id)
            })
            || ANDROID_SIGNATURES
                .iter()
                .any(|id| !signatures.contains(&SignatureScheme::from(*id)))
            || ANDROID_GROUPS.iter().any(|id| {
                config
                    .find_kx_group(NamedGroup::from(*id), ProtocolVersion::TLSv1_2)
                    .is_none()
            })
        {
            return Err(Error::General(
                "Android11 ClientHello layout conflicts with configured TLS capabilities".into(),
            ));
        }
        Ok(Self {
            profile: ClientHelloLayout::Android11,
            encoding: WireEncoding {
                grease: [0; 5],
                has_grease: false,
                boring_padding: false,
                padding_len: None,
                cookie_index: None,
                extensions: ANDROID_EXTENSIONS
                    .iter()
                    .map(|v| ExtensionType::from(*v))
                    .collect(),
            },
            ech: None,
            reality: false,
            randomized: None,
        })
    }

    pub(super) fn apply(
        &self,
        hello: &mut ClientHelloPayload,
        changed_group: bool,
    ) -> Result<(), Error> {
        if let Some(plan) = &self.randomized { return plan.apply(hello, changed_group, &self.encoding); }
        if let ClientHelloLayout::Naive150 { aes_hardware } = self.profile {
            return self.apply_naive150(hello, changed_group, aes_hardware);
        }
        if let ClientHelloLayout::Naive150Quic { aes_hardware } = self.profile {
            return self.apply_naive150_quic(hello, changed_group, aes_hardware);
        }

        if self.profile == ClientHelloLayout::Browser360_7_5 {
            return self.apply_browser360(hello, changed_group);
        }
        if self.profile == ClientHelloLayout::Firefox120 {
            return self.apply_firefox(hello, changed_group);
        }
        if let Some(template) = self.profile.fixed_browser() {
            return self.apply_fixed_browser(hello, changed_group, &template);
        }
        if self.profile == ClientHelloLayout::Android11 {
            hello.cipher_suites = ANDROID_CIPHERS
                .iter()
                .map(|v| CipherSuite::from(*v))
                .collect();
            hello.named_groups = Some(
                ANDROID_GROUPS
                    .iter()
                    .map(|v| NamedGroup::from(*v))
                    .collect(),
            );
            hello.signature_schemes = Some(
                ANDROID_SIGNATURES
                    .iter()
                    .map(|v| SignatureScheme::from(*v))
                    .collect(),
            );
            hello.renegotiation_info = Some(PayloadU8::new(vec![]));
            if hello
                .collect_used()
                .iter()
                .any(|t| !self.encoding.extensions.contains(t))
            {
                return Err(Error::General(
                    "Android11 cannot silently discard non-template TLS extensions".into(),
                ));
            }
            hello.wire_encoding = Some(self.encoding.clone());
            return Ok(());
        }
        hello.cipher_suites = core::iter::once(CipherSuite::from(self.encoding.grease[0]))
            .chain(CIPHERS.iter().map(|v| CipherSuite::from(*v)))
            .collect();
        hello.named_groups = Some(
            core::iter::once(NamedGroup::from(self.encoding.grease[1]))
                .chain(
                    GROUPS
                        .iter()
                        .filter(|group| !self.reality || **group != 4588)
                        .map(|v| NamedGroup::from(*v)),
                )
                .collect(),
        );
        hello.signature_schemes = Some(
            SIGNATURES
                .iter()
                .map(|v| SignatureScheme::from(*v))
                .collect(),
        );
        hello.renegotiation_info = Some(PayloadU8::new(vec![]));
        hello.sct_request = Some(());
        if !hello
            .application_settings
            .as_ref()
            .is_some_and(|names| names.len() == 1 && names[0].as_ref() == b"h2")
        {
            return Err(invalid());
        }
        // Chrome requests TLS 1.2 tickets even without a client-side cache.
        if hello.session_ticket.is_none() {
            hello.session_ticket = Some(ClientSessionTicket::Request);
        }
        if !changed_group {
            hello.key_shares.as_mut().ok_or_else(invalid)?.insert(
                0,
                KeyShareEntry::new(NamedGroup::from(self.encoding.grease[1]), &[0]),
            );
        }
        // The cover hello retains the pinned TLS 1.2/1.3 offer. ECH's inner
        // hello and the actual version policy remain TLS 1.3 only.
        if let Some(versions) = &mut hello.supported_versions {
            versions.tls12 = true;
        }
        if let Some(ech) = &self.ech {
            hello.encrypted_client_hello = Some(ech.clone());
        }
        // Never discard a caller's non-template extension silently.
        if hello.collect_used().iter().any(|typ| {
            !self.encoding.extensions.contains(typ)
                && !matches!(
                    typ,
                    ExtensionType::Cookie | ExtensionType::PreSharedKey | ExtensionType::EarlyData
                )
        }) {
            return Err(invalid());
        }
        hello.wire_encoding = Some(self.encoding.clone());
        Ok(())
    }

    #[cfg(feature = "tls12")]
    fn firefox(config: &ClientConfig, cx: &ClientContext<'_>) -> Result<Self, Error> {
        let reality = cx.data.reality.is_some();
        let signatures = config.verifier.supported_verify_schemes();
        let delegated: Vec<_> = config
            .verifier
            .supported_delegated_verify_schemes()
            .iter()
            .copied()
            .map(u16::from)
            .collect();
        if config.legacy_enabled()
            || !config.supports_version(ProtocolVersion::TLSv1_3, cx.common.protocol)
            || config.enable_tls12_renegotiation
                != config.supports_version(ProtocolVersion::TLSv1_2, cx.common.protocol)
            || cx.common.is_quic()
            || config.ech_mode.is_some()
            || config.application_settings.is_some()
            || !config.cert_decompressors.is_empty()
            || !config.cert_compressors.is_empty()
            || config.alpn_protocols.is_empty()
            || config.send_ticket_request.is_some()
            || config.enable_early_data
            || config.enable_secret_extraction
            || config.initial_key_share_groups != [NamedGroup::X25519, NamedGroup::secp256r1]
            || !config.advertise_record_size_limit
            || !config.enable_delegated_credentials
            || delegated != FIREFOX_DELEGATED_SIGNATURES
            || FIREFOX_CIPHERS.iter().any(|id| {
                !config
                    .provider
                    .cipher_suites
                    .iter()
                    .any(|suite| u16::from(suite.suite()) == *id)
            })
            || FIREFOX_SIGNATURES
                .iter()
                .any(|id| !signatures.contains(&SignatureScheme::from(*id)))
            || FIREFOX_GROUPS.iter().any(|id| {
                config
                    .find_kx_group(NamedGroup::from(*id), ProtocolVersion::TLSv1_3)
                    .is_none()
            })
        {
            return Err(firefox_invalid());
        }
        let rng = config.provider.secure_random;
        let mut random = [0u8; 2];
        rng.fill(&mut random)?;
        let encapsulated = config
            .find_kx_group(NamedGroup::X25519, ProtocolVersion::TLSv1_3)
            .ok_or_else(firefox_invalid)?
            .start()?
            .pub_key()
            .to_vec();
        let mut payload = vec![0; 239];
        rng.fill(&mut payload)?;
        let ech = EncryptedClientHello::Outer(EncryptedClientHelloOuter {
            cipher_suite: HpkeSymmetricCipherSuite {
                kdf_id: HpkeKdf::from(1),
                aead_id: HpkeAead::from(if random[0] & 1 == 0 { 1 } else { 3 }),
            },
            config_id: random[1],
            enc: PayloadU16::new(encapsulated),
            payload: PayloadU16::new(payload),
        });
        Ok(Self {
            profile: ClientHelloLayout::Firefox120,
            encoding: WireEncoding {
                grease: [0; 5],
                has_grease: false,
                boring_padding: false,
                padding_len: None,
                cookie_index: None,
                extensions: FIREFOX_EXTENSIONS
                    .iter()
                    .map(|id| ExtensionType::from(*id))
                    .collect(),
            },
            ech: Some(ech),
            reality,
            randomized: None,
        })
    }

    fn apply_firefox(
        &self,
        hello: &mut ClientHelloPayload,
        changed_group: bool,
    ) -> Result<(), Error> {
        if hello.record_size_limit != Some(16385)
            || hello
                .delegated_credential_schemes
                .as_ref()
                .map(|schemes| schemes.iter().copied().map(u16::from).collect::<Vec<_>>())
                .as_deref()
                != Some(FIREFOX_DELEGATED_SIGNATURES)
            || (!changed_group
                && hello
                    .key_shares
                    .as_ref()
                    .map(|shares| shares.iter().map(|s| s.group).collect::<Vec<_>>())
                    .as_deref()
                    != Some(&[NamedGroup::X25519, NamedGroup::secp256r1]))
        {
            return Err(firefox_invalid());
        }
        hello.cipher_suites = FIREFOX_CIPHERS
            .iter()
            .map(|id| CipherSuite::from(*id))
            .collect();
        hello.named_groups = Some(
            FIREFOX_GROUPS
                .iter()
                .map(|id| NamedGroup::from(*id))
                .collect(),
        );
        hello.signature_schemes = Some(
            FIREFOX_SIGNATURES
                .iter()
                .map(|id| SignatureScheme::from(*id))
                .collect(),
        );
        hello.renegotiation_info = Some(PayloadU8::new(vec![]));
        hello.session_ticket = Some(ClientSessionTicket::Request);
        let versions = hello
            .supported_versions
            .as_mut()
            .ok_or_else(firefox_invalid)?;
        versions.tls13 = true;
        versions.tls12 = true;
        versions.tls11 = false;
        versions.tls10 = false;
        hello.encrypted_client_hello = Some(self.ech.as_ref().ok_or_else(firefox_invalid)?.clone());
        if hello
            .collect_used()
            .iter()
            .any(|typ| !self.encoding.extensions.contains(typ) && *typ != ExtensionType::Cookie)
        {
            return Err(firefox_invalid());
        }
        hello.wire_encoding = Some(self.encoding.clone());
        Ok(())
    }

    #[cfg(feature = "tls12")]
    fn fixed_browser(
        config: &ClientConfig,
        cx: &ClientContext<'_>,
        profile: ClientHelloLayout,
    ) -> Result<Self, Error> {
        let template = profile.fixed_browser().ok_or_else(invalid)?;
        let reality = cx.data.reality.is_some();
        let signatures = config.verifier.supported_verify_schemes();
        let versions = [
            ProtocolVersion::TLSv1_0,
            ProtocolVersion::TLSv1_1,
            ProtocolVersion::TLSv1_2,
            ProtocolVersion::TLSv1_3,
        ];
        let modern_only = !config.legacy_enabled()
            && config.supports_version(ProtocolVersion::TLSv1_3, cx.common.protocol)
            && !config.supports_version(ProtocolVersion::TLSv1_2, cx.common.protocol)
            && !config.enable_tls12_renegotiation;
        let version_policy = if reality || modern_only {
            !config.legacy_enabled()
                && config.supports_version(ProtocolVersion::TLSv1_3, cx.common.protocol)
        } else {
            config.legacy_enabled()
                && versions
                    .iter()
                    .all(|v| config.supports_version(*v, cx.common.protocol))
                && config.enable_tls12_renegotiation
        };
        let settings = match profile {
            ClientHelloLayout::Edge85 | ClientHelloLayout::Safari16 | ClientHelloLayout::Ios14 => {
                config.application_settings.is_none()
            }
            ClientHelloLayout::Qq11_1 => config.application_settings.as_ref().is_some_and(|s| {
                s.codepoint == super::ApplicationSettingsCodepoint::Legacy
                    && s.settings(b"h2").is_some()
            }),
            _ => false,
        };
        let compression = match template.compression {
            Some(algorithm) => {
                config.cert_decompressors.len() == 1
                    && u16::from(config.cert_decompressors[0].algorithm()) == algorithm
            }
            None => config.cert_decompressors.is_empty(),
        };
        if !version_policy
            || !settings
            || cx.common.is_quic()
            || config.ech_mode.is_some()
            || config.initial_key_share_groups != [NamedGroup::X25519]
            || !compression
            || config.alpn_protocols.is_empty()
            || config.send_ticket_request.is_some()
            || config.enable_early_data
            || template.ciphers.iter().any(|id| {
                !config
                    .provider
                    .cipher_suites
                    .iter()
                    .any(|s| u16::from(s.suite()) == *id)
            })
            || template
                .signatures
                .iter()
                .any(|id| !signatures.contains(&SignatureScheme::from(*id)))
            || template.groups.iter().any(|id| {
                config
                    .find_kx_group(NamedGroup::from(*id), ProtocolVersion::TLSv1_3)
                    .is_none()
            })
        {
            return Err(Error::General(
                "fixed browser ClientHello layout conflicts with configured TLS capabilities"
                    .into(),
            ));
        }
        let mut bytes = [0; 5];
        config.provider.secure_random.fill(&mut bytes)?;
        let mut grease = [0; 5];
        for (value, byte) in grease.iter_mut().zip(bytes) {
            let byte = u16::from((byte & 0xf0) | 0x0a);
            *value = byte | (byte << 8);
        }
        if grease[2] == grease[3] {
            grease[3] ^= 0x1010;
        }
        Ok(Self {
            profile,
            encoding: WireEncoding {
                grease,
                has_grease: true,
                boring_padding: true,
                padding_len: None,
                cookie_index: None,
                extensions: template
                    .extensions
                    .iter()
                    .map(|v| ExtensionType::from(*v))
                    .collect(),
            },
            ech: None,
            reality,
            randomized: None,
        })
    }

    fn apply_fixed_browser(
        &self,
        hello: &mut ClientHelloPayload,
        changed_group: bool,
        template: &FixedBrowser,
    ) -> Result<(), Error> {
        hello.cipher_suites = core::iter::once(CipherSuite::from(self.encoding.grease[0]))
            .chain(template.ciphers.iter().map(|v| CipherSuite::from(*v)))
            .collect();
        hello.named_groups = Some(
            core::iter::once(NamedGroup::from(self.encoding.grease[1]))
                .chain(template.groups.iter().map(|v| NamedGroup::from(*v)))
                .collect(),
        );
        hello.signature_schemes = Some(
            template
                .signatures
                .iter()
                .map(|v| SignatureScheme::from(*v))
                .collect(),
        );
        hello.renegotiation_info = Some(PayloadU8::new(vec![]));
        hello.sct_request = Some(());
        if template.tickets {
            hello.session_ticket = Some(ClientSessionTicket::Request);
        }
        if self.profile == ClientHelloLayout::Qq11_1
            && !hello
                .application_settings_legacy
                .as_ref()
                .is_some_and(|names| names.len() == 1 && names[0].as_ref() == b"h2")
        {
            return Err(Error::General(
                "QQ11.1 requires exactly the h2 ALPS offer".into(),
            ));
        }
        if !changed_group {
            hello.key_shares.as_mut().ok_or_else(invalid)?.insert(
                0,
                KeyShareEntry::new(NamedGroup::from(self.encoding.grease[1]), &[0]),
            );
        }
        let versions = hello.supported_versions.as_mut().ok_or_else(invalid)?;
        versions.tls13 = true;
        versions.tls12 = true;
        versions.tls11 = true;
        versions.tls10 = true;
        if hello
            .collect_used()
            .iter()
            .any(|typ| !self.encoding.extensions.contains(typ) && *typ != ExtensionType::Cookie)
        {
            return Err(Error::General(
                "fixed browser layout cannot silently discard non-template TLS extensions".into(),
            ));
        }
        hello.wire_encoding = Some(self.encoding.clone());
        hello.update_boring_padding()
    }

    /// The pinned uTLS inserts a new Cookie object at a random index below
    /// `len(Extensions)-2`. Keep omitted objects (such as IP SNI) in that count.
    pub(super) fn apply_retry_cookie(
        &self,
        hello: &mut ClientHelloPayload,
        rng: &dyn SecureRandom,
    ) -> Result<(), Error> {
        if (self.profile.fixed_browser().is_none()
            && !matches!(self.profile, ClientHelloLayout::Firefox120 | ClientHelloLayout::Randomized))
            || hello.cookie.is_none()
        {
            return Ok(());
        }
        let upper = if matches!(self.profile, ClientHelloLayout::Firefox120 | ClientHelloLayout::Randomized) {
            // Firefox has exactly the template objects, including omitted SNI.
            self.encoding.extensions.len() - 2
        } else {
            // First GREASE + template + last GREASE + padding, minus final 2.
            self.encoding.extensions.len() + 1
        };
        let index = choose(rng, upper)?;
        hello
            .wire_encoding
            .as_mut()
            .ok_or_else(invalid)?
            .cookie_index = Some(index);
        hello.update_boring_padding()
    }
}
fn naive150_invalid() -> Error {
    Error::General("Naive150 ClientHello layout conflicts with configured TLS capabilities".into())
}

fn browser360_invalid() -> Error {
    Error::General("360 7.5 ClientHello layout conflicts with configured TLS capabilities".into())
}
fn firefox_invalid() -> Error {
    Error::General(
        "Firefox120 ClientHello layout conflicts with configured TLS capabilities".into(),
    )
}

fn choose(rng: &dyn SecureRandom, upper: usize) -> Result<usize, Error> {
    let limit = 256 - (256 % upper);
    loop {
        let mut byte = [0];
        rng.fill(&mut byte)?;
        let value = usize::from(byte[0]);
        if value < limit {
            return Ok(value % upper);
        }
    }
}
