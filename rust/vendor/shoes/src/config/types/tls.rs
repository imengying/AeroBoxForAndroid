use serde::{Deserialize, Serialize};

/// Additional TLS policy shared by stream TLS and native QUIC clients.
/// Empty trust roots use the bundled Mozilla roots. A nonempty list replaces
/// that store; each entry is an inline PEM bundle or a named/file PEM reference.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TlsClientOptions {
    /// Explicit browser wire policy. `random` is resolved once per process at
    /// deserialization; serialization records the selected fixed profile.
    /// `randomized` keeps its token and uses a separate process-fixed structural
    /// plan when compiling or constructing a connection; it never resamples.
    /// Default TLS has no browser fingerprint.
    #[serde(
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_fingerprint"
    )]
    pub fingerprint: Option<TlsClientFingerprint>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub root_certificates: Vec<String>,
    /// Base64 SHA-256 hashes of the leaf certificate's DER SubjectPublicKeyInfo.
    /// Pins add a restriction to `verify`; with `verify: false`, pins still apply.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub certificate_public_key_sha256: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_version: Option<TlsVersion>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_version: Option<TlsVersion>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cipher_suites: Vec<String>,
    /// Suppress only the ClientHello SNI extension. Certificate verification
    /// still uses sni_hostname (or the destination hostname/IP when omitted).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub disable_sni: bool,
    /// Encrypt ClientHello using an inline ECH CONFIGS PEM or HTTPS DNS records.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ech: Option<crate::ech::EchOptions>,
}

impl TlsClientOptions {
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum TlsClientFingerprint {
    #[serde(rename = "chrome133")]
    Chrome133,
    #[serde(rename = "android11")]
    Android11,
    #[serde(rename = "edge85")]
    Edge85,
    #[serde(rename = "qq11_1")]
    Qq11_1,
    /// Android's Safari16 TLS fingerprint, not an Apple platform target.
    #[serde(rename = "safari16")]
    Safari16,
    /// Android's iOS14 TLS fingerprint, not an Apple platform target.
    #[serde(rename = "ios14")]
    Ios14,
    #[serde(rename = "firefox120")]
    Firefox120,
    /// Android's pinned legacy 360 7.5 template; TLS1.0..1.2, no REALITY.
    #[serde(rename = "360_7_5")]
    Browser360_7_5,
    /// One process-fixed randomized structure from the original Android weights.
    /// Invalid generated structures fail without filtering or choosing again.
    #[serde(rename = "randomized")]
    Randomized,
}

impl From<aerobox_fingerprint::Profile> for TlsClientFingerprint {
    fn from(profile: aerobox_fingerprint::Profile) -> Self {
        match profile {
            aerobox_fingerprint::Profile::Chrome133 => Self::Chrome133,
            aerobox_fingerprint::Profile::Firefox120 => Self::Firefox120,
            aerobox_fingerprint::Profile::Edge85 => Self::Edge85,
            aerobox_fingerprint::Profile::Safari16 => Self::Safari16,
            aerobox_fingerprint::Profile::Ios14 => Self::Ios14,
        }
    }
}

/// Resolve only the explicit `random` token. The public fixed-profile enum and
/// its existing serde names remain unchanged; no unresolved Random can reach
/// provider or policy code. This may run before a later field is rejected, so
/// all parsing and configuration failures must retain the process selection.
pub(super) fn deserialize_fingerprint<'de, D>(
    deserializer: D,
) -> Result<Option<TlsClientFingerprint>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_fingerprint_with(deserializer, aerobox_fingerprint::random_profile)
}

fn deserialize_fingerprint_with<'de, D>(
    deserializer: D,
    random: impl FnOnce() -> Result<aerobox_fingerprint::Profile, aerobox_fingerprint::InitError>,
) -> Result<Option<TlsClientFingerprint>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{Error, value::StringDeserializer};
    Option::<String>::deserialize(deserializer)?
        .map(|name| {
            if name == "random" {
                random().map(Into::into).map_err(D::Error::custom)
            } else {
                TlsClientFingerprint::deserialize(StringDeserializer::<D::Error>::new(name))
            }
        })
        .transpose()
}

#[cfg(test)]
mod fingerprint_tests;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub enum TlsVersion {
    #[serde(rename = "1.0")]
    V10,
    #[serde(rename = "1.1")]
    V11,
    #[serde(rename = "1.2")]
    V12,
    #[serde(rename = "1.3")]
    V13,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum TlsKeyExchangeGroup {
    X25519MLKEM768,
    SecP256r1MLKEM768,
    X25519,
    SecP256r1,
    SecP384r1,
    SecP521r1,
    FFDHE2048,
    FFDHE3072,
}

impl TlsKeyExchangeGroup {
    pub fn is_hybrid(self) -> bool {
        matches!(self, Self::X25519MLKEM768 | Self::SecP256r1MLKEM768)
    }

    pub fn rustls_group(self) -> &'static dyn rustls::crypto::SupportedKxGroup {
        use crate::crypto::rustcrypto_kx::group;
        use rustls::NamedGroup;
        match self {
            Self::X25519MLKEM768 => group(NamedGroup::X25519MLKEM768),
            Self::SecP256r1MLKEM768 => group(NamedGroup::secp256r1MLKEM768),
            Self::X25519 => group(NamedGroup::X25519),
            Self::SecP256r1 => group(NamedGroup::secp256r1),
            Self::SecP384r1 => group(NamedGroup::secp384r1),
            Self::SecP521r1 => group(NamedGroup::secp521r1),
            Self::FFDHE2048 => &aerobox_crypto::ffdhe::FFDHE2048,
            Self::FFDHE3072 => &aerobox_crypto::ffdhe::FFDHE3072,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct TlsKeyExchangeGroups(Option<Vec<TlsKeyExchangeGroup>>);

impl<'de> Deserialize<'de> for TlsKeyExchangeGroups {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let groups = Vec::<TlsKeyExchangeGroup>::deserialize(deserializer)?;
        if groups.is_empty() {
            return Err(serde::de::Error::custom(
                "key_exchange_groups must not be empty",
            ));
        }
        for (index, group) in groups.iter().enumerate() {
            if groups[..index].contains(group) {
                return Err(serde::de::Error::custom(
                    "duplicate key_exchange_groups entry",
                ));
            }
        }
        Ok(Self(Some(groups)))
    }
}

impl TlsKeyExchangeGroups {
    pub fn is_default(&self) -> bool {
        self.0.is_none()
    }

    pub fn groups(&self) -> Option<&[TlsKeyExchangeGroup]> {
        self.0.as_deref()
    }

    pub fn requires_hybrid(&self) -> bool {
        self.groups()
            .is_some_and(|groups| groups.iter().all(|g| g.is_hybrid()))
    }

    pub fn validate_vision(&self, vision: bool) -> std::io::Result<()> {
        if vision && self.requires_hybrid() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "hybrid-only key_exchange_groups cannot be combined with Vision: direct copy bypasses TLS encryption",
            ));
        }
        Ok(())
    }

    pub fn validate_zero_rtt(&self, zero_rtt_handshake: bool) -> std::io::Result<()> {
        if zero_rtt_handshake && self.requires_hybrid() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "hybrid-only key_exchange_groups cannot be combined with zero_rtt_handshake",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ClientProxyConfig, ClientQuicConfig, ServerQuicConfig, TlsServerConfig};

    #[test]
    fn allowlists_are_nonempty_unique_and_native_only() {
        for yaml in [
            "[]",
            "null",
            "[X25519, X25519]",
            "[SecP384r1MLKEM1024]",
            "[MLKEM768]",
            "[typo]",
        ] {
            assert!(
                serde_yaml::from_str::<TlsKeyExchangeGroups>(yaml).is_err(),
                "{yaml}"
            );
        }
        for (yaml, strict) in [
            ("[X25519MLKEM768]", true),
            ("[SecP256r1MLKEM768, X25519MLKEM768]", true),
            ("[X25519MLKEM768, X25519]", false),
            ("[SecP256r1, SecP384r1]", false),
        ] {
            let groups: TlsKeyExchangeGroups = serde_yaml::from_str(yaml).unwrap();
            assert_eq!(groups.requires_hybrid(), strict);
            assert_eq!(
                groups,
                serde_yaml::from_str(&serde_yaml::to_string(&groups).unwrap()).unwrap()
            );
            assert_eq!(groups.validate_vision(true).is_err(), strict);
            assert_eq!(groups.validate_zero_rtt(true).is_err(), strict);
            assert!(groups.validate_vision(false).is_ok());
        }
    }

    #[test]
    fn ordinary_tls_and_quic_share_the_allowlist() {
        for field in ["", "key_exchange_groups: [SecP256r1MLKEM768]\n"] {
            let strict = !field.is_empty();
            let client: ClientProxyConfig =
                serde_yaml::from_str(&format!("type: tls\n{field}protocol: {{type: socks}}\n"))
                    .unwrap();
            let ClientProxyConfig::Tls(tls) = &client else {
                panic!()
            };
            assert_eq!(tls.key_exchange_groups.requires_hybrid(), strict);
            let serialized = serde_yaml::to_string(&client).unwrap();
            assert_eq!(serialized.contains("key_exchange_groups"), strict);
            assert!(serde_yaml::from_str::<ClientProxyConfig>(&serialized).is_ok());
            let server: TlsServerConfig = serde_yaml::from_str(&format!(
                "{field}cert: cert\nkey: key\nprotocol: {{type: socks}}\n"
            ))
            .unwrap();
            assert_eq!(server.key_exchange_groups.requires_hybrid(), strict);
            let client: ClientQuicConfig =
                serde_yaml::from_str(&format!("verify: true\n{field}")).unwrap();
            assert_eq!(client.key_exchange_groups.requires_hybrid(), strict);
            let server: ServerQuicConfig =
                serde_yaml::from_str(&format!("cert: cert\nkey: key\n{field}")).unwrap();
            assert_eq!(server.key_exchange_groups.requires_hybrid(), strict);
        }
    }
}
