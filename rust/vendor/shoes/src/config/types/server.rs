//! Server configuration types.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::address::NetLocation;
use crate::option_util::{NoneOrSome, OneOrSome};

use super::common::{
    default_reality_server_short_ids, default_reality_time_diff, default_true, is_false,
};
use super::dns::DnsConfig;
use super::rules::{ClientChainHop, RuleConfig};
use super::selection::ConfigSelection;
use super::shadowsocks::ShadowsocksConfig;
use super::transport::{BindLocation, ServerQuicConfig, TcpConfig, Transport};

/// AnyTLS user configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnyTlsUserConfig {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    pub password: String,
}

/// NaiveProxy user configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NaiveUserConfig {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    pub username: String,
    pub password: String,
}

/// NaiveProxy fallback configuration for probe resistance
///
/// Must be an absolute path to a directory to serve static files from.
/// External server fallback (http/https URLs) is no longer supported.
#[derive(Debug, Clone)]
pub struct NaiveFallbackConfig(pub std::path::PathBuf);

impl<'de> serde::Deserialize<'de> for NaiveFallbackConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        let s = String::deserialize(deserializer)?;
        if s.starts_with('/') {
            Ok(NaiveFallbackConfig(std::path::PathBuf::from(s)))
        } else {
            Err(Error::custom(
                "Fallback must be an absolute path (starting with '/')",
            ))
        }
    }
}

impl serde::Serialize for NaiveFallbackConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0.display().to_string())
    }
}

// Client route types used by server fallback destinations.

/// Custom deserializer for ServerProxyConfig::Shadowsocks
fn deserialize_shadowsocks_server<'de, D>(
    deserializer: D,
) -> Result<(ShadowsocksConfig, bool), D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ShadowsocksServerTemp {
        cipher: String,
        password: String,
        #[serde(default = "default_true")]
        udp_enabled: bool,
    }

    let temp = ShadowsocksServerTemp::deserialize(deserializer)?;
    let config =
        ShadowsocksConfig::from_fields(&temp.cipher, &temp.password).map_err(Error::custom)?;

    Ok((config, temp.udp_enabled))
}

/// Custom serializer for ServerProxyConfig::Shadowsocks - flattens config fields
fn serialize_shadowsocks_server<S>(
    config: &ShadowsocksConfig,
    udp_enabled: &bool,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeStruct;

    let mut state = serializer.serialize_struct("Shadowsocks", 3)?;
    config.serialize_fields(&mut state)?;
    state.serialize_field("udp_enabled", udp_enabled)?;
    state.end()
}

/// Custom deserializer for ServerProxyConfig::Vmess that validates legacy force_aead field
fn deserialize_vmess_server<'de, D>(deserializer: D) -> Result<(String, String, bool), D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct VmessServerTemp {
        cipher: String,
        user_id: String,
        #[serde(default = "default_true")]
        udp_enabled: bool,
        #[serde(default)]
        force_aead: Option<bool>,
    }

    let temp = VmessServerTemp::deserialize(deserializer)?;

    // Check if force_aead was explicitly set
    if let Some(force_aead_value) = temp.force_aead {
        if !force_aead_value {
            return Err(Error::custom(
                "Non-AEAD VMess mode (force_aead=false) is no longer supported. \
                 Please remove the force_aead field from your configuration, or set it to true.",
            ));
        }
        // Warn about deprecated field
        log::warn!(
            "The 'force_aead' field in VMess server configuration is deprecated and will be removed in a future version. \
             AEAD mode is now always enabled. Please remove this field from your configuration."
        );
    }

    Ok((temp.cipher, temp.user_id, temp.udp_enabled))
}

pub fn direct_allow_rule() -> NoneOrSome<ConfigSelection<RuleConfig>> {
    NoneOrSome::One(ConfigSelection::Config(RuleConfig::default()))
}

#[derive(Debug, Clone, Serialize)]
pub struct ServerRecord<P, R, D> {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub sniff: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub dns_hijack: bool,
    #[serde(flatten)]
    pub bind_location: BindLocation,
    pub protocol: P,
    #[serde(
        alias = "transport",
        default,
        skip_serializing_if = "Transport::is_default"
    )]
    pub transport: Transport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_settings: Option<TcpConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quic_settings: Option<ServerQuicConfig>,
    #[serde(
        alias = "rule",
        default = "direct_allow_rule",
        skip_serializing_if = "NoneOrSome::is_unspecified"
    )]
    pub rules: NoneOrSome<R>,
    /// DNS configuration for this server (optional).
    /// Can reference a dns_group by name or specify inline DNS servers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<D>,
}

pub type ServerConfig = ServerRecord<ServerProxyConfig, ConfigSelection<RuleConfig>, DnsConfig>;

impl<'de> serde::de::Deserialize<'de> for ServerConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        use serde::de::Error;

        let value = serde_yaml::Value::deserialize(deserializer)?;
        let map = value
            .as_mapping()
            .ok_or_else(|| Error::custom("ServerConfig must be a YAML mapping"))?;

        const VALID_FIELDS: &[&str] = &[
            "name",
            "address",
            "addresses",
            "path", // BindLocation (flattened)
            "protocol",
            "transport",
            "tcp_settings",
            "quic_settings",
            "rules",
            "rule",
            "dns",
            "sniff",
            "dns_hijack",
        ];

        // Check for unknown fields
        for key in map.keys() {
            if let Some(key_str) = key.as_str()
                && !VALID_FIELDS.contains(&key_str)
            {
                return Err(Error::custom(format!(
                    "unknown field `{}` in server config. Expected one of: {}",
                    key_str,
                    VALID_FIELDS.join(", ")
                )));
            }
        }

        let protocol: ServerProxyConfig = map
            .get("protocol")
            .ok_or_else(|| Error::custom("missing 'protocol' field in server config"))
            .and_then(|v| {
                serde_yaml::from_value(v.clone())
                    .map_err(|e| Error::custom(format!("invalid protocol: {e}")))
            })?;

        // Parse bind_location (flattened - either address or path)
        let bind_location = if let Some(v) = map.get("address").or_else(|| map.get("addresses")) {
            serde_yaml::from_value(v.clone())
                .map(BindLocation::Address)
                .map_err(|e| Error::custom(format!("invalid address: {e}")))?
        } else if let Some(v) = map.get("path") {
            serde_yaml::from_value(v.clone())
                .map(BindLocation::Path)
                .map_err(|e| Error::custom(format!("invalid path: {e}")))?
        } else {
            return Err(Error::custom(
                "server config must have 'address', 'addresses', or 'path' field",
            ));
        };

        // Parse transport (optional, default)
        let transport: Transport = map
            .get("transport")
            .map(|v| serde_yaml::from_value(v.clone()))
            .transpose()
            .map_err(|e| Error::custom(format!("invalid transport: {e}")))?
            .unwrap_or_else(|| Transport::default());

        // Parse tcp_settings (optional, skip if null)
        let tcp_settings: Option<TcpConfig> = map
            .get("tcp_settings")
            .filter(|v| !v.is_null())
            .map(|v| serde_yaml::from_value(v.clone()))
            .transpose()
            .map_err(|e| Error::custom(format!("invalid tcp_settings: {e}")))?;

        // Parse quic_settings (optional, skip if null)
        let quic_settings: Option<ServerQuicConfig> = map
            .get("quic_settings")
            .filter(|v| !v.is_null())
            .map(|v| serde_yaml::from_value(v.clone()))
            .transpose()
            .map_err(|e| Error::custom(format!("invalid quic_settings: {e}")))?;

        // Parse rules (optional, with alias "rule", default to direct_allow_rule, skip if null)
        let rules: NoneOrSome<ConfigSelection<RuleConfig>> = map
            .get("rules")
            .or_else(|| map.get("rule"))
            .filter(|v| !v.is_null())
            .map(|v| serde_yaml::from_value(v.clone()))
            .transpose()
            .map_err(|e| Error::custom(format!("invalid rules: {e}")))?
            .unwrap_or_else(|| direct_allow_rule());

        // Parse dns (optional)
        let dns: Option<DnsConfig> = map
            .get("dns")
            .filter(|v| !v.is_null())
            .map(|v| serde_yaml::from_value(v.clone()))
            .transpose()
            .map_err(|e| Error::custom(format!("invalid dns: {e}")))?;

        let sniff = map
            .get("sniff")
            .map(|v| serde_yaml::from_value(v.clone()))
            .transpose()
            .map_err(|e| Error::custom(format!("invalid sniff: {e}")))?
            .unwrap_or(false);

        Ok(ServerConfig {
            name: map
                .get("name")
                .map(|v| serde_yaml::from_value(v.clone()))
                .transpose()
                .map_err(Error::custom)?,
            sniff,
            dns_hijack: map
                .get("dns_hijack")
                .map(|value| serde_yaml::from_value(value.clone()))
                .transpose()
                .map_err(Error::custom)?
                .unwrap_or(false),
            bind_location,
            protocol,
            transport,
            tcp_settings,
            quic_settings,
            rules,
            dns,
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(bound(deserialize = "P: Deserialize<'de>, R: Deserialize<'de>, H: Deserialize<'de>"))]
pub struct RealityServerRecord<P, R, H> {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mldsa65_seed: Option<String>,
    /// X25519 private key (32 bytes, base64url encoded)
    pub private_key: String,

    /// List of valid short IDs (hex strings, 0-16 chars each)
    #[serde(alias = "short_id", default = "default_reality_server_short_ids")]
    pub short_ids: OneOrSome<String>,

    /// Fallback destination (e.g., "example.com:443")
    pub dest: NetLocation,

    /// Maximum timestamp difference in milliseconds (optional)
    #[serde(default = "default_reality_time_diff")]
    pub max_time_diff: Option<u64>,

    /// Minimum client version [major, minor, patch] (optional)
    #[serde(default)]
    pub min_client_version: Option<[u8; 3]>,

    /// Maximum client version [major, minor, patch] (optional)
    #[serde(default)]
    pub max_client_version: Option<[u8; 3]>,

    /// TLS 1.3 cipher suites to support (optional)
    /// Valid values: "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"
    /// If empty or not specified, the default set is used.
    #[serde(alias = "cipher_suite", default)]
    pub cipher_suites: NoneOrSome<crate::reality::CipherSuite>,

    /// Enable XTLS-Vision protocol for TLS-in-TLS optimization.
    /// When enabled, the inner protocol MUST be VLESS.
    /// Vision detects TLS-in-TLS scenarios and switches to Direct mode for zero-copy performance.
    /// Reality provides censorship resistance while Vision provides performance optimization.
    #[serde(default)]
    pub vision: bool,
    /// Inner protocol (VLESS, Trojan, etc.)
    pub protocol: P,

    /// Client chain for connecting to dest server (for fallback connections).
    /// If not specified, connects directly to dest.
    #[serde(default)]
    pub dest_client_chain: NoneOrSome<H>,

    /// Override rules
    #[serde(alias = "override_rule", default)]
    pub override_rules: NoneOrSome<R>,
}

pub type RealityServerConfig =
    RealityServerRecord<ServerProxyConfig, ConfigSelection<RuleConfig>, ClientChainHop>;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(bound(deserialize = "P: Deserialize<'de>, R: Deserialize<'de>"))]
pub struct TlsServerRecord<P, R> {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_source: Option<String>,
    #[serde(skip)]
    pub certificate_binding: Option<std::sync::Arc<crate::certificates::Source>>,
    #[serde(
        default,
        skip_serializing_if = "super::tls::TlsKeyExchangeGroups::is_default"
    )]
    pub key_exchange_groups: super::tls::TlsKeyExchangeGroups,
    #[serde(default)]
    pub cert: String,
    #[serde(default)]
    pub key: String,
    #[serde(alias = "alpn_protocol", default)]
    pub alpn_protocols: NoneOrSome<String>,

    // trusted CA certs that client certs must chain to.
    // note that if a client cert chains back to a cert in this field,
    // it is validated even if the leaf certificate is not in `client_fingerprints`
    // below.
    #[serde(alias = "client_ca_cert", default)]
    pub client_ca_certs: NoneOrSome<String>,

    // sha256 fingerprint of allowed client certificates
    //
    // To generate a new ECDSA client certificate:
    // 1. Generate private key with P-256 curve:
    //    openssl ecparam -genkey -name prime256v1 -out client.key
    // 2. Create self-signed certificate:
    //    openssl req -new -x509 -nodes -key client.key -out client.crt -days 365 -subj "/CN=Client"
    //
    // Get the certificate's SHA256 fingerprint:
    //    openssl x509 -in client.crt -noout -fingerprint -sha256
    //
    // Each generated key pair will be unique. Multiple fingerprints can be specified
    // to allow multiple client certificates.
    #[serde(alias = "client_fingerprint", default)]
    pub client_fingerprints: NoneOrSome<String>,

    /// Enable XTLS-Vision protocol for TLS-in-TLS optimization.
    /// When enabled, the inner protocol MUST be VLESS.
    /// Vision detects TLS-in-TLS scenarios and switches to Direct mode for zero-copy performance.
    /// Requires TLS 1.3.
    #[serde(default)]
    pub vision: bool,
    pub protocol: P,

    #[serde(alias = "override_rule", default)]
    pub override_rules: NoneOrSome<R>,
}

pub type TlsServerConfig = TlsServerRecord<ServerProxyConfig, ConfigSelection<RuleConfig>>;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(bound(deserialize = "P: Deserialize<'de>, R: Deserialize<'de>"))]
pub struct WebsocketServerRecord<P, R> {
    #[serde(default)]
    pub matching_path: Option<String>,
    #[serde(default)]
    pub matching_headers: Option<HashMap<String, String>>,
    #[serde(default, skip_serializing_if = "crate::websocket::is_zero")]
    pub max_early_data: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub early_data_header_name: Option<String>,
    pub protocol: P,
    #[serde(default)]
    pub ping_type: WebsocketPingType,

    #[serde(alias = "override_rule", default)]
    pub override_rules: NoneOrSome<R>,
}

pub type WebsocketServerConfig =
    WebsocketServerRecord<ServerProxyConfig, ConfigSelection<RuleConfig>>;

#[derive(Default, Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum WebsocketPingType {
    Disabled,
    // Ping frames are better if the websocket (or a proxy) requires it to stop from timing
    // out because it causes the remote end to write a pong, which could prevent the connection
    // from timing out.
    // However, some clients (e.g. Quantumult-X) can't handle ping frames and disconnects when
    // one is received, so empty frames can be better for compatibility.
    #[serde(alias = "ping", alias = "ping-frame")]
    #[default]
    PingFrame,
    #[serde(alias = "empty", alias = "empty-frame")]
    EmptyFrame,
}

impl WebsocketPingType {
    pub fn is_default(&self) -> bool {
        matches!(self, WebsocketPingType::PingFrame)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ServerProxyConfig {
    Http {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<String>,
    },
    #[serde(alias = "socks5")]
    Socks {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<String>,
        /// Enable UDP functionality (UDP ASSOCIATE and UDP-over-TCP).
        /// When false (default), UDP ASSOCIATE returns "command not supported".
        #[serde(default = "default_true")]
        udp_enabled: bool,
    },
    #[serde(
        alias = "ss",
        deserialize_with = "deserialize_shadowsocks_server",
        serialize_with = "serialize_shadowsocks_server"
    )]
    Shadowsocks {
        config: ShadowsocksConfig,
        #[serde(default = "default_true")]
        udp_enabled: bool,
    },

    Vless {
        user_id: String,
        #[serde(
            default,
            skip_serializing_if = "super::vless::VlessEncryptionSetting::is_disabled"
        )]
        decryption: super::vless::VlessEncryptionSetting,
        #[serde(
            default,
            rename = "encryption",
            skip_serializing,
            deserialize_with = "super::vless::reject_server_encryption"
        )]
        _invalid_encryption: (),
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        vision: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        encryption_limits: Option<super::vless::VlessEncryptionLimits>,
        #[serde(default = "default_true")]
        udp_enabled: bool,
        /// Fallback destination for failed authentication (optional)
        /// When set, failed auth attempts are proxied here instead of rejected
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fallback: Option<NetLocation>,
    },
    Trojan {
        password: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        shadowsocks: Option<ShadowsocksConfig>,
    },
    Tls {
        // sni_targets is the previous field name
        #[serde(default, alias = "sni_targets", alias = "targets")]
        tls_targets: HashMap<String, TlsServerConfig>,
        // default_target is the previous field name
        #[serde(
            default,
            alias = "default_target",
            skip_serializing_if = "Option::is_none"
        )]
        default_tls_target: Option<Box<TlsServerConfig>>,

        #[serde(default)]
        reality_targets: HashMap<String, RealityServerConfig>,

        #[serde(default, skip_serializing_if = "Option::is_none")]
        tls_buffer_size: Option<usize>,
    },
    #[serde(deserialize_with = "deserialize_vmess_server")]
    Vmess {
        cipher: String,
        user_id: String,
        #[serde(default = "default_true")]
        udp_enabled: bool,
    },
    /// AnyTLS inner protocol handler
    /// Used as inner protocol within TLS/Reality/etc.
    Anytls {
        #[serde(alias = "user")]
        users: OneOrSome<AnyTlsUserConfig>,
        #[serde(alias = "padding")]
        padding_scheme: Option<Vec<String>>,
        #[serde(default = "default_true")]
        udp_enabled: bool,
        /// Fallback destination for failed authentication (optional)
        /// When set, failed auth attempts are proxied here instead of rejected
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fallback: Option<NetLocation>,
    },
    #[serde(alias = "ws")]
    Websocket {
        #[serde(alias = "target")]
        targets: Box<OneOrSome<WebsocketServerConfig>>,
    },
    #[serde(alias = "forward")]
    PortForward {
        #[serde(alias = "target")]
        targets: OneOrSome<NetLocation>,
    },
    Hysteria2 {
        password: String,
        #[serde(default = "default_true")]
        udp_enabled: bool,
    },
    #[serde(alias = "tuic")]
    TuicV5 {
        uuid: String,
        password: String,
        /// Enable 0-RTT (0.5-RTT for server) handshake for faster connection establishment.
        /// Default is false for security - 0-RTT data is vulnerable to replay attacks.
        /// See: https://blog.cloudflare.com/even-faster-connection-establishment-with-quic-0-rtt-resumption/
        #[serde(default)]
        zero_rtt_handshake: bool,
    },
    /// Mixed HTTP+SOCKS5 server (auto-detects protocol from first byte)
    /// Similar to mihomo's mixed-port feature.
    #[serde(alias = "http+socks", alias = "socks+http")]
    Mixed {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<String>,
        /// Enable UDP functionality for SOCKS5 (UDP ASSOCIATE and UDP-over-TCP)
        #[serde(default = "default_true")]
        udp_enabled: bool,
    },
    /// NaiveProxy server (HTTP/2 CONNECT with padding)
    /// Should be used within TLS for proper camouflage
    #[serde(alias = "naive")]
    Naiveproxy {
        /// List of authorized users
        #[serde(alias = "user")]
        users: OneOrSome<NaiveUserConfig>,
        /// Enable padding protocol (default: true)
        #[serde(default = "default_true")]
        padding: bool,
        /// Fallback for probe resistance (optional)
        /// Can be either a URL (http:// or https://) to reverse proxy, or an absolute path to serve files from
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fallback: Option<NaiveFallbackConfig>,
        /// Enable UDP-over-TCP (UoT) support (default: true)
        #[serde(default = "default_true")]
        udp_enabled: bool,
    },
}

impl std::fmt::Display for ServerProxyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http { .. } => write!(f, "HTTP"),
            Self::Socks { .. } => write!(f, "SOCKS"),
            Self::Shadowsocks { .. } => write!(f, "Shadowsocks"),

            Self::Vless { .. } => write!(f, "Vless"),
            Self::Trojan { .. } => write!(f, "Trojan"),
            Self::Tls {
                tls_targets,
                default_tls_target,

                reality_targets,
                ..
            } => {
                let mut parts = vec![];

                if !tls_targets.is_empty() {
                    parts.push("TLS");
                }

                if !reality_targets.is_empty() {
                    parts.push("REALITY");
                }

                if tls_targets.values().any(|cfg| cfg.vision)
                    || default_tls_target.as_ref().is_some_and(|cfg| cfg.vision)
                    || reality_targets.values().any(|cfg| cfg.vision)
                {
                    parts.push("Vision");
                }

                write!(f, "{}", parts.join("+"))
            }
            Self::Vmess { .. } => write!(f, "Vmess"),
            Self::Websocket { .. } => write!(f, "Websocket"),

            Self::PortForward { .. } => write!(f, "Portforward"),
            Self::Hysteria2 { .. } => write!(f, "Hysteria2"),
            Self::TuicV5 { .. } => write!(f, "TuicV5"),
            Self::Mixed { .. } => write!(f, "Mixed (HTTP+SOCKS5)"),
            Self::Anytls { .. } => write!(f, "AnyTLS"),
            Self::Naiveproxy { .. } => write!(f, "NaiveProxy"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ResolvedServerProxyConfig {
    Http {
        #[serde(skip_serializing_if = "Option::is_none")]
        username: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        password: Option<String>,
    },
    Socks {
        #[serde(skip_serializing_if = "Option::is_none")]
        username: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        password: Option<String>,
        udp_enabled: bool,
    },
    #[serde(serialize_with = "serialize_shadowsocks_server")]
    Shadowsocks {
        config: ShadowsocksConfig,
        udp_enabled: bool,
    },

    Vless {
        user_id: String,
        #[serde(skip_serializing_if = "super::vless::VlessEncryptionSetting::is_disabled")]
        decryption: super::vless::VlessEncryptionSetting,
        #[serde(rename = "encryption", skip_serializing)]
        _invalid_encryption: (),
        #[serde(skip_serializing_if = "std::ops::Not::not")]
        vision: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        encryption_limits: Option<super::vless::VlessEncryptionLimits>,
        udp_enabled: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        fallback: Option<NetLocation>,
    },
    Trojan {
        password: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        shadowsocks: Option<ShadowsocksConfig>,
    },
    Tls {
        tls_targets: HashMap<String, crate::config::resolved::ResolvedTlsServerConfig>,
        #[serde(skip_serializing_if = "Option::is_none")]
        default_tls_target: Option<Box<crate::config::resolved::ResolvedTlsServerConfig>>,

        reality_targets: HashMap<String, crate::config::resolved::ResolvedRealityServerConfig>,

        #[serde(skip_serializing_if = "Option::is_none")]
        tls_buffer_size: Option<usize>,
    },
    Vmess {
        cipher: String,
        user_id: String,
        udp_enabled: bool,
    },
    Anytls {
        users: OneOrSome<AnyTlsUserConfig>,
        padding_scheme: Option<Vec<String>>,
        udp_enabled: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        fallback: Option<NetLocation>,
    },
    Websocket {
        targets: Box<OneOrSome<crate::config::resolved::ResolvedWebsocketServerConfig>>,
    },
    PortForward {
        targets: OneOrSome<NetLocation>,
    },
    Hysteria2 {
        password: String,
        udp_enabled: bool,
    },
    TuicV5 {
        uuid: String,
        password: String,
        zero_rtt_handshake: bool,
    },
    Mixed {
        #[serde(skip_serializing_if = "Option::is_none")]
        username: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        password: Option<String>,
        udp_enabled: bool,
    },
    Naiveproxy {
        users: OneOrSome<NaiveUserConfig>,
        padding: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        fallback: Option<NaiveFallbackConfig>,
        udp_enabled: bool,
    },
}

impl std::fmt::Display for ResolvedServerProxyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http { .. } => write!(f, "HTTP"),
            Self::Socks { .. } => write!(f, "SOCKS"),
            Self::Shadowsocks { .. } => write!(f, "Shadowsocks"),

            Self::Vless { .. } => write!(f, "Vless"),
            Self::Trojan { .. } => write!(f, "Trojan"),
            Self::Tls {
                tls_targets,
                default_tls_target,

                reality_targets,
                ..
            } => {
                let mut parts = vec![];

                if !tls_targets.is_empty() {
                    parts.push("TLS");
                }

                if !reality_targets.is_empty() {
                    parts.push("REALITY");
                }

                if tls_targets.values().any(|cfg| cfg.vision)
                    || default_tls_target.as_ref().is_some_and(|cfg| cfg.vision)
                    || reality_targets.values().any(|cfg| cfg.vision)
                {
                    parts.push("Vision");
                }

                write!(f, "{}", parts.join("+"))
            }
            Self::Vmess { .. } => write!(f, "Vmess"),
            Self::Websocket { .. } => write!(f, "Websocket"),

            Self::PortForward { .. } => write!(f, "Portforward"),
            Self::Hysteria2 { .. } => write!(f, "Hysteria2"),
            Self::TuicV5 { .. } => write!(f, "TuicV5"),
            Self::Mixed { .. } => write!(f, "Mixed (HTTP+SOCKS5)"),
            Self::Anytls { .. } => write!(f, "AnyTLS"),
            Self::Naiveproxy { .. } => write!(f, "NaiveProxy"),
        }
    }
}

#[cfg(test)]
mod tests;
