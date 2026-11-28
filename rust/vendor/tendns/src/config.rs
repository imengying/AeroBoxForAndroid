use std::{
    fs,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use hickory_proto::rr::Name;
use serde::{Deserialize, Deserializer};
use url::Url;
use zeroize::Zeroizing;

use crate::{
    names::canonical_name,
    policy::{Discovery, Policy},
    protocol::Secret,
};

pub struct Config {
    pub listeners: Vec<Listener>,
    pub upstreams: Vec<Upstream>,
    pub policy: Arc<Policy>,
    pub valid_for: Duration,
    pub upstream_timeout: Duration,
    pub request_timeout: Duration,
    pub max_inflight: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "type", rename_all = "lowercase")]
pub enum Listener {
    Dns {
        address: SocketAddr,
    },
    Http {
        address: SocketAddr,
        #[serde(default = "default_query_path")]
        path: String,
        #[serde(default, deserialize_with = "secret_tokens")]
        auth_tokens: Vec<Zeroizing<String>>,
        auth_token_file: Option<PathBuf>,
    },
    Https {
        address: SocketAddr,
        #[serde(default = "default_query_path")]
        path: String,
        #[serde(default = "default_http2")]
        http2: bool,
        cert: PathBuf,
        key: PathBuf,
        #[serde(default, deserialize_with = "secret_tokens")]
        auth_tokens: Vec<Zeroizing<String>>,
        auth_token_file: Option<PathBuf>,
    },
}

impl Listener {
    pub fn address(&self) -> SocketAddr {
        match self {
            Self::Dns { address } | Self::Http { address, .. } | Self::Https { address, .. } => {
                *address
            }
        }
    }
}

fn secret_tokens<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<Zeroizing<String>>, D::Error> {
    Ok(Vec::<String>::deserialize(deserializer)?
        .into_iter()
        .map(Zeroizing::new)
        .collect())
}

#[derive(Clone, Debug)]
pub enum Upstream {
    Plain(SocketAddr),
    Doh { url: Url, bootstrap: Vec<IpAddr> },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    #[serde(default = "default_listeners")]
    listeners: Vec<Listener>,
    #[serde(default)]
    upstreams: Vec<RawUpstream>,
    #[serde(default)]
    discovery: Vec<RawDiscovery>,
    #[serde(default)]
    hex_zones: Vec<String>,
    #[serde(default = "default_ttl")]
    ttl: u32,
    #[serde(default = "default_validity")]
    valid_for: String,
    #[serde(default = "default_upstream_timeout")]
    upstream_timeout: String,
    #[serde(default = "default_request_timeout")]
    request_timeout: String,
    #[serde(default = "default_capacity")]
    cache_capacity: usize,
    #[serde(default = "default_inflight")]
    max_inflight: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "type", rename_all = "lowercase")]
enum RawUpstream {
    Plain { address: SocketAddr },
    Doh { url: String, bootstrap: Vec<IpAddr> },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDiscovery {
    domain: String,
    key: String,
}

fn default_listeners() -> Vec<Listener> {
    vec![Listener::Dns {
        address: "0.0.0.0:5300".parse().expect("literal address"),
    }]
}
fn default_query_path() -> String {
    "/dns-query".into()
}
fn default_http2() -> bool {
    true
}
fn default_ttl() -> u32 {
    60
}
fn default_validity() -> String {
    "24h".into()
}
fn default_upstream_timeout() -> String {
    "3s".into()
}
fn default_request_timeout() -> String {
    "10s".into()
}
fn default_capacity() -> usize {
    1024
}
fn default_inflight() -> usize {
    256
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            Zeroizing::new(fs::read_to_string(path).context("cannot read configuration file")?);
        let mut config = Self::parse(&text)?;
        let directory = path.parent().unwrap_or_else(|| Path::new("."));
        for listener in &mut config.listeners {
            let auth_token_file = match listener {
                Listener::Https {
                    cert,
                    key,
                    auth_token_file,
                    ..
                } => {
                    *cert = directory.join(&*cert);
                    *key = directory.join(&*key);
                    auth_token_file
                }
                Listener::Http {
                    auth_token_file, ..
                } => auth_token_file,
                Listener::Dns { .. } => continue,
            };
            if let Some(path) = auth_token_file {
                *path = directory.join(&*path);
            }
        }
        Ok(config)
    }

    pub fn parse(text: &str) -> Result<Self> {
        // TOML's Display includes source lines, which can contain discovery keys.
        let raw: RawConfig = toml::from_str(text).map_err(|_| {
            anyhow::anyhow!("invalid TOML configuration; check field names and types")
        })?;
        let listeners: Vec<_> = raw.listeners.iter().map(Listener::address).collect();
        ensure!(!listeners.is_empty(), "configure at least one listener");
        ensure!(
            listeners.iter().all(|addr| addr.port() != 0),
            "listener port must be nonzero"
        );
        for (i, address) in listeners.iter().enumerate() {
            ensure!(
                !listeners[..i].contains(address),
                "duplicate listener address"
            );
        }
        for listener in &raw.listeners {
            if let Listener::Https { cert, key, .. } = listener {
                ensure!(
                    !cert.as_os_str().is_empty() && !key.as_os_str().is_empty(),
                    "HTTPS listeners require certificate and key paths"
                );
            }
            if let Listener::Http {
                path,
                auth_token_file,
                ..
            }
            | Listener::Https {
                path,
                auth_token_file,
                ..
            } = listener
            {
                ensure!(
                    path.starts_with('/')
                        && path.parse::<http::uri::PathAndQuery>().is_ok_and(|parsed| {
                            parsed.query().is_none() && parsed.as_str() == path
                        }),
                    "HTTP/HTTPS listener path must start with / and contain no query, fragment, or whitespace"
                );
                ensure!(
                    auth_token_file
                        .as_ref()
                        .is_none_or(|path| !path.as_os_str().is_empty()),
                    "auth_token_file must be a nonempty path"
                );
            }
        }
        ensure!(
            raw.max_inflight > 0 && raw.max_inflight <= 65_536,
            "max_inflight must be 1-65536"
        );
        let mut discovery: Vec<Discovery> = Vec::new();
        for item in raw.discovery {
            let key = Zeroizing::new(item.key);
            let domain = canonical_name(&item.domain).context("invalid discovery domain")?;
            discovery.push(Discovery {
                domain,
                key: Arc::new(Secret::decode(&key)?),
            });
        }
        let mut hex_zones: Vec<Name> = Vec::new();
        for item in raw.hex_zones {
            let domain = canonical_name(&item).context("invalid hex zone")?;
            hex_zones.push(domain);
        }
        let policy = Arc::new(Policy::new(
            discovery,
            hex_zones,
            raw.ttl,
            raw.cache_capacity,
        )?);
        let mut upstreams = Vec::new();
        for item in raw.upstreams {
            upstreams.push(match item {
                RawUpstream::Plain { address } => {
                    ensure!(
                        address.port() != 0 && !address.ip().is_unspecified(),
                        "upstream requires a concrete address and port"
                    );
                    ensure!(
                        !raw.listeners
                            .iter()
                            .filter(|listener| matches!(listener, Listener::Dns { .. }))
                            .map(Listener::address)
                            .any(|listen| listen.port() == address.port()
                                && (listen.ip() == address.ip()
                                    || (listen.ip().is_unspecified()
                                        && address.ip().is_loopback()))),
                        "upstream points to our listener"
                    );
                    Upstream::Plain(address)
                }
                RawUpstream::Doh { url, bootstrap } => {
                    let url = Url::parse(&url).context("invalid DoH URL")?;
                    ensure!(
                        url.scheme() == "https"
                            && url.host_str().is_some()
                            && url.username().is_empty()
                            && url.password().is_none()
                            && url.fragment().is_none(),
                        "DoH URL must be HTTPS without credentials or fragment"
                    );
                    ensure!(
                        !bootstrap.is_empty() && bootstrap.iter().all(|ip| !ip.is_unspecified()),
                        "DoH requires explicit bootstrap IP addresses"
                    );
                    Upstream::Doh { url, bootstrap }
                }
            });
        }
        let request_timeout = duration(&raw.request_timeout, "request_timeout")?;
        ensure!(
            request_timeout <= Duration::from_secs(86_400),
            "request_timeout must not exceed 24h"
        );
        Ok(Self {
            listeners: raw.listeners,
            upstreams,
            policy,
            valid_for: duration(&raw.valid_for, "valid_for")?,
            upstream_timeout: duration(&raw.upstream_timeout, "upstream_timeout")?,
            request_timeout,
            max_inflight: raw.max_inflight,
        })
    }

    pub fn discovery_for(&self, name: &Name) -> Option<&Discovery> {
        self.policy.discovery_for(name)
    }
}

fn duration(value: &str, name: &str) -> Result<Duration> {
    let result =
        humantime::parse_duration(value).with_context(|| format!("invalid {name} duration"))?;
    ensure!(result.as_secs() > 0, "{name} must be at least one second");
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    const KEY: &str = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc";

    #[test]
    fn request_timeout_has_bounds_safe_for_all_listener_timers() {
        for (value, seconds) in [("1s", 1), ("24h", 86_400)] {
            let config = Config::parse(&format!("request_timeout='{value}'")).unwrap();
            assert_eq!(config.request_timeout, Duration::from_secs(seconds));
        }
        for value in ["86401s", "18446744073709551615s"] {
            let error = Config::parse(&format!("request_timeout='{value}'"))
                .err()
                .expect("excessive request timeout accepted");
            assert_eq!(error.to_string(), "request_timeout must not exceed 24h");
        }
    }

    #[test]
    fn listener_config_is_typed_and_resolves_paths_relative_to_toml() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        fs::write(
            &path,
            r#"
            [[listeners]]
            type = "http"
            address = "0.0.0.0:8053"
            auth_tokens = ["inline-secret"]
            [[listeners]]
            type = "https"
            address = "0.0.0.0:8443"
            cert = "server.crt"
            key = "server.key"
            auth_token_file = "tokens.txt"
        "#,
        )
        .unwrap();
        let config = Config::load(&path).unwrap();
        assert_eq!(config.listeners.len(), 2);
        let Listener::Http {
            auth_tokens,
            auth_token_file,
            ..
        } = &config.listeners[0]
        else {
            panic!()
        };
        assert_eq!(auth_tokens[0].as_str(), "inline-secret");
        assert!(auth_token_file.is_none());
        let Listener::Https {
            cert,
            key,
            auth_token_file,
            ..
        } = &config.listeners[1]
        else {
            panic!()
        };
        assert_eq!(cert, &directory.path().join("server.crt"));
        assert_eq!(key, &directory.path().join("server.key"));
        assert_eq!(
            auth_token_file.as_ref().unwrap(),
            &directory.path().join("tokens.txt")
        );
        // Config loading must not open startup-only credential files, including for the offline CLI.
        for invalid in [
            "listen=['0.0.0.0:5300']",
            "listeners=[]",
            "listeners=[{type='dns', address='0.0.0.0:53', auth_tokens=['secret']}]",
            "listeners=[{type='dns', address='0.0.0.0:53', auth_token_file='tokens'}]",
            "listeners=[{type='dns', address='0.0.0.0:53', path='/dns-query'}]",
            "listeners=[{type='dns', address='0.0.0.0:53', http2=true}]",
            "listeners=[{type='http', address='0.0.0.0:80', http2=true}]",
            "listeners=[{type='http', address='0.0.0.0:80', http2=false}]",
            "listeners=[{type='http', address='0.0.0.0:80', cert='cert'}]",
            "listeners=[{type='https', address='0.0.0.0:443', cert='cert'}]",
            "listeners=[{type='http', address='0.0.0.0:0'}]",
            "listeners=[{type='http', address='0.0.0.0:80', auth_token_file=''}]",
            "listeners=[{type='http', address='0.0.0.0:80'}, {type='dns', address='0.0.0.0:80'}]",
        ] {
            let error = Config::parse(invalid)
                .err()
                .expect("invalid listener config");
            assert!(!format!("{error:#}").contains("secret"));
        }
    }

    #[test]
    fn listener_paths_and_https_http2_have_validated_defaults_and_overrides() {
        for kind in ["http", "https"] {
            let mut base = format!("[[listeners]]\ntype='{kind}'\naddress='0.0.0.0:8443'\n");
            if kind == "https" {
                base.push_str("cert='server.crt'\nkey='server.key'\n");
            }
            let config = Config::parse(&base).unwrap();
            match &config.listeners[0] {
                Listener::Http { path, .. } => assert_eq!(path, "/dns-query"),
                Listener::Https { path, http2, .. } => {
                    assert_eq!(path, "/dns-query");
                    assert!(*http2);
                }
                Listener::Dns { .. } => panic!("expected HTTP/HTTPS listener"),
            }
            for expected in ["/", "/private/resolve", "/dns-query/", "/dns%2Dquery"] {
                let config = Config::parse(&format!("{base}path={expected:?}")).unwrap();
                match &config.listeners[0] {
                    Listener::Http { path, .. } | Listener::Https { path, .. } => {
                        assert_eq!(path, expected);
                    }
                    Listener::Dns { .. } => panic!("expected HTTP/HTTPS listener"),
                }
            }
            for path in [
                "",
                "dns-query",
                "https://example.com/dns-query",
                "/dns-query?name=example.com",
                "/dns-query#fragment",
                "/dns query",
                "/dns\nquery",
            ] {
                assert!(
                    Config::parse(&format!("{base}path={path:?}")).is_err(),
                    "{kind}: {path:?}"
                );
            }
            if kind == "https" {
                for expected in [false, true] {
                    let config = Config::parse(&format!("{base}http2={expected}")).unwrap();
                    let Listener::Https { http2, .. } = &config.listeners[0] else {
                        panic!("expected HTTPS listener");
                    };
                    assert_eq!(*http2, expected);
                }
                assert!(Config::parse(&format!("{base}http2='true'")).is_err());
            }
        }
    }

    #[test]
    fn parses_config_and_selects_longest_domain() {
        let config = Config::parse(&format!(
            r#"
            hex_zones = ["hex.example.net"]
            [[upstreams]]
            type = "plain"
            address = "1.1.1.1:53"
            [[upstreams]]
            type = "doh"
            url = "https://dns.example/dns-query"
            bootstrap = ["192.0.2.1", "2001:db8::1"]
            [[discovery]]
            domain = "example.com"
            key = "{KEY}"
            [[discovery]]
            domain = "inner.example.com"
            key = "{KEY}"
        "#
        ))
        .unwrap();
        assert_eq!(config.upstreams.len(), 2);
        assert_eq!(
            config
                .discovery_for(&canonical_name("a.inner.example.com").unwrap())
                .unwrap()
                .domain
                .to_ascii(),
            "inner.example.com."
        );
        assert!(
            config
                .discovery_for(&canonical_name("badexample.com").unwrap())
                .is_none()
        );
    }

    #[test]
    fn rejects_bad_configs_without_printing_secrets() {
        for text in [
            "ttl = 0".to_owned(),
            "listeners = []".to_owned(),
            "unknown = 1".to_owned(),
            "hex_zones = ['x.com', 'a.x.com']".to_owned(),
            format!(
                "hex_zones = ['a.example.com']\n[[discovery]]\ndomain='example.com'\nkey='{KEY}'"
            ),
            format!("[[discovery]]\ndomain='example.com'\nkey='{KEY}SECRET'"),
            format!("[[discovery]]\ndomain='example.com'\nkey='{KEY}SECRET"),
            "[[upstreams]]\ntype='doh'\nurl='http://example.com/dns-query'\nbootstrap=['1.1.1.1']"
                .to_owned(),
            "[[upstreams]]\ntype='doh'\nurl='https://example.com/dns-query'\nbootstrap=[]"
                .to_owned(),
            "[[upstreams]]\ntype='plain'\naddress='127.0.0.1:5300'".to_owned(),
        ] {
            let error = Config::parse(&text)
                .err()
                .expect("invalid config")
                .to_string();
            assert!(!error.contains(KEY));
        }
    }

    #[test]
    fn rejects_ambiguous_zones_invalid_limits_and_unsupported_upstreams() {
        let discovery = format!("[[discovery]]\ndomain='example.com'\nkey='{KEY}'\n");
        for text in [
            "listeners=[{type='dns', address='0.0.0.0:0'}]".to_owned(),
            "cache_capacity=0".to_owned(), "cache_capacity=65537".to_owned(),
            "max_inflight=0".to_owned(), "max_inflight=65537".to_owned(),
            "valid_for='0s'".to_owned(), "upstream_timeout='500ms'".to_owned(),
            "request_timeout='not a duration'".to_owned(),
            "hex_zones=['EXAMPLE.COM', 'example.com.']".to_owned(),
            "hex_zones=['a.example.com', 'example.com']".to_owned(),
            format!("hex_zones=['com']\n{discovery}"),
            format!("{discovery}[[discovery]]\ndomain='EXAMPLE.COM.'\nkey='{KEY}'"),
            "[[upstreams]]\ntype='dot'\naddress='1.1.1.1:853'".to_owned(),
            "[[upstreams]]\ntype='plain'\naddress='0.0.0.0:53'".to_owned(),
            "[[upstreams]]\ntype='plain'\naddress='1.1.1.1:0'".to_owned(),
            "[[upstreams]]\ntype='doh'\nurl='https://user:secret@dns.test/dns-query'\nbootstrap=['1.1.1.1']".to_owned(),
            "[[upstreams]]\ntype='doh'\nurl='https://dns.test/dns-query#fragment'\nbootstrap=['1.1.1.1']".to_owned(),
            "[[upstreams]]\ntype='doh'\nurl='https://dns.test/dns-query'\nbootstrap=['::']".to_owned(),
        ] {
            let error = Config::parse(&text).err().expect("invalid configuration accepted");
            assert!(!format!("{error:#}").contains(KEY));
        }
        let defaults = Config::parse("").unwrap();
        assert!(
            defaults.upstreams.is_empty(),
            "offline key/TXT generation needs no upstream"
        );
        assert_eq!(defaults.listeners.len(), 1);
        assert_eq!(
            defaults.listeners[0].address(),
            "0.0.0.0:5300".parse().unwrap()
        );
        assert!(Config::parse("cache_capacity=65536\nmax_inflight=65536").is_ok());
    }
}
