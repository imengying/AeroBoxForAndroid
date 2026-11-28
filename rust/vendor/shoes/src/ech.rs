//! Client ECH policy. All HPKE is RustCrypto; no opportunistic cleartext fallback.
use crate::resolver::Resolver;
use base64::{Engine, engine::general_purpose::STANDARD};
use hickory_resolver::proto::{
    op::{Message, MessageType, Query, ResponseCode},
    rr::{Name, RData, RecordType, rdata::svcb::SvcParamValue},
};
use rustls::{ClientConfig, client::EchConfig, pki_types::ServerName};
use serde::{Deserialize, Serialize};
use std::{
    io::{self, Read},
    sync::Arc,
    time::Duration,
};
use tokio::{sync::Mutex, time::Instant};

const MAX_PEM: usize = 128 * 1024;
const MAX_ALIASES: usize = 8;
fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}
fn bad(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct EchOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query_server_name: Option<String>,
}
impl EchOptions {
    /// Resolve files while loading configuration, not on a connection's hot path.
    pub(crate) fn embed(&mut self) -> io::Result<()> {
        if self.config.as_ref().is_none_or(String::is_empty) {
            if let Some(path) = self.config_path.as_ref().filter(|p| !p.is_empty()) {
                let mut data = String::new();
                std::fs::File::open(path)?
                    .take(MAX_PEM as u64 + 1)
                    .read_to_string(&mut data)?;
                if data.len() > MAX_PEM {
                    return Err(invalid("ECH config PEM exceeds 128 KiB"));
                }
                self.config = Some(data);
            }
        }
        self.config_path = None;
        self.static_config()?;
        if let Some(name) = self.query_server_name.as_ref().filter(|n| !n.is_empty()) {
            if crate::dns::canonical_hostname(name).is_none() {
                return Err(invalid("ECH query_server_name requires a DNS hostname"));
            }
        }
        Ok(())
    }
    pub(crate) fn static_config(&self) -> io::Result<Option<EchConfig>> {
        self.config
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(parse_pem)
            .transpose()
    }
}
fn parse_pem(pem: &str) -> io::Result<EchConfig> {
    if pem.len() > MAX_PEM {
        return Err(invalid("ECH config PEM exceeds 128 KiB"));
    }
    let content = pem
        .trim()
        .strip_prefix("-----BEGIN ECH CONFIGS-----")
        .and_then(|s| s.strip_suffix("-----END ECH CONFIGS-----"))
        .ok_or_else(|| invalid("expected one ECH CONFIGS PEM block"))?;
    let encoded: String = content
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| invalid("invalid ECH CONFIGS base64"))?;
    parse_list(&bytes)
}
fn parse_list(bytes: &[u8]) -> io::Result<EchConfig> {
    if bytes.len() < 3
        || bytes.len() > 65537
        || usize::from(u16::from_be_bytes([bytes[0], bytes[1]])) != bytes.len() - 2
    {
        return Err(invalid("invalid or trailing ECHConfigList data"));
    }
    EchConfig::new(bytes.into(), aerobox_crypto::hpke::ALL_SUPPORTED_SUITES)
        .map_err(io::Error::other)
}

#[derive(Debug, Default)]
pub(crate) struct RetryConfigs(std::sync::Mutex<Option<Vec<u8>>>);
impl rustls::client::EchRejectionHandler for RetryConfigs {
    fn rejected(&self, configs: Option<Vec<u8>>) {
        *self.0.lock().unwrap() = configs;
    }
}
impl RetryConfigs {
    pub(crate) fn take(&self) -> io::Result<Option<EchConfig>> {
        self.0
            .lock()
            .unwrap()
            .take()
            .map(|bytes| parse_list(&bytes))
            .transpose()
    }
}

#[derive(Debug)]
struct Cached {
    mode: Arc<EchConfig>,
    expires: Option<Instant>,
}
#[derive(Debug)]
pub(crate) struct Policy {
    inline: Option<Arc<EchConfig>>,
    query: String,
    cache: Mutex<Option<Cached>>,
}
impl Policy {
    pub(crate) fn new(options: &EchOptions, name: &ServerName<'_>) -> io::Result<Arc<Self>> {
        let mut options = options.clone();
        options.embed()?;
        let inline = options.static_config()?.map(Arc::new);
        if !matches!(name, ServerName::DnsName(_)) {
            return Err(invalid("ECH requires a TLS DNS server name"));
        }
        let query = options
            .query_server_name
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| name.to_str().into_owned());
        let query = crate::dns::canonical_hostname(&query)
            .ok_or_else(|| invalid("invalid ECH query hostname"))?;
        Ok(Arc::new(Self {
            inline,
            query,
            cache: Mutex::new(None),
        }))
    }
    pub(crate) async fn mode(&self, resolver: &Arc<dyn Resolver>) -> io::Result<Arc<EchConfig>> {
        let budget = resolver
            .request_timeout()
            .unwrap_or(Duration::from_secs(10));
        let deadline = Instant::now()
            .checked_add(budget)
            .ok_or_else(|| invalid("ECH DNS timeout overflows"))?;
        // Include time waiting for another caller. Cancellation drops the lock
        // and any in-flight DNS request; no detached query survives its caller.
        tokio::time::timeout_at(deadline, async {
            let mut cache = self.cache.lock().await;
            if let Some(cached) = &*cache {
                if cached
                    .expires
                    .is_none_or(|expires| expires > Instant::now())
                {
                    return Ok(cached.mode.clone());
                }
            }
            *cache = None;
            if let Some(mode) = &self.inline {
                return Ok(mode.clone());
            }
            let (mode, ttl) = fetch(&self.query, resolver, deadline).await?;
            let mode = Arc::new(mode);
            *cache = Some(Cached {
                mode: mode.clone(),
                expires: Some(Instant::now() + Duration::from_secs(u64::from(ttl))),
            });
            Ok(mode)
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "ECH DNS lookup timed out"))?
    }

    /// Publish a retry only after the second handshake succeeds. Preserve the
    /// original DNS TTL and do not overwrite a concurrent, newer DNS refresh.
    pub(crate) fn accepted_retry(&self, previous: &Arc<EchConfig>, replacement: Arc<EchConfig>) {
        let Ok(mut cache) = self.cache.try_lock() else {
            return;
        };
        let current = cache
            .as_ref()
            .map(|entry| &entry.mode)
            .or(self.inline.as_ref());
        if !current.is_some_and(|current| Arc::ptr_eq(current, previous)) {
            return;
        }
        let expires = cache.as_ref().and_then(|entry| entry.expires);
        if expires.is_some_and(|expires| expires <= Instant::now()) {
            return;
        }
        *cache = Some(Cached {
            mode: replacement,
            expires,
        });
    }
    pub(crate) async fn prepare(
        &self,
        base: &Arc<ClientConfig>,
        resolver: &Arc<dyn Resolver>,
    ) -> io::Result<Prepared> {
        Prepared::new(base, self.mode(resolver).await?)
    }
}
#[derive(Debug)]
pub(crate) struct Prepared {
    pub(crate) config: Arc<ClientConfig>,
    pub(crate) mode: Arc<EchConfig>,
    pub(crate) retry: Arc<RetryConfigs>,
}
impl Prepared {
    pub(crate) fn new(base: &Arc<ClientConfig>, mode: Arc<EchConfig>) -> io::Result<Self> {
        let mut config = (**base).clone();
        config
            .set_ech_config((*mode).clone())
            .map_err(io::Error::other)?;
        // set_ech_config defaults to no early data. Preserve only the caller's
        // explicit policy; ordinary TLS/QUIC bases keep this disabled.
        config.enable_early_data = base.enable_early_data;
        let retry = Arc::new(RetryConfigs::default());
        config.ech_rejection_handler = Some(retry.clone());
        Ok(Self {
            config: Arc::new(config),
            mode,
            retry,
        })
    }
}

async fn fetch(
    name: &str,
    resolver: &Arc<dyn Resolver>,
    deadline: Instant,
) -> io::Result<(EchConfig, u32)> {
    let mut name = Name::from_ascii(name).map_err(io::Error::other)?;
    name.set_fqdn(true);
    let mut seen = Vec::new();
    let mut ttl = u32::MAX;
    for _ in 0..MAX_ALIASES {
        if seen.contains(&name) {
            return Err(bad("ECH DNS alias loop"));
        }
        seen.push(name.clone());
        let mut request = Message::query();
        request.metadata.id = rand::random();
        request.metadata.recursion_desired = true;
        request.add_query(Query::query(name.clone(), RecordType::HTTPS));
        let raw = resolver
            .exchange_with_deadline(request.to_vec().map_err(io::Error::other)?, deadline)
            .await?;
        let response = crate::dns::message::decode(&raw)?;
        if response.metadata.id != request.metadata.id
            || response.metadata.op_code != request.metadata.op_code
            || response.metadata.message_type != MessageType::Response
            || response.queries != request.queries
            || response.metadata.truncation
            || response.response_code != ResponseCode::NoError
        {
            return Err(bad("invalid ECH HTTPS DNS response"));
        }
        let mut owner = name.clone();
        let mut local_seen = Vec::new();
        for _ in 0..MAX_ALIASES {
            if local_seen.contains(&owner) {
                return Err(bad("ECH DNS CNAME loop"));
            }
            local_seen.push(owner.clone());
            let records: Vec<_> = response
                .answers
                .iter()
                .filter(|r| {
                    r.name == owner && r.dns_class == hickory_resolver::proto::rr::DNSClass::IN
                })
                .collect();
            if let Some((record, cname)) = records.iter().find_map(|r| {
                if let RData::CNAME(c) = &r.data {
                    Some((*r, c))
                } else {
                    None
                }
            }) {
                ttl = ttl.min(record.ttl);
                owner = cname.0.clone();
                continue;
            }
            let mut bindings: Vec<_> = records
                .iter()
                .filter_map(|r| {
                    if let RData::HTTPS(h) = &r.data {
                        Some((*r, &h.0))
                    } else {
                        None
                    }
                })
                .collect();
            bindings.sort_by_key(|(_, binding)| binding.svc_priority);
            if let Some((record, binding)) = bindings.first().filter(|(_, b)| b.svc_priority == 0) {
                if binding.target_name.is_root() {
                    return Err(bad("unavailable ECH HTTPS alias"));
                }
                ttl = ttl.min(record.ttl);
                owner = binding.target_name.clone();
                break;
            }
            for (record, binding) in bindings {
                for (_, value) in &binding.svc_params {
                    if let SvcParamValue::EchConfigList(list) = value {
                        return Ok((parse_list(&list.0)?, ttl.min(record.ttl)));
                    }
                }
            }
            if owner != name {
                break;
            }
            return Err(bad("no ECH config found in HTTPS DNS answer"));
        }
        name = owner;
    }
    Err(bad("ECH DNS alias limit exceeded"))
}

pub(crate) fn contains(protocol: &crate::config::ResolvedClientProxyConfig) -> bool {
    use crate::config::ResolvedClientProxyConfig as P;
    match protocol {
        P::Tls(tls) => tls.options.ech.is_some() || contains(&tls.protocol),
        P::Reality { protocol, .. } => contains(protocol),
        P::Websocket(c) => contains(&c.protocol),
        P::StreamTransport(c) => contains(&c.protocol),

        P::Multiplex(c) => contains(&c.protocol),
        P::Uot(c) => contains(&c.protocol),
        _ => false,
    }
}

#[cfg(test)]
mod tests;
