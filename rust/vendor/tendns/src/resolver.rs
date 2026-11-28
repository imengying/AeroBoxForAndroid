use std::{
    collections::{HashMap, HashSet},
    future::Future,
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail, ensure};
use hickory_proto::{
    op::{Edns, Message, Metadata, OpCode, Query, ResponseCode},
    rr::{
        DNSClass, Name, RData, Record, RecordType,
        rdata::{A, AAAA, CNAME},
    },
};
use tokio::{sync::Mutex, time::Instant};

use crate::{
    deadline,
    policy::{Discovery, Policy},
    protocol::{self, Entry, Publication, Value},
    upstream::Exchange,
};

pub trait Clock: Send + Sync {
    fn now(&self) -> Result<u64>;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Result<u64> {
        Ok(SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before Unix epoch")?
            .as_secs())
    }
}

/// Resolution and publication caching for one immutable policy and upstream.
///
/// Create separate instances for different upstream policies, even when they use
/// the same keys. The resolver never opens sockets or loads configuration files.
pub struct Resolver {
    policy: Arc<Policy>,
    upstream: Arc<dyn Exchange>,
    clock: Arc<dyn Clock>,
    cache: Mutex<HashMap<Name, Arc<Mutex<Option<Cached>>>>>,
}

#[derive(Clone)]
struct Cached {
    publication: Option<Arc<Publication>>,
    until: Instant,
}

enum Local {
    Forward,
    Missing,
    Found {
        entries: Vec<Entry>,
        ttl: u32,
        expires_at: Option<u64>,
    },
}

/// Address-family selection for application lookups.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum IpStrategy {
    Ipv4Only,
    Ipv6Only,
    #[default]
    Ipv4ThenIpv6,
    Ipv6ThenIpv4,
    Ipv4AndIpv6,
}

impl IpStrategy {
    fn select(self, addresses: &mut Vec<IpAddr>) {
        let has_v4 = addresses.iter().any(IpAddr::is_ipv4);
        let has_v6 = addresses.iter().any(IpAddr::is_ipv6);
        addresses.retain(|ip| match self {
            Self::Ipv4Only => ip.is_ipv4(),
            Self::Ipv6Only => ip.is_ipv6(),
            Self::Ipv4ThenIpv6 => !has_v4 || ip.is_ipv4(),
            Self::Ipv6ThenIpv4 => !has_v6 || ip.is_ipv6(),
            Self::Ipv4AndIpv6 => true,
        });
    }
}

/// Negative private lookup results, distinct from authentication/transport errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LookupError {
    NotFound,
    NoData,
}

impl std::fmt::Display for LookupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NotFound => "private name does not exist",
            Self::NoData => "name has no addresses for the requested family",
        })
    }
}

impl std::error::Error for LookupError {}

impl Resolver {
    pub fn new(policy: Arc<Policy>, upstream: Arc<dyn Exchange>) -> Self {
        Self::with_clock(policy, upstream, Arc::new(SystemClock))
    }

    pub fn with_clock(
        policy: Arc<Policy>,
        upstream: Arc<dyn Exchange>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            policy,
            upstream,
            clock,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Answers a DNS message without an overall timeout. Packet-serving callers
    /// should apply [`validate_request`] before invoking this method, and either
    /// enforce their own deadline or use [`Self::answer_with_deadline`].
    pub async fn answer(&self, request: Message) -> Result<Message> {
        self.answer_inner(request, None).await
    }

    /// Covers the entire request, including cache waits and all CNAME/TXT steps.
    pub async fn answer_with_deadline(
        &self,
        request: Message,
        deadline: Instant,
    ) -> Result<Message> {
        deadline::timeout_at(deadline, self.answer_inner(request, Some(deadline)))
            .await
            .context("DNS resolution timed out")?
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Resolves private/hex addresses, following local CNAMEs before handing an
    /// external terminal name to the application's ordinary address resolver.
    ///
    /// The fallback is never called for a missing or invalid private name. It
    /// receives the original absolute deadline and can preserve native OS/NSS
    /// behavior. Private chain expiry is checked again after the fallback returns.
    ///
    /// For strict namespace protection, pass absolute names and prevent fallback
    /// search/alias expansion into protected namespaces. Unclaimed relative names
    /// are passed through unchanged; native search lists and NSS aliases are
    /// opaque to this resolver and may resolve such names outside tendns.
    ///
    /// Do not cache the returned addresses with a fixed lifetime: the resolver's
    /// own publication cache already enforces TTL and authenticated expiry.
    pub async fn lookup_ip<F, Fut>(
        &self,
        name: Name,
        strategy: IpStrategy,
        deadline: Instant,
        fallback: F,
    ) -> Result<Vec<IpAddr>>
    where
        F: FnOnce(Name, Instant) -> Fut,
        Fut: Future<Output = Result<Vec<IpAddr>>>,
    {
        deadline::timeout_at(deadline, async {
            let mut name = name;
            if self.policy.claims(&name) {
                name = name.to_lowercase();
                name.set_fqdn(true);
            }
            let mut seen = HashSet::new();
            let mut expires_at: Option<u64> = None;
            for _ in 0..16 {
                ensure!(seen.insert(name.clone()), "CNAME loop");
                let mut addresses = match self.local(&name, Some(deadline)).await? {
                    Local::Forward => {
                        self.remaining_validity(expires_at)?;
                        deadline::check(deadline).context("DNS resolution timed out")?;
                        fallback(name, deadline).await?
                    }
                    Local::Missing => {
                        self.remaining_validity(expires_at)?;
                        return Err(LookupError::NotFound.into());
                    }
                    Local::Found {
                        entries,
                        expires_at: expiry,
                        ..
                    } => {
                        if let Some(expiry) = expiry {
                            expires_at = Some(expires_at.map_or(expiry, |old| old.min(expiry)));
                        }
                        if let Some(target) = entries.iter().find_map(|entry| match &entry.value {
                            Value::Cname(target) => Some(target),
                            _ => None,
                        }) {
                            name = target.clone();
                            continue;
                        }
                        entries
                            .into_iter()
                            .filter_map(|entry| match entry.value {
                                Value::A(ip) => Some(IpAddr::V4(ip)),
                                Value::Aaaa(ip) => Some(IpAddr::V6(ip)),
                                Value::Cname(_) => None,
                            })
                            .collect()
                    }
                };
                self.remaining_validity(expires_at)?;
                strategy.select(&mut addresses);
                let mut unique = HashSet::new();
                addresses.retain(|ip| unique.insert(*ip));
                ensure!(!addresses.is_empty(), LookupError::NoData);
                return Ok(addresses);
            }
            bail!("CNAME chain exceeds 16 names")
        })
        .await
        .context("DNS resolution timed out")?
    }

    async fn answer_inner(&self, request: Message, deadline: Option<Instant>) -> Result<Message> {
        ensure!(request.queries.len() == 1, "expected one question");
        let question = &request.queries[0];
        let mut name = question.name().to_lowercase();
        if self.policy.claims(&name) {
            name.set_fqdn(true);
        }
        let kind = question.query_type();
        let mut seen = HashSet::new();
        let mut response = local_response(&request, ResponseCode::NoError);
        let mut synthesized_at = None;
        let mut expires_at: Option<u64> = None;
        for _ in 0..16 {
            ensure!(seen.insert(name.clone()), "CNAME loop");
            match self.local(&name, deadline).await? {
                Local::Forward => {
                    let mut forwarded = request.clone();
                    forwarded.queries = vec![Query::query(name, kind)];
                    let mut result = self.exchange(forwarded, deadline).await?;
                    result.metadata.id = request.metadata.id;
                    result.queries = request.queries.clone();
                    if !response.answers.is_empty() {
                        response = self.finish_local(response, synthesized_at, expires_at)?;
                        response.answers.append(&mut result.answers);
                        result.answers = response.answers;
                        result.metadata.authentic_data = false;
                        result.metadata.authoritative = false;
                    }
                    return Ok(result);
                }
                Local::Missing => {
                    response.metadata.response_code = ResponseCode::NXDomain;
                    return self.finish_local(response, synthesized_at, expires_at);
                }
                Local::Found {
                    entries,
                    ttl,
                    expires_at: entry_expiry,
                } => {
                    synthesized_at.get_or_insert_with(Instant::now);
                    if let Some(expiry) = entry_expiry {
                        expires_at =
                            Some(expires_at.map_or(expiry, |previous| previous.min(expiry)));
                    }
                    if let Some(target) = entries.iter().find_map(|entry| match &entry.value {
                        Value::Cname(target) => Some(target),
                        _ => None,
                    }) {
                        response.answers.push(Record::from_rdata(
                            name.clone(),
                            ttl,
                            RData::CNAME(CNAME(target.clone())),
                        ));
                        if matches!(kind, RecordType::CNAME | RecordType::ANY) {
                            return self.finish_local(response, synthesized_at, expires_at);
                        }
                        name = target.clone();
                        continue;
                    }
                    for entry in entries {
                        let data = match entry.value {
                            Value::A(ip) if matches!(kind, RecordType::A | RecordType::ANY) => {
                                RData::A(A(ip))
                            }
                            Value::Aaaa(ip)
                                if matches!(kind, RecordType::AAAA | RecordType::ANY) =>
                            {
                                RData::AAAA(AAAA(ip))
                            }
                            _ => continue,
                        };
                        let record = Record::from_rdata(name.clone(), ttl, data);
                        if !response.answers.contains(&record) {
                            response.answers.push(record);
                        }
                    }
                    return self.finish_local(response, synthesized_at, expires_at);
                }
            }
        }
        bail!("CNAME chain exceeds 16 names")
    }

    fn finish_local(
        &self,
        mut response: Message,
        synthesized_at: Option<Instant>,
        expires_at: Option<u64>,
    ) -> Result<Message> {
        let remaining = self.remaining_validity(expires_at)?;
        if let Some(started) = synthesized_at {
            // Conservatively age the local chain; newly received upstream records are untouched.
            let elapsed = started.elapsed().as_secs().min(u64::from(u32::MAX)) as u32;
            for record in &mut response.answers {
                record.ttl = record.ttl.saturating_sub(elapsed).min(remaining);
            }
        }
        Ok(response)
    }

    fn remaining_validity(&self, expires_at: Option<u64>) -> Result<u32> {
        let Some(expiry) = expires_at else {
            return Ok(u32::MAX);
        };
        let now = self.clock.now()?;
        ensure!(now < expiry, "publication expired during resolution");
        Ok((expiry - now).min(u64::from(u32::MAX)) as u32)
    }

    async fn exchange(&self, request: Message, deadline: Option<Instant>) -> Result<Message> {
        match deadline {
            Some(deadline) => {
                deadline::check(deadline).context("DNS resolution timed out")?;
                self.upstream
                    .exchange_with_deadline(request, deadline)
                    .await
            }
            None => self.upstream.exchange(request).await,
        }
    }

    async fn local(&self, name: &Name, deadline: Option<Instant>) -> Result<Local> {
        for zone in self.policy.hex_zones() {
            if !zone.zone_of(name) {
                continue;
            }
            if name == zone {
                return Ok(Local::Found {
                    entries: Vec::new(),
                    ttl: self.policy.ttl(),
                    expires_at: None,
                });
            }
            if name.num_labels() != zone.num_labels() + 1 {
                return Ok(Local::Missing);
            }
            let Some(label) = name.iter().next() else {
                return Ok(Local::Missing);
            };
            if label.len() != 8 || !label.iter().all(u8::is_ascii_hexdigit) {
                return Ok(Local::Missing);
            }
            let hex = std::str::from_utf8(label).expect("ASCII hex");
            let ip = Ipv4Addr::from(u32::from_str_radix(hex, 16).expect("validated hex"));
            return Ok(Local::Found {
                entries: vec![Entry {
                    subdomain: String::new(),
                    value: Value::A(ip),
                }],
                ttl: self.policy.ttl(),
                expires_at: None,
            });
        }
        let Some(discovery) = self.policy.discovery_for(name) else {
            return Ok(Local::Forward);
        };
        let parent = name.base_name();
        if discovery.domain.zone_of(&parent) {
            let label = name.iter().next().context("missing child label")?;
            let label = std::str::from_utf8(label).context("invalid child label")?;
            if let Some(found) = self.entries(&parent, label, discovery, deadline).await? {
                return Ok(found);
            }
        }
        Ok(self
            .entries(name, "", discovery, deadline)
            .await?
            .unwrap_or(Local::Missing))
    }

    async fn entries(
        &self,
        owner: &Name,
        subdomain: &str,
        discovery: &Discovery,
        deadline: Option<Instant>,
    ) -> Result<Option<Local>> {
        let cached = self.publication(owner, discovery, deadline).await?;
        let Some(publication) = cached.publication else {
            return Ok(None);
        };
        let now = self.clock.now()?;
        publication.validate_time(now)?;
        let entries: Vec<_> = publication
            .entries
            .iter()
            .filter(|entry| entry.subdomain == subdomain)
            .cloned()
            .collect();
        // An owner with hidden children exists, even without records of its own.
        if entries.is_empty() && !subdomain.is_empty() {
            return Ok(None);
        }
        let cache_ttl = cached
            .until
            .saturating_duration_since(Instant::now())
            .as_secs();
        let remaining_validity = publication.expires_at - now;
        let ttl = cache_ttl
            .min(u64::from(self.policy.ttl()))
            .min(remaining_validity) as u32;
        Ok(Some(Local::Found {
            entries,
            ttl,
            expires_at: Some(publication.expires_at),
        }))
    }

    async fn publication(
        &self,
        owner: &Name,
        discovery: &Discovery,
        deadline: Option<Instant>,
    ) -> Result<Cached> {
        let slot = {
            let mut cache = self.cache.lock().await;
            if let Some(slot) = cache.get(owner) {
                slot.clone()
            } else {
                if cache.len() >= self.policy.cache_capacity()
                    && let Some(evicted) = cache.keys().next().cloned()
                {
                    cache.remove(&evicted);
                }
                let slot = Arc::new(Mutex::new(None));
                cache.insert(owner.clone(), slot.clone());
                slot
            }
        };
        // Serialize only this owner's fetch; unrelated names can resolve concurrently.
        let mut state = slot.lock().await;
        if let Some(cached) = state.as_ref() {
            let now = self.clock.now()?;
            if cached.until > Instant::now()
                && cached
                    .publication
                    .as_ref()
                    .is_none_or(|p| p.validate_time(now).is_ok())
            {
                return Ok(cached.clone());
            }
        }
        *state = None;
        let mut query = Message::query();
        query.metadata.recursion_desired = true;
        query
            .queries
            .push(Query::query(owner.clone(), RecordType::TXT));
        let mut edns = Edns::new();
        edns.set_max_payload(1232);
        query.edns = Some(edns);
        let answer = self.exchange(query, deadline).await?;
        let now = self.clock.now()?;
        let (publication, ttl) =
            collect_publications(&answer, owner, discovery, now, self.policy.ttl())?;
        let cached = Cached {
            publication: publication.map(Arc::new),
            until: Instant::now() + Duration::from_secs(u64::from(ttl)),
        };
        *state = Some(cached.clone());
        Ok(cached)
    }
}

pub fn local_response(request: &Message, code: ResponseCode) -> Message {
    let mut result = Message::response(request.metadata.id, request.metadata.op_code);
    result.metadata = Metadata::response_from_request(&request.metadata);
    result.metadata.response_code = code;
    result.metadata.recursion_available = true;
    result.metadata.authoritative = false;
    result.metadata.authentic_data = false;
    result.queries = request.queries.clone();
    if let Some(edns) = &request.edns {
        let mut reply = Edns::new();
        reply.set_max_payload(edns.max_payload().clamp(512, 1232));
        result.edns = Some(reply);
    }
    result
}

pub(crate) fn collect_publications(
    response: &Message,
    owner: &Name,
    discovery: &Discovery,
    now: u64,
    ttl_cap: u32,
) -> Result<(Option<Publication>, u32)> {
    ensure!(!response.metadata.truncation, "truncated TXT response");
    ensure!(
        matches!(
            response.metadata.response_code,
            ResponseCode::NoError | ResponseCode::NXDomain
        ),
        "TXT lookup failed"
    );
    ensure!(
        !response
            .answers
            .iter()
            .any(|r| r.name == *owner && matches!(r.data, RData::CNAME(_))),
        "TXT CNAME indirection is not supported"
    );
    let mut txt_count = 0;
    let mut total_bytes = 0;
    let mut combined: Option<Publication> = None;
    let mut ttl = ttl_cap;
    for record in &response.answers {
        if record.name != *owner || record.dns_class != DNSClass::IN {
            continue;
        }
        let RData::TXT(txt) = &record.data else {
            continue;
        };
        txt_count += 1;
        total_bytes += txt.txt_data.iter().map(|chunk| chunk.len()).sum::<usize>();
        ensure!(
            txt_count <= 16 && total_bytes <= protocol::MAX_ENCODED * 16,
            "TXT response exceeds limits"
        );
        let value = txt.txt_data.concat();
        if !protocol::is_encrypted_txt(&value) {
            continue;
        }
        // A bad sibling value may contain the queried hidden label. It is not a miss.
        let publication = protocol::decrypt(&value, &discovery.key, owner, now)?;
        ensure!(
            response.metadata.response_code == ResponseCode::NoError,
            "contradictory TXT response"
        );
        ttl = ttl.min(record.ttl);
        if let Some(previous) = &mut combined {
            previous.issued_at = previous.issued_at.min(publication.issued_at);
            previous.expires_at = previous.expires_at.min(publication.expires_at);
            for entry in publication.entries {
                if !previous.entries.contains(&entry) {
                    previous.entries.push(entry);
                }
            }
            previous.validate(owner)?;
        } else {
            combined = Some(publication);
        }
    }
    if let Some(publication) = combined {
        ttl = u64::from(ttl).min(publication.expires_at - now) as u32;
        return Ok((Some(publication), ttl));
    }
    let ttl = response
        .authorities
        .iter()
        .filter_map(|r| match &r.data {
            RData::SOA(soa) if r.name.zone_of(owner) => Some(r.ttl.min(soa.minimum).min(ttl_cap)),
            _ => None,
        })
        .min()
        .unwrap_or(0);
    Ok((None, ttl))
}

pub fn validate_request(request: &Message) -> Option<ResponseCode> {
    if request.metadata.op_code != OpCode::Query {
        return Some(ResponseCode::NotImp);
    }
    if request.queries.len() != 1 {
        return Some(ResponseCode::FormErr);
    }
    if request.signature.is_some() {
        return Some(ResponseCode::Refused);
    }
    let query = &request.queries[0];
    if query.query_class() != DNSClass::IN
        || matches!(query.query_type(), RecordType::AXFR | RecordType::IXFR)
    {
        return Some(ResponseCode::Refused);
    }
    if request.edns.as_ref().is_some_and(|e| e.version() != 0) {
        return Some(ResponseCode::BADVERS);
    }
    None
}
