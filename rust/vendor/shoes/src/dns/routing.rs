//! DNS policy and named endpoint resolvers. Policies never fall back to an
//! unrelated resolver after an upstream error, and FakeIP is interception-only.
use super::IpStrategy;
use crate::{
    address::NetLocation,
    config::dns::{DnsRoutingConfig, DomainResolverConfig},
    resolver::{DnsExchangeFuture, ResolveFuture, Resolver},
    rules::Outcome,
};
use hickory_resolver::proto::{
    op::{Message, Query, ResponseCode},
    rr::{Name, RecordType},
};
use std::{collections::HashMap, io, net::SocketAddr, sync::Arc};

#[derive(Debug)]
pub(super) struct RoutingResolver {
    config: DnsRoutingConfig,
    upstreams: HashMap<String, Arc<dyn Resolver>>,
    cache: Arc<parking_lot::Mutex<super::cache::AnswerCache>>,
}
impl RoutingResolver {
    pub(super) fn new(
        config: DnsRoutingConfig,
        get: impl Fn(&str) -> Option<Arc<dyn Resolver>>,
    ) -> io::Result<Arc<Self>> {
        let mut upstreams = HashMap::new();
        for name in config.dependencies() {
            upstreams.insert(
                name.to_owned(),
                get(name).ok_or_else(|| {
                    crate::rules::invalid(format!("DNS upstream '{name}' is not ready"))
                })?,
            );
        }
        Ok(Arc::new(Self {
            config,
            upstreams,
            cache: Default::default(),
        }))
    }
    fn rule(
        &self,
        name: &str,
        kind: RecordType,
        intercepted: bool,
    ) -> Option<&crate::config::dns::DnsRoutingRule> {
        self.config.rules.iter().find(|rule| {
            (intercepted || !rule.fake_ip)
                && (rule.query_types.is_empty() || rule.query_types.contains(&u16::from(kind)))
                && rule.compiled.as_ref().is_some_and(|p| {
                    p.evaluate(Some(name.trim_end_matches('.')), None, 53) == Outcome::Match
                })
        })
    }
    pub(super) fn wants_fake(&self, request: &Message) -> bool {
        request.queries.len() == 1
            && self
                .rule(
                    &request.queries[0].name.to_ascii(),
                    request.queries[0].query_type,
                    true,
                )
                .is_some_and(|r| r.fake_ip)
    }
    fn dispatch(
        &self,
        request: Vec<u8>,
        deadline: Option<tokio::time::Instant>,
    ) -> DnsExchangeFuture {
        let parsed = super::message::decode(&request);
        let cache_request = parsed.as_ref().ok().and_then(|message| {
            super::cache::AnswerCache::key(message, &request).map(|key| (key, message.clone()))
        });
        let (upstream, response) = match parsed {
            Ok(message) if message.queries.len() == 1 => {
                let question = &message.queries[0];
                let rule = self.rule(&question.name.to_ascii(), question.query_type, false);
                if let Some(code) = rule.and_then(|r| r.rcode) {
                    (
                        None,
                        Some(
                            super::fake_ip::responder::response(
                                &message,
                                ResponseCode::from(0, code as u8),
                            )
                            .to_vec()
                            .map_err(io::Error::other),
                        ),
                    )
                } else {
                    let name = rule
                        .and_then(|r| r.server.as_ref())
                        .unwrap_or(&self.config.final_server);
                    (Some(self.upstreams[name].clone()), None)
                }
            }
            Ok(message) => (
                None,
                Some(
                    super::fake_ip::responder::response(&message, ResponseCode::FormErr)
                        .to_vec()
                        .map_err(io::Error::other),
                ),
            ),
            Err(error) => (None, Some(Err(error))),
        };
        if let Some(response) = response {
            return Box::pin(async { response });
        }
        let upstream = upstream.unwrap();
        if let Some((key, message)) = &cache_request {
            if let Some(response) = self
                .cache
                .lock()
                .get(key, message, std::time::Instant::now())
            {
                return Box::pin(async move { Ok(response) });
            }
        }
        let future = match deadline {
            Some(deadline) => upstream.exchange_with_deadline(request, deadline),
            None => upstream.exchange(request),
        };
        let cache = self.cache.clone();
        Box::pin(async move {
            let response = future.await?;
            if let Some((key, message)) = cache_request {
                cache
                    .lock()
                    .insert(key, &message, &response, std::time::Instant::now());
            }
            Ok(response)
        })
    }
}
impl Resolver for RoutingResolver {
    fn resolves_before_route(&self) -> bool {
        self.config.resolve_before_route
    }
    fn resolve_location(&self, location: &NetLocation) -> ResolveFuture {
        if let Some(address) = location.to_socket_addr_nonblocking() {
            return Box::pin(async move { Ok(vec![address]) });
        }
        let location = location.clone();
        let strategy = self.config.ip_strategy;
        let name = location.address().hostname().unwrap().to_owned();
        let query = |kind| {
            let mut message = Message::query();
            let parsed = Name::from_ascii(&name).map_err(io::Error::other);
            match parsed {
                Ok(name) => {
                    message.add_query(Query::query(name, kind));
                    match message.to_vec() {
                        Ok(bytes) => self.dispatch(bytes, None),
                        Err(error) => Box::pin(async move { Err(io::Error::other(error)) })
                            as DnsExchangeFuture,
                    }
                }
                Err(error) => Box::pin(async move { Err(error) }) as DnsExchangeFuture,
            }
        };
        let ipv4 = query(RecordType::A);
        let ipv6 = query(RecordType::AAAA);
        Box::pin(async move {
            let parse = |bytes: Vec<u8>, ipv6: bool| -> io::Result<Vec<SocketAddr>> {
                let message = super::message::decode(&bytes)?;
                if message.metadata.response_code != ResponseCode::NoError {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("DNS response {}", message.metadata.response_code),
                    ));
                }
                // Only accept addresses owned by the question or its CNAME chain.
                // Additional-section glue and HTTPS hints are not lookup answers.
                let mut allowed = vec![name.trim_end_matches('.').to_ascii_lowercase()];
                for _ in 0..message.answers.len().min(16) {
                    let mut changed = false;
                    for record in &message.answers {
                        if allowed.iter().any(|name| {
                            record
                                .name
                                .to_ascii()
                                .trim_end_matches('.')
                                .eq_ignore_ascii_case(name)
                        }) {
                            if let hickory_resolver::proto::rr::RData::CNAME(cname) = &record.data {
                                let name = cname
                                    .0
                                    .to_ascii()
                                    .trim_end_matches('.')
                                    .to_ascii_lowercase();
                                if !allowed.contains(&name) {
                                    allowed.push(name);
                                    changed = true;
                                }
                            }
                        }
                    }
                    if !changed {
                        break;
                    }
                }
                Ok(message
                    .answers
                    .iter()
                    .filter(|record| {
                        allowed.iter().any(|name| {
                            record
                                .name
                                .to_ascii()
                                .trim_end_matches('.')
                                .eq_ignore_ascii_case(name)
                        })
                    })
                    .filter_map(|record| match record.data {
                        hickory_resolver::proto::rr::RData::A(ip) if !ipv6 => {
                            Some(std::net::IpAddr::V4(ip.0))
                        }
                        hickory_resolver::proto::rr::RData::AAAA(ip) if ipv6 => {
                            Some(std::net::IpAddr::V6(ip.0))
                        }
                        _ => None,
                    })
                    .map(|ip| SocketAddr::new(ip, location.port()))
                    .collect())
            };
            let (v4, v6) = match strategy {
                IpStrategy::Ipv4Only => (ipv4.await.and_then(|b| parse(b, false)), Ok(Vec::new())),
                IpStrategy::Ipv6Only => (Ok(Vec::new()), ipv6.await.and_then(|b| parse(b, true))),
                _ => {
                    let (v4, v6) = tokio::join!(ipv4, ipv6);
                    (
                        v4.and_then(|b| parse(b, false)),
                        v6.and_then(|b| parse(b, true)),
                    )
                }
            };
            let mut addresses = Vec::new();
            let mut error = None;
            for result in if strategy == IpStrategy::Ipv6ThenIpv4 {
                [v6, v4]
            } else {
                [v4, v6]
            } {
                match result {
                    Ok(ips) => {
                        for ip in ips {
                            if !addresses.contains(&ip) {
                                addresses.push(ip);
                            }
                        }
                    }
                    Err(e) => error = Some(e),
                }
            }
            if addresses.is_empty() {
                Err(error.unwrap_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        "DNS returned no usable IP addresses",
                    )
                }))
            } else {
                Ok(addresses)
            }
        })
    }
    fn exchange(&self, request: Vec<u8>) -> DnsExchangeFuture {
        self.dispatch(request, None)
    }
    fn exchange_with_deadline(
        &self,
        request: Vec<u8>,
        deadline: tokio::time::Instant,
    ) -> DnsExchangeFuture {
        self.dispatch(request, Some(deadline))
    }
    fn retire(&self) {
        self.cache.lock().clear();
        for resolver in self.upstreams.values() {
            resolver.retire();
        }
    }
}

#[derive(Debug)]
struct Scope {
    base: Arc<dyn Resolver>,
    named: HashMap<String, Arc<dyn Resolver>>,
}
pub(super) fn scope(
    base: Arc<dyn Resolver>,
    named: impl Iterator<Item = (String, Arc<dyn Resolver>)>,
) -> Arc<dyn Resolver> {
    Arc::new(Scope {
        base,
        named: named.collect(),
    })
}
impl Resolver for Scope {
    fn resolves_before_route(&self) -> bool {
        self.base.resolves_before_route()
    }
    fn named(&self, name: &str) -> Option<Arc<dyn Resolver>> {
        self.named.get(name).cloned()
    }
    fn resolve_location(&self, location: &NetLocation) -> ResolveFuture {
        self.base.resolve_location(location)
    }
    fn exchange(&self, request: Vec<u8>) -> DnsExchangeFuture {
        self.base.exchange(request)
    }
    fn exchange_with_deadline(
        &self,
        request: Vec<u8>,
        deadline: tokio::time::Instant,
    ) -> DnsExchangeFuture {
        self.base.exchange_with_deadline(request, deadline)
    }
    fn fake_dns_context(&self) -> Option<Arc<super::DnsContext>> {
        self.base.fake_dns_context()
    }
    fn request_timeout(&self) -> Option<std::time::Duration> {
        self.base.request_timeout()
    }
    fn retire(&self) {
        self.base.retire();
    }
}

pub(crate) fn endpoint_resolver(
    base: &Arc<dyn Resolver>,
    config: &DomainResolverConfig,
) -> io::Result<Arc<dyn Resolver>> {
    let inner = base.named(&config.server).ok_or_else(|| {
        crate::rules::invalid(format!(
            "domain_resolver '{}' is unavailable",
            config.server
        ))
    })?;
    Ok(Arc::new(Strategy {
        inner,
        strategy: config.ip_strategy,
    }))
}
#[derive(Debug)]
struct Strategy {
    inner: Arc<dyn Resolver>,
    strategy: IpStrategy,
}
impl Resolver for Strategy {
    fn named(&self, name: &str) -> Option<Arc<dyn Resolver>> {
        self.inner.named(name)
    }

    fn resolves_before_route(&self) -> bool {
        self.inner.resolves_before_route()
    }

    fn request_timeout(&self) -> Option<std::time::Duration> {
        self.inner.request_timeout()
    }

    fn retire(&self) {
        self.inner.retire();
    }

    fn fake_dns_context(&self) -> Option<Arc<super::DnsContext>> {
        self.inner.fake_dns_context()
    }

    // The address-family preference applies to resolved socket addresses only.
    // Raw queries (notably HTTPS for ECH) keep the selected resolver's policy,
    // timeout and transport lifecycle, without interpreting or filtering records.
    fn exchange(&self, request: Vec<u8>) -> DnsExchangeFuture {
        self.inner.exchange(request)
    }

    fn exchange_with_deadline(
        &self,
        request: Vec<u8>,
        deadline: tokio::time::Instant,
    ) -> DnsExchangeFuture {
        self.inner.exchange_with_deadline(request, deadline)
    }

    fn resolve_location(&self, location: &NetLocation) -> ResolveFuture {
        let future = self.inner.resolve_location(location);
        let strategy = self.strategy;
        Box::pin(async move {
            let mut addresses = future.await?;
            match strategy {
                IpStrategy::Ipv4Only => addresses.retain(SocketAddr::is_ipv4),
                IpStrategy::Ipv6Only => addresses.retain(SocketAddr::is_ipv6),
                IpStrategy::Ipv6ThenIpv4 => addresses.sort_by_key(SocketAddr::is_ipv4),
                _ => addresses.sort_by_key(SocketAddr::is_ipv6),
            }
            if addresses.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "domain resolver returned no address in the requested family",
                ));
            }
            Ok(addresses)
        })
    }
}

#[cfg(test)]
#[path = "routing_endpoint_tests.rs"]
mod endpoint_tests;
