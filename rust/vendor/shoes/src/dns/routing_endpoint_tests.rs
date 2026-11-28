use super::*;
use crate::dns::DnsContext;
use crate::resolver::{DnsCallerDeadline, dns_caller_deadline};
use ::hickory_resolver::proto::{
    op::MessageType,
    rr::{
        RData, Record,
        rdata::{
            HTTPS, SVCB,
            svcb::{EchConfigList, SvcParamKey, SvcParamValue},
        },
    },
};
use std::{
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    time::Duration,
};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

#[derive(Debug)]
struct ForbiddenFallback;

impl Resolver for ForbiddenFallback {
    fn resolve_location(&self, _: &NetLocation) -> ResolveFuture {
        panic!("endpoint lookup fell back to the default resolver")
    }

    fn exchange(&self, _: Vec<u8>) -> DnsExchangeFuture {
        panic!("endpoint DNS message fell back to the default resolver")
    }
}

#[derive(Debug)]
struct NamedUpstream {
    nested: Arc<dyn Resolver>,
    context: Arc<DnsContext>,
    blocked: AtomicBool,
    retired: CancellationToken,
    exchanges: AtomicUsize,
    deadlines: parking_lot::Mutex<Vec<Instant>>,
}

impl NamedUpstream {
    fn new() -> Arc<Self> {
        let nested: Arc<dyn Resolver> = Arc::new(ForbiddenFallback);
        Arc::new(Self {
            context: Arc::new(DnsContext::real(nested.clone())),
            nested,
            blocked: AtomicBool::new(false),
            retired: CancellationToken::new(),
            exchanges: AtomicUsize::new(0),
            deadlines: Default::default(),
        })
    }

    fn endpoint(self: &Arc<Self>, strategy: IpStrategy) -> Arc<dyn Resolver> {
        let named: Arc<dyn Resolver> = self.clone();
        let base = scope(
            Arc::new(ForbiddenFallback),
            [("selected".into(), named)].into_iter(),
        );
        endpoint_resolver(
            &base,
            &DomainResolverConfig {
                server: "selected".into(),
                ip_strategy: strategy,
            },
        )
        .unwrap()
    }
}

impl Resolver for NamedUpstream {
    fn named(&self, name: &str) -> Option<Arc<dyn Resolver>> {
        (name == "nested").then(|| self.nested.clone())
    }

    fn resolves_before_route(&self) -> bool {
        true
    }

    fn request_timeout(&self) -> Option<Duration> {
        Some(Duration::from_millis(125))
    }

    fn retire(&self) {
        self.retired.cancel();
    }

    fn fake_dns_context(&self) -> Option<Arc<DnsContext>> {
        Some(self.context.clone())
    }

    fn resolve_location(&self, location: &NetLocation) -> ResolveFuture {
        let port = location.port();
        Box::pin(async move {
            Ok(vec![
                SocketAddr::new("192.0.2.1".parse().unwrap(), port),
                SocketAddr::new("2001:db8::1".parse().unwrap(), port),
            ])
        })
    }

    fn exchange(&self, request: Vec<u8>) -> DnsExchangeFuture {
        self.exchanges.fetch_add(1, Ordering::Relaxed);
        let blocked = self.blocked.load(Ordering::Relaxed);
        let retired = self.retired.clone();
        Box::pin(async move {
            if blocked {
                retired.cancelled().await;
            }
            if retired.is_cancelled() {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "selected DNS transport retired",
                ));
            }
            let mut reply = crate::dns::message::decode(&request)?;
            assert_eq!(reply.queries[0].query_type, RecordType::HTTPS);
            reply.metadata.message_type = MessageType::Response;
            reply.add_answer(Record::from_rdata(
                reply.queries[0].name.clone(),
                30,
                RData::HTTPS(HTTPS(SVCB::new(
                    1,
                    Name::root(),
                    vec![(
                        SvcParamKey::EchConfigList,
                        SvcParamValue::EchConfigList(EchConfigList(vec![0, 1, 42])),
                    )],
                ))),
            ));
            reply.to_vec().map_err(io::Error::other)
        })
    }

    fn exchange_with_deadline(&self, request: Vec<u8>, deadline: Instant) -> DnsExchangeFuture {
        self.deadlines.lock().push(deadline);
        let future = self.exchange(request);
        Box::pin(async move {
            tokio::time::timeout_at(deadline, future)
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, DnsCallerDeadline))?
        })
    }
}

fn https_query() -> Vec<u8> {
    let mut query = Message::query();
    query.metadata.id = 42;
    query.add_query(Query::query(
        Name::from_ascii("secret.example.").unwrap(),
        RecordType::HTTPS,
    ));
    query.to_vec().unwrap()
}

#[tokio::test]
async fn endpoint_family_strategy_preserves_raw_https_records() {
    let upstream = NamedUpstream::new();
    let location = NetLocation::from_str("secret.example:443", None).unwrap();
    let expected = upstream.exchange(https_query()).await.unwrap();
    for (strategy, addresses) in [
        (IpStrategy::Ipv4Only, vec!["192.0.2.1:443"]),
        (IpStrategy::Ipv6Only, vec!["[2001:db8::1]:443"]),
        (
            IpStrategy::Ipv6ThenIpv4,
            vec!["[2001:db8::1]:443", "192.0.2.1:443"],
        ),
        (
            IpStrategy::Ipv4ThenIpv6,
            vec!["192.0.2.1:443", "[2001:db8::1]:443"],
        ),
    ] {
        let endpoint = upstream.endpoint(strategy);
        assert_eq!(endpoint.exchange(https_query()).await.unwrap(), expected);
        assert_eq!(
            endpoint.resolve_location(&location).await.unwrap(),
            addresses
                .into_iter()
                .map(|value| value.parse::<SocketAddr>().unwrap())
                .collect::<Vec<_>>()
        );
    }
}

#[tokio::test]
async fn endpoint_preserves_caller_deadline_and_timeout_error_identity() {
    let upstream = NamedUpstream::new();
    upstream.blocked.store(true, Ordering::Relaxed);
    let endpoint = upstream.endpoint(IpStrategy::Ipv4Only);
    let deadline = Instant::now() + Duration::from_millis(5);
    let error = tokio::time::timeout(
        Duration::from_secs(1),
        endpoint.exchange_with_deadline(https_query(), deadline),
    )
    .await
    .expect("endpoint lost the caller's deadline")
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(dns_caller_deadline(&error));
    assert_eq!(&*upstream.deadlines.lock(), &[deadline]);
    assert_eq!(upstream.exchanges.load(Ordering::Relaxed), 1);
    assert!(!upstream.retired.is_cancelled());

    // An individual deadline must not permanently retire the shared upstream.
    upstream.blocked.store(false, Ordering::Relaxed);
    endpoint.exchange(https_query()).await.unwrap();
}

#[tokio::test]
async fn endpoint_retirement_reaches_pending_exchange_and_keeps_policy_capabilities() {
    let upstream = NamedUpstream::new();
    let endpoint = upstream.endpoint(IpStrategy::Ipv6Only);
    assert!(endpoint.resolves_before_route());
    assert_eq!(endpoint.request_timeout(), Some(Duration::from_millis(125)));
    assert!(Arc::ptr_eq(
        &endpoint.named("nested").unwrap(),
        &upstream.nested
    ));
    assert!(endpoint.named("missing").is_none());
    assert!(Arc::ptr_eq(
        &endpoint.fake_dns_context().unwrap(),
        &upstream.context
    ));

    upstream.blocked.store(true, Ordering::Relaxed);
    let mut pending = endpoint.exchange(https_query());
    assert!(futures::poll!(&mut pending).is_pending());
    endpoint.retire();
    let error = tokio::time::timeout(Duration::from_secs(1), pending)
        .await
        .expect("endpoint retirement left its DNS exchange alive")
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
    assert_eq!(
        endpoint.exchange(https_query()).await.unwrap_err().kind(),
        io::ErrorKind::ConnectionAborted
    );
}
