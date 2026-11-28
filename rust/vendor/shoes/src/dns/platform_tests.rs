use super::*;
use crate::embedding::{PhysicalNetwork, PhysicalNetworkKind, PhysicalNetworkSnapshot};
use hickory_resolver::proto::{
    op::{Message, Query, ResponseCode},
    rr::{
        Name, RData, Record, RecordType,
        rdata::{A, AAAA},
    },
};
use std::sync::{
    Mutex,
    atomic::{AtomicU64, AtomicUsize, Ordering},
};

#[derive(Clone, Copy)]
enum Reply {
    Answer(ResponseCode),
    Corrupt(u8),
    Fail,
    Pending,
    Switch,
}
struct Mock {
    generation: AtomicU64,
    reply: Mutex<Reply>,
    calls: Mutex<Vec<PlatformNetwork>>,
    active: Arc<AtomicUsize>,
    no_default: bool,
}
impl Mock {
    fn new(reply: Reply) -> Arc<Self> {
        Arc::new(Self {
            generation: AtomicU64::new(1),
            reply: Mutex::new(reply),
            calls: Default::default(),
            active: Default::default(),
            no_default: false,
        })
    }
}
struct Active(Arc<AtomicUsize>);
impl Drop for Active {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
impl Platform for Mock {
    fn protect(&self, _: i32) -> io::Result<()> {
        panic!("system DNS must not open a raw socket")
    }
    fn dns_servers(&self) -> io::Result<Vec<std::net::SocketAddr>> {
        panic!("system DNS does not need raw endpoints")
    }
    fn supports_system_dns(&self) -> bool {
        true
    }
    fn physical_networks(&self) -> io::Result<PhysicalNetworkSnapshot> {
        Ok(PhysicalNetworkSnapshot {
            generation: self.generation.load(Ordering::SeqCst),
            default_handle: (!self.no_default).then_some(u64::MAX),
            networks: vec![PhysicalNetwork {
                handle: u64::MAX,
                kind: PhysicalNetworkKind::Wifi,
                interface: "wlan0".into(),
                dns: vec![],
            }],
        })
    }
    fn exchange_system_dns(self: Arc<Self>, query: PlatformDnsQuery) -> DnsExchangeFuture {
        Box::pin(async move {
            self.calls.lock().unwrap().push(query.network);
            self.active.fetch_add(1, Ordering::SeqCst);
            let _active = Active(self.active.clone());
            let mode = *self.reply.lock().unwrap();
            match mode {
                Reply::Fail => return Err(io::ErrorKind::PermissionDenied.into()),
                Reply::Pending => return std::future::pending().await,
                Reply::Switch => {
                    self.generation.fetch_add(1, Ordering::SeqCst);
                }
                _ => {}
            }
            let mut response = super::super::message::decode(&query.message)?;
            response.metadata.message_type = MessageType::Response;
            response.metadata.response_code = match mode {
                Reply::Answer(code) => code,
                _ => ResponseCode::NoError,
            };
            if response.metadata.response_code == ResponseCode::NoError {
                let q = &response.queries[0];
                let data = match q.query_type {
                    RecordType::A => Some(RData::A(A("192.0.2.8".parse().unwrap()))),
                    RecordType::AAAA => Some(RData::AAAA(AAAA("2001:db8::8".parse().unwrap()))),
                    _ => None,
                };
                if let Some(data) = data {
                    response
                        .answers
                        .push(Record::from_rdata(q.name.clone(), 60, data));
                }
            }
            match mode {
                Reply::Corrupt(0) => response.metadata.id ^= 1,
                Reply::Corrupt(1) => response.metadata.message_type = MessageType::Query,
                Reply::Corrupt(2) => response.metadata.op_code = OpCode::Status,
                Reply::Corrupt(3) => {
                    response.queries[0].name = Name::from_ascii("different.example").unwrap()
                }
                Reply::Corrupt(4) => response.metadata.truncation = true,
                Reply::Corrupt(5) => return Ok(vec![0; 11]),
                Reply::Corrupt(6) => return Ok(vec![0; 65536]),
                Reply::Corrupt(7) => {
                    let mut bytes = response.to_vec().unwrap();
                    bytes.push(0);
                    return Ok(bytes);
                }
                _ => {}
            }
            response.to_vec().map_err(io::Error::other)
        })
    }
}
fn request(kind: RecordType) -> Vec<u8> {
    let mut message = Message::query();
    message.metadata.id = 123;
    message.add_query(Query::query(
        Name::from_ascii("system.example").unwrap(),
        kind,
    ));
    message.to_vec().unwrap()
}
async fn poll_pending<T>(
    future: &mut std::pin::Pin<Box<impl std::future::Future<Output = T> + ?Sized>>,
) {
    std::future::poll_fn(|cx| {
        assert!(future.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
}

#[tokio::test]
async fn raw_rcodes_and_https_queries_use_exact_network_without_plain_dns() {
    for code in [
        ResponseCode::NoError,
        ResponseCode::NXDomain,
        ResponseCode::ServFail,
        ResponseCode::Refused,
    ] {
        let platform = Mock::new(Reply::Answer(code));
        let resolver = resolver(platform.clone()).unwrap();
        for kind in [RecordType::A, RecordType::AAAA, RecordType::HTTPS] {
            let bytes = resolver.exchange(request(kind)).await.unwrap();
            let response = super::super::message::decode(&bytes).unwrap();
            assert_eq!(response.metadata.response_code, code);
            assert_eq!(response.metadata.id, 123);
            assert_eq!(response.queries[0].query_type, kind);
        }
        assert!(platform.calls.lock().unwrap().iter().all(|n| *n
            == PlatformNetwork {
                generation: 1,
                handle: u64::MAX
            }));
    }
    let platform = Mock::new(Reply::Fail);
    assert_eq!(
        resolver(platform.clone())
            .unwrap()
            .exchange(request(RecordType::A))
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::PermissionDenied
    );
    assert_eq!(platform.calls.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn malformed_responses_and_requests_are_rejected_before_caching() {
    for variant in 0..8 {
        let platform = Mock::new(Reply::Corrupt(variant));
        let resolver = resolver(platform.clone()).unwrap();
        assert_eq!(
            resolver
                .exchange(request(RecordType::A))
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData,
            "variant {variant}"
        );
        *platform.reply.lock().unwrap() = Reply::Answer(ResponseCode::NoError);
        resolver.exchange(request(RecordType::A)).await.unwrap();
        assert_eq!(platform.calls.lock().unwrap().len(), 2);
    }
    let platform = Mock::new(Reply::Fail);
    let resolver = resolver(platform.clone()).unwrap();
    for bytes in [vec![0; 11], vec![0; 65536]] {
        assert!(resolver.exchange(bytes).await.is_err());
    }
    assert!(platform.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn cache_hits_and_delayed_first_poll_cannot_cross_network_generations() {
    let platform = Mock::new(Reply::Answer(ResponseCode::NoError));
    let resolver = resolver(platform.clone()).unwrap();
    let target = NetLocation::from_str("system.example:443", None).unwrap();
    let addresses = resolver.resolve_location(&target).await.unwrap();
    assert_eq!(
        addresses,
        [
            "192.0.2.8:443".parse().unwrap(),
            "[2001:db8::8]:443".parse().unwrap()
        ]
    );
    resolver.resolve_location(&target).await.unwrap();
    assert_eq!(platform.calls.lock().unwrap().len(), 2);
    let cached = resolver.resolve_location(&target);
    let raw_cached = resolver.exchange(request(RecordType::A));
    platform.generation.store(2, Ordering::SeqCst);
    assert_eq!(
        cached.await.unwrap_err().kind(),
        io::ErrorKind::NotConnected
    );
    assert_eq!(
        raw_cached.await.unwrap_err().kind(),
        io::ErrorKind::NotConnected
    );
    assert_eq!(platform.calls.lock().unwrap().len(), 2);
    let fresh = super::resolver(platform.clone()).unwrap();
    fresh.exchange(request(RecordType::A)).await.unwrap();
    assert_eq!(platform.calls.lock().unwrap().last().unwrap().generation, 2);
    let cached = fresh.exchange(request(RecordType::A));
    fresh.retire();
    assert_eq!(
        cached.await.unwrap_err().kind(),
        io::ErrorKind::NotConnected
    );
}

#[tokio::test(start_paused = true)]
async fn retirement_deadlines_and_caller_drop_cancel_the_platform_future() {
    let platform = Mock::new(Reply::Pending);
    let resolver = resolver(platform.clone()).unwrap();
    let mut pending = resolver.exchange(request(RecordType::A));
    poll_pending(&mut pending).await;
    assert_eq!(platform.active.load(Ordering::SeqCst), 1);
    drop(pending);
    assert_eq!(platform.active.load(Ordering::SeqCst), 0);
    let mut pending = resolver.exchange(request(RecordType::A));
    poll_pending(&mut pending).await;
    resolver.retire();
    assert_eq!(
        pending.await.unwrap_err().kind(),
        io::ErrorKind::NotConnected
    );
    assert_eq!(platform.active.load(Ordering::SeqCst), 0);
    let resolver = super::resolver(platform.clone()).unwrap();
    let result = resolver
        .exchange_with_deadline(
            request(RecordType::A),
            Instant::now() + Duration::from_millis(20),
        )
        .await;
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert_eq!(platform.active.load(Ordering::SeqCst), 0);
    let calls = platform.calls.lock().unwrap().len();
    let delayed = resolver.exchange(request(RecordType::A));
    tokio::time::advance(TIMEOUT).await;
    assert_eq!(delayed.await.unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert_eq!(platform.calls.lock().unwrap().len(), calls);
}

#[tokio::test]
async fn late_completion_on_replaced_network_is_not_exposed_or_cached() {
    let platform = Mock::new(Reply::Switch);
    let resolver = resolver(platform.clone()).unwrap();
    assert_eq!(
        resolver
            .exchange(request(RecordType::A))
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::NotConnected
    );
}

#[tokio::test]
async fn system_queries_are_bounded_and_release_capacity_on_cancel() {
    let platform = Mock::new(Reply::Pending);
    let resolver = resolver(platform.clone()).unwrap();
    let mut pending = Vec::new();
    for _ in 0..MAX_QUERIES {
        let mut future = resolver.exchange(request(RecordType::A));
        poll_pending(&mut future).await;
        pending.push(future);
    }
    assert!(resolver.exchange(request(RecordType::A)).await.is_err());
    assert_eq!(platform.calls.lock().unwrap().len(), MAX_QUERIES);
    pending.pop();
    let mut future = resolver.exchange(request(RecordType::A));
    poll_pending(&mut future).await;
    assert_eq!(platform.active.load(Ordering::SeqCst), MAX_QUERIES);
    resolver.retire();
    drop((pending, future));
    assert_eq!(platform.active.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn missing_default_network_allows_context_but_never_dispatches_dns() {
    let mut platform = Mock::new(Reply::Fail);
    Arc::get_mut(&mut platform).unwrap().no_default = true;
    let resolver = resolver(platform.clone()).unwrap();
    assert_eq!(
        resolver
            .exchange(request(RecordType::A))
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::NotConnected
    );
    assert!(platform.calls.lock().unwrap().is_empty());
}
