//! Integration at the actual TUN TCP/UDP ingress functions, with a held DNS
//! lookup proving that attribution starts before remote setup can stall.
use super::*;
use crate::{
    address::{NetLocation, NetLocationMask},
    client_proxy_selector::{ClientProxySelector, ConnectAction, ConnectRule},
    control::{
        catalog::RuleDescription,
        flows::{FlowContext, FlowRegistry},
    },
    dns::{DnsContext, fake_ip::FakeIpOptions},
    resolver::{ResolveFuture, Resolver},
};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadBuf},
    net::{TcpListener, UdpSocket},
    sync::Notify,
};

const HOST: &str = "original-owner.aerobox-test.example";

#[derive(Debug)]
struct HeldResolver {
    endpoint: SocketAddr,
    entered: AtomicUsize,
    changed: Notify,
    released: CancellationToken,
}
impl HeldResolver {
    fn new(endpoint: SocketAddr) -> Arc<Self> {
        Arc::new(Self {
            endpoint,
            entered: AtomicUsize::new(0),
            changed: Notify::new(),
            released: CancellationToken::new(),
        })
    }
    async fn wait_entered(&self) {
        loop {
            let changed = self.changed.notified();
            if self.entered.load(Ordering::SeqCst) != 0 {
                return;
            }
            changed.await;
        }
    }
}
impl Resolver for Arc<HeldResolver> {
    fn resolve_location(&self, target: &NetLocation) -> ResolveFuture {
        assert_eq!(target.address().hostname(), Some(HOST));
        assert_eq!(target.port(), self.endpoint.port());
        let this = self.clone();
        Box::pin(async move {
            this.entered.fetch_add(1, Ordering::SeqCst);
            this.changed.notify_one();
            this.released.cancelled().await;
            Ok(vec![this.endpoint])
        })
    }
}

struct OwnerPlatform {
    queries: Mutex<Vec<ConnectionOwnerQuery>>,
    changed: Notify,
}
impl OwnerPlatform {
    async fn wait_count(&self, expected: usize) {
        loop {
            let changed = self.changed.notified();
            if self.queries.lock().len() >= expected {
                return;
            }
            changed.await;
        }
    }
}
impl Platform for OwnerPlatform {
    fn protect(&self, _: i32) -> io::Result<()> {
        Ok(())
    }
    fn dns_servers(&self) -> io::Result<Vec<SocketAddr>> {
        Ok(Vec::new())
    }
    fn connection_owner(&self, query: ConnectionOwnerQuery) -> io::Result<Option<ConnectionOwner>> {
        self.queries.lock().push(query);
        self.changed.notify_one();
        Ok(Some(ConnectionOwner {
            uid: 10123,
            packages: vec!["b.shared".into(), "a.shared".into()],
        }))
    }
}
struct Installed(Arc<OwnerContext>);
impl Drop for Installed {
    fn drop(&mut self) {
        self.0.retire();
    }
}

struct Fixture {
    selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    held: Arc<HeldResolver>,
    registry: Arc<FlowRegistry>,
    original: NetLocation,
    source: SocketAddr,
}
fn make_fixture(endpoint: SocketAddr, ipv6: bool) -> Fixture {
    let held = HeldResolver::new(endpoint);
    let resolver: Arc<dyn Resolver> = Arc::new(held.clone());
    let dns = Arc::new(
        DnsContext::new(
            FakeIpOptions {
                ipv6_range: Some("fd00:198:18::/112".into()),
                ..Default::default()
            },
            resolver.clone(),
        )
        .unwrap(),
    );
    let fake = dns.allocate(HOST, ipv6).unwrap();
    let original = NetLocation::from_ip_addr(fake, endpoint.port());
    let source = if ipv6 {
        "[fd00::2]:12001"
    } else {
        "172.19.0.2:12001"
    }
    .parse()
    .unwrap();
    let registry = Arc::new(FlowRegistry::default());
    let chain = crate::tcp::chain_builder::build_direct_chain_group(resolver.clone())
        .with_description(Some(Arc::new(RuleDescription {
            payload: "restored-host".into(),
            proxy: "DIRECT".into(),
            context: Some(Arc::new(FlowContext {
                registry: registry.clone(),
                generation: 1,
                inbound: "ingress".into(),
                scope: "root".into(),
                protocol: "fixture".into(),
            })),
        })));
    let selector = Arc::new(
        ClientProxySelector::new(vec![ConnectRule::new(
            vec![NetLocationMask::from(HOST).unwrap()],
            ConnectAction::new_allow(None, chain),
        )])
        .with_fake_dns_context(Some(dns))
        .unwrap(),
    );
    Fixture {
        selector,
        resolver,
        held,
        registry,
        original,
        source,
    }
}
async fn assert_owner(fixture: &Fixture) {
    loop {
        let snapshot = fixture.registry.snapshot(0);
        assert_eq!(snapshot.connections.len(), 1);
        let meta = &snapshot.connections[0].metadata;
        if meta.uid.is_some() {
            assert_eq!(meta.uid, Some(10123));
            assert_eq!(meta.packages, ["a.shared", "b.shared"]);
            assert_eq!(meta.process, "a.shared");
            assert_eq!(
                meta.shoes_original_destination,
                fixture.original.to_string()
            );
            assert_eq!(
                meta.remote_destination,
                format!("{HOST}:{}", fixture.original.port())
            );
            return;
        }
        tokio::task::yield_now().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tun_fakeip_owner_starts_before_dns_and_non_tun_remains_unknown() {
    const CHILD: &str = "AEROBOX_OWNER_INGRESS_CHILD";
    if std::env::var_os(CHILD).is_none() {
        shoes_test_support::isolated::run_isolated(
            "embedding::owner::ingress_tests::tun_fakeip_owner_starts_before_dns_and_non_tun_remains_unknown",
            CHILD,
            "1",
        );
        return;
    }
    tokio::time::timeout(Duration::from_secs(10), async {
        let platform = Arc::new(OwnerPlatform {
            queries: Mutex::new(Vec::new()),
            changed: Notify::new(),
        });
        let _installed = Installed(OwnerContext::install(platform.clone()));
        let mut expected = 0;
        for ipv6 in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let fixture = make_fixture(listener.local_addr().unwrap(), ipv6);
            let (mut app, inbound) = tokio::io::duplex(256);
            let handler = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(
                crate::tun::handle_tcp_connection(
                    inbound,
                    fixture.original.clone(),
                    fixture.selector.clone(),
                    fixture.resolver.clone(),
                    Some(fixture.source),
                ),
            ));
            fixture.held.wait_entered().await;
            expected += 1;
            // DNS is still pending: querying only after successful dial fails
            // here and would permit socket-tuple reuse to change attribution.
            platform.wait_count(expected).await;
            assert_eq!(
                platform.queries.lock().last(),
                Some(&ConnectionOwnerQuery {
                    ip_protocol: 6,
                    source: fixture.source,
                    destination: fixture.original.to_socket_addr_nonblocking().unwrap(),
                })
            );
            fixture.held.released.cancel();
            let (mut remote, _) = listener.accept().await.unwrap();
            app.write_all(b"original-tuple").await.unwrap();
            let mut bytes = [0; 14];
            remote.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"original-tuple");
            remote.write_all(&bytes).await.unwrap();
            app.read_exact(&mut bytes).await.unwrap();
            assert_owner(&fixture).await;
            app.shutdown().await.unwrap();
            remote.shutdown().await.unwrap();
            drop(app);
            drop(remote);
            handler.await.unwrap().unwrap();

            let exit = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let fixture = make_fixture(exit.local_addr().unwrap(), ipv6);
            let selector = fixture.selector.clone();
            let resolver = fixture.resolver.clone();
            let destination = fixture.original.clone();
            let source = fixture.source;
            let connecting = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
                crate::routing::ingress::connect_tun_udp_packet(
                    &selector,
                    destination,
                    &resolver,
                    source,
                    b"packet",
                )
                .await
            }));
            fixture.held.wait_entered().await;
            expected += 1;
            platform.wait_count(expected).await;
            assert_eq!(
                platform.queries.lock().last(),
                Some(&ConnectionOwnerQuery {
                    ip_protocol: 17,
                    source: fixture.source,
                    destination: fixture.original.to_socket_addr_nonblocking().unwrap(),
                })
            );
            fixture.held.released.cancel();
            let mut stream = connecting.await.unwrap().unwrap();
            futures::future::poll_fn(|cx| {
                std::pin::Pin::new(&mut *stream).poll_write_message(cx, b"packet")
            })
            .await
            .unwrap();
            let mut bytes = [0; 64];
            let (length, sender) = exit.recv_from(&mut bytes).await.unwrap();
            assert_eq!(&bytes[..length], b"packet");
            exit.send_to(b"reply", sender).await.unwrap();
            let mut buf = ReadBuf::new(&mut bytes);
            futures::future::poll_fn(|cx| {
                std::pin::Pin::new(&mut *stream).poll_read_message(cx, &mut buf)
            })
            .await
            .unwrap();
            assert_eq!(buf.filled(), b"reply");
            assert_owner(&fixture).await;
            drop(stream);
        }

        // A source socket alone does not establish App attribution for SOCKS,
        // HTTP or probes. Exercise their shared TCP/UDP ingress paths as well.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fixture = make_fixture(listener.local_addr().unwrap(), false);
        fixture.held.released.cancel();
        let setup = crate::tcp::ingress::PreparedTcp::new(
            &fixture.selector,
            fixture.original.clone(),
            vec![],
        )
        .unwrap()
        .with_source(Some(fixture.source))
        .connect(
            &mut tokio::io::empty(),
            &fixture.selector,
            &fixture.resolver,
        )
        .await
        .unwrap();
        let (remote, _) = listener.accept().await.unwrap();
        tokio::task::yield_now().await;
        assert!(
            fixture.registry.snapshot(0).connections[0]
                .metadata
                .uid
                .is_none()
        );
        drop(setup);
        drop(remote);

        let exit = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let fixture = make_fixture(exit.local_addr().unwrap(), false);
        fixture.held.released.cancel();
        let stream = crate::routing::ingress::connect_udp_packet(
            &fixture.selector,
            fixture.original.clone(),
            &fixture.resolver,
            Some(fixture.source),
            b"packet",
        )
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            fixture.registry.snapshot(0).connections[0]
                .metadata
                .uid
                .is_none()
        );
        assert_eq!(platform.queries.lock().len(), expected);
        drop(stream);
    })
    .await
    .expect("TUN owner lookup did not precede outbound DNS or leaked an ingress task");
}
