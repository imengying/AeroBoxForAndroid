//! Real host lifecycle around the Android system-DNS platform contract.
//! Tests serialize ownership of the process-wide platform; no Android JNI is mocked as
//! device verification. Only the platform DNS callback itself is a test double.
use shoes::{
    embedding::{
        EmbeddedCore, PhysicalNetwork, PhysicalNetworkKind, PhysicalNetworkSnapshot, Platform,
        PlatformDnsQuery, PlatformNetwork, StandaloneProbes,
    },
    resolver::DnsExchangeFuture,
};
use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Notify, oneshot},
    task::JoinSet,
};

static PLATFORM_GATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct SnapshotPause {
    remaining: usize,
    entered: oneshot::Sender<()>,
    resume: std::sync::mpsc::Receiver<()>,
}

struct SystemDnsPlatform {
    generation: AtomicU64,
    calls: Mutex<Vec<(PlatformNetwork, String, u16)>>,
    protected: AtomicUsize,
    active: Arc<AtomicUsize>,
    changed: Notify,
    snapshot_pause: Mutex<Option<SnapshotPause>>,
}
impl SystemDnsPlatform {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            generation: AtomicU64::new(1),
            calls: Mutex::new(Vec::new()),
            protected: AtomicUsize::new(0),
            active: Default::default(),
            changed: Notify::new(),
            snapshot_pause: Mutex::new(None),
        })
    }
    // Count the positive A answers. Empty AAAA replies have no SOA/negative TTL
    // and correctly must not be cached by the platform resolver.
    fn count(&self, generation: u64, name: &str) -> usize {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(network, query, kind)| {
                network.generation == generation && query == name && *kind == 1
            })
            .count()
    }
    async fn wait_for(&self, generation: u64, name: &str) {
        loop {
            let changed = self.changed.notified();
            if self.count(generation, name) != 0 {
                return;
            }
            changed.await;
        }
    }
    fn pause_snapshot(
        &self,
        remaining: usize,
    ) -> (oneshot::Receiver<()>, std::sync::mpsc::Sender<()>) {
        let (entered, observed) = oneshot::channel();
        let (resume, resumed) = std::sync::mpsc::channel();
        *self.snapshot_pause.lock().unwrap() = Some(SnapshotPause {
            remaining,
            entered,
            resume: resumed,
        });
        (observed, resume)
    }
}
struct Active(Arc<AtomicUsize>);
impl Drop for Active {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
impl Platform for SystemDnsPlatform {
    fn protect(&self, _: i32) -> io::Result<()> {
        self.protected.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn dns_servers(&self) -> io::Result<Vec<SocketAddr>> {
        panic!("platform system DNS must never require raw port-53 endpoints")
    }
    fn supports_system_dns(&self) -> bool {
        true
    }
    fn physical_networks(&self) -> io::Result<PhysicalNetworkSnapshot> {
        let pause = {
            let mut pause = self.snapshot_pause.lock().unwrap();
            if let Some(pause) = pause.as_mut() {
                pause.remaining -= 1;
            }
            if pause.as_ref().is_some_and(|pause| pause.remaining == 0) {
                pause.take()
            } else {
                None
            }
        };
        if let Some(pause) = pause {
            let _ = pause.entered.send(());
            pause.resume.recv_timeout(Duration::from_secs(5)).unwrap();
        }
        Ok(PhysicalNetworkSnapshot {
            generation: self.generation.load(Ordering::SeqCst),
            default_handle: Some(u64::MAX),
            networks: vec![PhysicalNetwork {
                handle: u64::MAX,
                kind: PhysicalNetworkKind::Wifi,
                interface: "test-physical".into(),
                // Private DNS can work without a usable physical port-53 list.
                dns: Vec::new(),
            }],
        })
    }
    fn exchange_system_dns(self: Arc<Self>, query: PlatformDnsQuery) -> DnsExchangeFuture {
        Box::pin(async move {
            assert_eq!(query.network.handle, u64::MAX);
            assert_eq!(
                query.network.generation,
                self.generation.load(Ordering::SeqCst)
            );
            assert!(tokio::time::Instant::now() < query.deadline);
            let (name, kind, _) = question(&query.message);
            self.calls
                .lock()
                .unwrap()
                .push((query.network, name.clone(), kind));
            self.active.fetch_add(1, Ordering::SeqCst);
            let _active = Active(self.active.clone());
            self.changed.notify_one();
            if name.starts_with("blocked-") {
                return std::future::pending().await;
            }
            Ok(answer(&query.message))
        })
    }
}

/// Encode only the test's A/AAAA questions, without adding another protocol
/// library to the Android crate's dependencies. Unknown names never hit OS DNS.
fn question(message: &[u8]) -> (String, u16, usize) {
    assert!(message.len() >= 12);
    assert_eq!(u16::from_be_bytes([message[4], message[5]]), 1);
    let mut offset = 12;
    let mut labels = Vec::new();
    loop {
        let length = usize::from(message[offset]);
        offset += 1;
        if length == 0 {
            break;
        }
        assert!(length <= 63 && offset + length <= message.len());
        labels.push(std::str::from_utf8(&message[offset..offset + length]).unwrap());
        offset += length;
    }
    let kind = u16::from_be_bytes([message[offset], message[offset + 1]]);
    assert_eq!(&message[offset + 2..offset + 4], &[0, 1]);
    (labels.join("."), kind, offset + 4)
}
fn answer(request: &[u8]) -> Vec<u8> {
    let (_, kind, end) = question(request);
    assert!(matches!(kind, 1 | 28));
    let mut response = request[..end].to_vec();
    response[2] = 0x80 | (request[2] & 1);
    response[3] = 0x80;
    response[6..12].fill(0);
    if kind == 1 {
        response[7] = 1;
        response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1]);
    }
    response
}

fn document(proxy: SocketAddr, dns_port: u16) -> String {
    serde_json::json!([
        {"dns_group":"platform", "dns_servers":[{"url":"system", "ip_strategy":"ipv4_only"}]},
        {"dns_group":"named-upstream", "dns_servers":[{
            "url":format!("tcp://dns-platform.aerobox-test.example:{dns_port}"),
            "bootstrap_url":"platform", "ip_strategy":"ipv4_only"
        }]},
        {"client_group":"platform-direct", "type":"selector", "client_chain":{
            "name":"platform-leaf",
            "protocol":{"type":"direct"},
            "domain_resolver":{"server":"platform", "ip_strategy":"ipv4_only"}
        }},
        {"client_group":"upstream-route", "client_chain":{
            "protocol":{"type":"direct"},
            "domain_resolver":{"server":"named-upstream", "ip_strategy":"ipv4_only"}
        }},
        {"address":proxy.to_string(), "protocol":{"type":"socks"},
            "dns":{"servers":"named-upstream"},
            "rules":[{"conditions":{"any_destination":true}, "client_chain":"upstream-route"}]}
    ])
    .to_string()
}
fn probe_document() -> Vec<shoes::config::Config> {
    serde_json::from_value(serde_json::json!([
        {"dns_group":"platform", "dns_servers":[{"url":"system", "ip_strategy":"ipv4_only"}]},
        {"client_group":"platform-direct", "type":"selector", "client_chain":{
            "name":"platform-leaf",
            "protocol":{"type":"direct"},
            "domain_resolver":{"server":"platform", "ip_strategy":"ipv4_only"}
        }}
    ]))
    .unwrap()
}

async fn http_fixture(listener: TcpListener) {
    let mut clients = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (mut stream, _) = accepted.unwrap();
                clients.spawn(async move {
                    let mut header = Vec::new();
                    while !header.ends_with(b"\r\n\r\n") {
                        if header.len() >= 8192 { return; }
                        let Ok(byte) = stream.read_u8().await else { return; };
                        header.push(byte);
                    }
                    let _ = stream.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
                    let _ = stream.shutdown().await;
                });
            }
            Some(result) = clients.join_next(), if !clients.is_empty() => { result.unwrap(); }
        }
    }
}
async fn dns_fixture(listener: TcpListener, observed: Arc<AtomicUsize>) {
    let mut clients = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (mut stream, _) = accepted.unwrap();
                let observed = observed.clone();
                clients.spawn(async move {
                    while let Ok(length) = stream.read_u16().await {
                        let mut request = vec![0; usize::from(length)];
                        if stream.read_exact(&mut request).await.is_err() { break; }
                        let (name, _, _) = question(&request);
                        assert_eq!(name, "routed.aerobox-test.example");
                        observed.fetch_add(1, Ordering::SeqCst);
                        let response = answer(&request);
                        if stream.write_u16(response.len() as u16).await.is_err() { break; }
                        if stream.write_all(&response).await.is_err() { break; }
                    }
                });
            }
            Some(result) = clients.join_next(), if !clients.is_empty() => { result.unwrap(); }
        }
    }
}
async fn routed_http(proxy: SocketAddr, target_port: u16) {
    let name = b"routed.aerobox-test.example";
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut greeting = [0; 2];
    stream.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [5, 0]);
    let mut connect = vec![5, 1, 0, 3, name.len() as u8];
    connect.extend_from_slice(name);
    connect.extend_from_slice(&target_port.to_be_bytes());
    stream.write_all(&connect).await.unwrap();
    let mut response = [0; 4];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response[..3], &[5, 0, 0]);
    let length = match response[3] {
        1 => 6,
        4 => 18,
        other => panic!("unexpected SOCKS address {other}"),
    };
    stream.read_exact(&mut vec![0; length]).await.unwrap();
    stream
        .write_all(
            b"GET / HTTP/1.1\r\nHost: routed.aerobox-test.example\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let mut header = [0; 12];
    stream.read_exact(&mut header).await.unwrap();
    assert_eq!(&header, b"HTTP/1.1 204");
}

#[tokio::test(flavor = "current_thread")]
async fn system_dns_bootstrap_urltest_switch_shutdown_and_standalone_use_platform() {
    let _gate = PLATFORM_GATE.lock().await;
    tokio::time::timeout(Duration::from_secs(30), async {
        let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_port = http.local_addr().unwrap().port();
        let dns = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dns_port = dns.local_addr().unwrap().port();
        let proxy = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let observed = Arc::new(AtomicUsize::new(0));
        let mut fixtures = JoinSet::new();
        fixtures.spawn(http_fixture(http));
        fixtures.spawn(dns_fixture(dns, observed.clone()));

        let platform = SystemDnsPlatform::new();
        let config = document(proxy, dns_port);
        let core = Arc::new(
            EmbeddedCore::start_json(&config, Some(platform.clone()))
                .await
                .unwrap(),
        );
        assert!(
            platform.count(1, "dns-platform.aerobox-test.example") > 0,
            "named DNS endpoint must bootstrap through Android system DNS"
        );
        routed_http(proxy, http_port).await;
        assert!(observed.load(Ordering::SeqCst) > 0);
        assert_eq!(
            platform.count(1, "routed.aerobox-test.example"),
            0,
            "explicit upstream queries must not be redirected to system DNS"
        );

        let url = format!("http://probe.aerobox-test.example:{http_port}/");
        core.urltest("platform-direct".into(), url.clone(), 3000)
            .await
            .unwrap();
        let cached = platform.count(1, "probe.aerobox-test.example");
        assert!(cached > 0);
        core.urltest("platform-direct".into(), url.clone(), 3000)
            .await
            .unwrap();
        assert_eq!(platform.count(1, "probe.aerobox-test.example"), cached);

        let probe_core = core.clone();
        let blocked = tokio::spawn(async move {
            probe_core
                .urltest(
                    "platform-direct".into(),
                    "http://blocked-switch.aerobox-test.example/".into(),
                    30000,
                )
                .await
        });
        platform
            .wait_for(1, "blocked-switch.aerobox-test.example")
            .await;
        assert!(platform.active.load(Ordering::SeqCst) > 0);
        platform.generation.store(2, Ordering::SeqCst);
        core.network_changed().await.unwrap();
        assert!(blocked.await.unwrap().is_err());
        assert_eq!(platform.active.load(Ordering::SeqCst), 0);
        assert!(platform.count(2, "dns-platform.aerobox-test.example") > 0);
        core.urltest("platform-direct".into(), url.clone(), 3000)
            .await
            .unwrap();
        assert!(
            platform.count(2, "probe.aerobox-test.example") > 0,
            "an old network's cache must not satisfy the replacement generation"
        );
        routed_http(proxy, http_port).await;

        let probe_core = core.clone();
        let blocked = tokio::spawn(async move {
            probe_core
                .urltest(
                    "platform-direct".into(),
                    "http://blocked-stop.aerobox-test.example/".into(),
                    30000,
                )
                .await
        });
        platform
            .wait_for(2, "blocked-stop.aerobox-test.example")
            .await;
        core.shutdown().await.unwrap();
        assert!(blocked.await.unwrap().is_err());
        assert_eq!(platform.active.load(Ordering::SeqCst), 0);
        assert!(platform.protected.load(Ordering::SeqCst) > 0);
        drop(core);

        let before = platform.count(2, "probe.aerobox-test.example");
        let probes = Arc::new(StandaloneProbes::new(Some(platform.clone())).unwrap());
        probes
            .probe(
                probe_document(),
                "platform-direct".into(),
                url.clone(),
                3000,
            )
            .await
            .unwrap();
        assert!(
            platform.count(2, "probe.aerobox-test.example") > before,
            "stopped service cache must not survive into standalone probes"
        );
        let context = probes.clone();
        let blocked = tokio::spawn(async move {
            context
                .probe(
                    probe_document(),
                    "platform-direct".into(),
                    "http://blocked-standalone.aerobox-test.example/".into(),
                    30000,
                )
                .await
        });
        platform
            .wait_for(2, "blocked-standalone.aerobox-test.example")
            .await;
        probes.shutdown().await;
        assert!(blocked.await.unwrap().is_err());
        assert_eq!(platform.active.load(Ordering::SeqCst), 0);
        drop(probes);

        let before = platform.count(2, "probe.aerobox-test.example");
        let replacement = StandaloneProbes::new(Some(platform.clone())).unwrap();
        replacement
            .probe(probe_document(), "platform-direct".into(), url, 3000)
            .await
            .unwrap();
        assert!(platform.count(2, "probe.aerobox-test.example") > before);
        replacement.shutdown().await;
        drop(replacement);
        fixtures.abort_all();
        while fixtures.join_next().await.is_some() {}
    })
    .await
    .expect("platform DNS lifecycle stalled");
}

#[tokio::test(flavor = "current_thread")]
async fn standalone_probes_share_cache_and_refresh_with_old_probes_still_pending() {
    let _gate = PLATFORM_GATE.lock().await;
    tokio::time::timeout(Duration::from_secs(10), async {
        let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "http://probe.aerobox-test.example:{}/",
            http.local_addr().unwrap().port()
        );
        let mut fixtures = JoinSet::new();
        fixtures.spawn(http_fixture(http));
        let platform = SystemDnsPlatform::new();
        let probes = Arc::new(StandaloneProbes::new(Some(platform.clone())).unwrap());
        probes
            .probe(
                probe_document(),
                "platform-direct".into(),
                url.clone(),
                3000,
            )
            .await
            .unwrap();
        let cached = platform.count(1, "probe.aerobox-test.example");
        assert!(cached > 0);

        let mut pending = Vec::new();
        for name in [
            "blocked-first.aerobox-test.example",
            "blocked-second.aerobox-test.example",
        ] {
            let context = probes.clone();
            pending.push(tokio::spawn(async move {
                context
                    .probe(
                        probe_document(),
                        "platform-direct".into(),
                        format!("http://{name}/"),
                        30000,
                    )
                    .await
            }));
            platform.wait_for(1, name).await;
        }
        probes
            .probe(
                probe_document(),
                "platform-direct".into(),
                url.clone(),
                3000,
            )
            .await
            .unwrap();
        assert!(pending.iter().all(|probe| !probe.is_finished()));
        assert_eq!(platform.count(1, "probe.aerobox-test.example"), cached);

        // Preserve the shared batch and both pending callers across the switch.
        // The incoming probe must retire them and install the new DNS context.
        platform.generation.store(2, Ordering::SeqCst);
        probes
            .probe(
                probe_document(),
                "platform-direct".into(),
                url.clone(),
                3000,
            )
            .await
            .unwrap();
        for probe in pending {
            assert!(probe.await.unwrap().is_err());
        }
        assert_eq!(platform.active.load(Ordering::SeqCst), 0);
        let refreshed = platform.count(2, "probe.aerobox-test.example");
        assert!(refreshed > 0, "replacement epoch reused stale DNS");
        probes
            .probe(probe_document(), "platform-direct".into(), url, 3000)
            .await
            .unwrap();
        assert_eq!(platform.count(2, "probe.aerobox-test.example"), refreshed);
        probes.shutdown().await;
        drop(probes);
        fixtures.abort_all();
        while fixtures.join_next().await.is_some() {}
    })
    .await
    .expect("standalone probe network replacement stalled");
}

#[tokio::test(flavor = "current_thread")]
async fn dropping_standalone_probe_cancels_its_pending_platform_query() {
    let _gate = PLATFORM_GATE.lock().await;
    tokio::time::timeout(Duration::from_secs(5), async {
        let platform = SystemDnsPlatform::new();
        let probes = Arc::new(StandaloneProbes::new(Some(platform.clone())).unwrap());
        let context = probes.clone();
        let pending = tokio::spawn(async move {
            context
                .probe(
                    probe_document(),
                    "platform-direct".into(),
                    "http://blocked-abandoned.aerobox-test.example/".into(),
                    30000,
                )
                .await
        });
        platform
            .wait_for(1, "blocked-abandoned.aerobox-test.example")
            .await;
        assert!(platform.active.load(Ordering::SeqCst) > 0);
        pending.abort();
        assert!(pending.await.unwrap_err().is_cancelled());
        // Observe cleanup before shutdown can cancel the whole shared context.
        while platform.active.load(Ordering::SeqCst) != 0 {
            tokio::task::yield_now().await;
        }
        probes.shutdown().await;
    })
    .await
    .expect("abandoned probe retained its platform DNS query");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_during_standalone_network_refresh_never_admits_replacement() {
    let _gate = PLATFORM_GATE.lock().await;
    tokio::time::timeout(Duration::from_secs(10), async {
        let platform = SystemDnsPlatform::new();
        let probes = Arc::new(StandaloneProbes::new(Some(platform.clone())).unwrap());
        let context = probes.clone();
        let old = tokio::spawn(async move {
            context
                .probe(
                    probe_document(),
                    "platform-direct".into(),
                    "http://blocked-before-refresh.aerobox-test.example/".into(),
                    30000,
                )
                .await
        });
        platform
            .wait_for(1, "blocked-before-refresh.aerobox-test.example")
            .await;
        platform.generation.store(2, Ordering::SeqCst);
        // Admission reads the changed epoch, waits for old cleanup, and reads
        // again. Pause the third snapshot inside installation of fresh DNS.
        let (refreshing, resume) = platform.pause_snapshot(3);
        let context = probes.clone();
        let replacement = tokio::spawn(async move {
            context
                .probe(
                    probe_document(),
                    "platform-direct".into(),
                    "http://after-refresh.aerobox-test.example/".into(),
                    30000,
                )
                .await
        });
        refreshing.await.unwrap();
        let mut shutdown = std::pin::pin!(probes.shutdown());
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(shutdown.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        resume.send(()).unwrap();
        shutdown.await;
        assert!(old.await.unwrap().is_err());
        assert!(replacement.await.unwrap().is_err());
        assert_eq!(platform.active.load(Ordering::SeqCst), 0);
        assert_eq!(platform.count(2, "after-refresh.aerobox-test.example"), 0);
        let error = probes
            .probe(
                probe_document(),
                "platform-direct".into(),
                "http://after-shutdown.aerobox-test.example/".into(),
                3000,
            )
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert_eq!(platform.count(2, "after-shutdown.aerobox-test.example"), 0);
    })
    .await
    .expect("standalone shutdown raced network refresh indefinitely");
}
