use super::*;
use crate::{
    address::NetLocation,
    control::flows::{FlowContext, FlowInfo, FlowRegistry},
};
use std::sync::{
    Condvar, Mutex as StdMutex,
    atomic::{AtomicUsize, Ordering},
};
static TEST_GATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
struct Mock {
    calls: Mutex<Vec<ConnectionOwnerQuery>>,
    release: (StdMutex<bool>, Condvar),
    started: AtomicUsize,
    finished: AtomicUsize,
    changed: tokio::sync::Notify,
    invalid: bool,
}
impl Mock {
    fn new(block: bool, invalid: bool) -> Arc<Self> {
        Arc::new(Self {
            calls: Default::default(),
            release: (StdMutex::new(!block), Condvar::new()),
            started: AtomicUsize::new(0),
            finished: AtomicUsize::new(0),
            changed: tokio::sync::Notify::new(),
            invalid,
        })
    }
    fn open(&self) {
        *self.release.0.lock().unwrap() = true;
        self.release.1.notify_all();
    }
    async fn started(&self, count: usize) {
        tokio::time::timeout(Duration::from_secs(3), async {
            while self.started.load(Ordering::SeqCst) < count {
                self.changed.notified().await;
            }
        })
        .await
        .unwrap();
    }
    async fn drained(&self, count: usize) {
        tokio::time::timeout(Duration::from_secs(3), async {
            while self.finished.load(Ordering::SeqCst) < count
                || CAPACITY
                    .get()
                    .is_some_and(|s| s.available_permits() != MAX_PENDING)
            {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
    }
    fn context(self: &Arc<Self>) -> Arc<OwnerContext> {
        Arc::new(OwnerContext {
            platform: self.clone(),
            cancelled: CancellationToken::new(),
        })
    }
}
impl Drop for Mock {
    fn drop(&mut self) {
        *self.release.0.lock().unwrap() = true;
        self.release.1.notify_all();
    }
}
impl Platform for Mock {
    fn protect(&self, _: i32) -> io::Result<()> {
        Ok(())
    }
    fn dns_servers(&self) -> io::Result<Vec<SocketAddr>> {
        Ok(vec![])
    }
    fn connection_owner(&self, query: ConnectionOwnerQuery) -> io::Result<Option<ConnectionOwner>> {
        self.calls.lock().push(query);
        self.started.fetch_add(1, Ordering::SeqCst);
        self.changed.notify_one();
        let mut released = self.release.0.lock().unwrap();
        while !*released {
            released = self.release.1.wait(released).unwrap();
        }
        self.finished.fetch_add(1, Ordering::SeqCst);
        if self.invalid {
            return Ok(Some(ConnectionOwner {
                uid: 1,
                packages: vec!["bad/package".into()],
            }));
        }
        Ok(Some(ConnectionOwner {
            uid: 10042,
            packages: vec!["z.shared".into(), "a.shared".into(), "z.shared".into()],
        }))
    }
}
fn query(protocol: u8, v6: bool) -> ConnectionOwnerQuery {
    ConnectionOwnerQuery {
        ip_protocol: protocol,
        source: if v6 {
            "[fd00::2]:12345"
        } else {
            "172.19.0.2:12345"
        }
        .parse()
        .unwrap(),
        destination: if v6 {
            "[fd00:198:18::8]:443"
        } else {
            "198.18.0.8:443"
        }
        .parse()
        .unwrap(),
    }
}
async fn lookup_default(
    context: Arc<OwnerContext>,
    query: ConnectionOwnerQuery,
) -> Option<ConnectionOwner> {
    lookup(
        context,
        query,
        CancellationToken::new(),
        CancellationToken::new(),
        Duration::from_secs(2),
    )
    .await
}

#[test]
fn owner_json_rejects_oversized_or_ambiguous_attribution() {
    assert_eq!(ConnectionOwner::from_json("null").unwrap(), None);
    let owner = ConnectionOwner::from_json(r#"{"uid":123,"packages":["z.app","a.app","z.app"]}"#)
        .unwrap()
        .unwrap();
    assert_eq!(owner.packages, ["a.app", "z.app"]);
    for value in [
        serde_json::json!({"uid":-1,"packages":[]}),
        serde_json::json!({"uid":4294967296u64,"packages":[]}),
        serde_json::json!({"uid":1,"packages":[""]}),
        serde_json::json!({"uid":1,"packages":["a..b"]}),
        serde_json::json!({"uid":1,"packages":["a/b"]}),
        serde_json::json!({"uid":1,"packages":["a.1b"]}),
        serde_json::json!({"uid":1,"packages":["a.非"]}),
        serde_json::json!({"uid":1,"packages":vec!["a.b";65]}),
        serde_json::json!({"uid":1,"packages":[],"unexpected":1}),
    ] {
        assert!(
            ConnectionOwner::from_json(&value.to_string()).is_err(),
            "{value}"
        );
    }
    assert!(ConnectionOwner::from_json(&" ".repeat(32769)).is_err());
    assert!(ConnectionOwner::from_json(r#"{"uid":0,"packages":["a.$bad"]}"#).is_err());
    assert!(ConnectionOwner::from_json(r#"{"uid":0,"packages":["a.B$Inner"]}"#).is_ok());
}

#[tokio::test]
async fn tcp_udp_ipv4_ipv6_use_original_tuple_and_preserve_shared_uid() {
    let _gate = TEST_GATE.lock().await;
    let platform = Mock::new(false, false);
    for protocol in [6, 17] {
        for v6 in [false, true] {
            let tuple = query(protocol, v6);
            let owner = lookup_default(platform.context(), tuple).await.unwrap();
            assert_eq!(owner.uid, 10042);
            assert_eq!(owner.packages, ["a.shared", "z.shared"]);
            assert_eq!(platform.calls.lock().last(), Some(&tuple));
        }
    }
    let invalid = Mock::new(false, true);
    assert!(
        lookup_default(invalid.context(), query(6, false))
            .await
            .is_none()
    );
    let mut bad = query(1, false);
    assert!(lookup_default(platform.context(), bad).await.is_none());
    bad.ip_protocol = 6;
    bad.source.set_port(0);
    assert!(lookup_default(platform.context(), bad).await.is_none());
    assert_eq!(platform.calls.lock().len(), 4);
}

#[tokio::test]
async fn timeout_retains_blocking_capacity_and_cancelled_work_cannot_spawn_more() {
    let _gate = TEST_GATE.lock().await;
    let platform = Mock::new(true, false);
    let context = platform.context();
    let mut tasks = Vec::new();
    for _ in 0..MAX_PENDING {
        let context = context.clone();
        tasks.push(tokio::spawn(lookup(
            context,
            query(6, false),
            CancellationToken::new(),
            CancellationToken::new(),
            Duration::from_millis(100),
        )));
    }
    platform.started(MAX_PENDING).await;
    for task in tasks {
        assert!(task.await.unwrap().is_none());
    }
    assert!(
        lookup_default(context.clone(), query(17, true))
            .await
            .is_none()
    );
    assert_eq!(platform.started.load(Ordering::SeqCst), MAX_PENDING);
    platform.open();
    platform.drained(MAX_PENDING).await;
    assert!(
        lookup_default(context.clone(), query(17, true))
            .await
            .is_some()
    );
    context.cancelled.cancel();
    assert!(lookup_default(context, query(6, false)).await.is_none());
    assert_eq!(platform.started.load(Ordering::SeqCst), MAX_PENDING + 1);
}

fn flow(context: &FlowContext, owner: Option<FlowOwner>) -> crate::control::flows::FlowGuard {
    context.register(
        "tcp",
        &NetLocation::from_str("real.example:8443", None)
            .unwrap()
            .into(),
        vec!["proxy".into()],
        "all",
        FlowInfo {
            owner,
            source: Some(query(6, false).source),
            original: Some(NetLocation::from_str("198.18.0.8:443", None).unwrap()),
            ..Default::default()
        },
    )
}

#[tokio::test]
async fn closed_flow_and_retired_host_reject_late_results_even_when_port_is_reused() {
    let _gate = TEST_GATE.lock().await;
    let platform = Mock::new(true, false);
    let owner_context = platform.context();
    let context = FlowContext {
        registry: Arc::new(FlowRegistry::default()),
        generation: 1,
        inbound: "tun".into(),
        scope: "root".into(),
        protocol: "Tun".into(),
    };
    let old = flow(
        &context,
        Some(FlowOwner::with_context(
            owner_context.clone(),
            query(6, false),
        )),
    );
    platform.started(1).await;
    drop(old);
    let fresh = flow(&context, None);
    owner_context.cancelled.cancel();
    platform.open();
    platform.drained(1).await;
    assert!(fresh.entry.owner.snapshot().is_none());
    assert!(
        context.registry.snapshot(0).connections[0]
            .metadata
            .uid
            .is_none()
    );
    let context2 = platform.context();
    drop(fresh);
    let fresh = flow(
        &context,
        Some(FlowOwner::with_context(context2, query(6, false))),
    );
    tokio::time::timeout(Duration::from_secs(3), async {
        while fresh.entry.owner.snapshot().is_none() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
    let snapshot = context.registry.snapshot(0);
    let metadata = &snapshot.connections[0].metadata;
    assert_eq!(metadata.uid, Some(10042));
    assert_eq!(metadata.packages, ["a.shared", "z.shared"]);
    assert_eq!(metadata.process, "a.shared");
    assert!(metadata.process_path.is_empty());
    assert_eq!(metadata.shoes_original_destination, "198.18.0.8:443");
    assert_eq!(metadata.remote_destination, "real.example:8443");
}
