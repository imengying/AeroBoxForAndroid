use super::*;
use crate::{
    dial_options::{DialDuration, DialOptions},
    embedding::PhysicalNetwork,
};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug)]
pub(crate) struct Host {
    pub(crate) snapshot: Mutex<PhysicalNetworkSnapshot>,
    pub(crate) bound: Mutex<Vec<u64>>,
    reject: Vec<u64>,
}
impl Platform for Host {
    fn protect(&self, _: i32) -> io::Result<()> {
        panic!("selected sockets must not bind to the default network first")
    }
    fn dns_servers(&self) -> io::Result<Vec<std::net::SocketAddr>> {
        Ok(vec![])
    }
    fn physical_networks(&self) -> io::Result<PhysicalNetworkSnapshot> {
        Ok(self.snapshot.lock().clone())
    }
    fn protect_on_network(&self, _: i32, generation: u64, handle: u64) -> io::Result<()> {
        let current = self.snapshot.lock();
        self.bound.lock().push(handle);
        if generation != current.generation || !current.networks.iter().any(|n| n.handle == handle)
        {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "stale network"));
        }
        if self.reject.contains(&handle) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "network denied",
            ));
        }
        Ok(())
    }
}
pub(crate) fn make_host(reject: Vec<u64>) -> Arc<Host> {
    Arc::new(Host {
        snapshot: Mutex::new(PhysicalNetworkSnapshot {
            generation: 7,
            default_handle: Some(1),
            networks: [
                PhysicalNetworkKind::Wifi,
                PhysicalNetworkKind::Cellular,
                PhysicalNetworkKind::Ethernet,
            ]
            .into_iter()
            .enumerate()
            .map(|(i, kind)| PhysicalNetwork {
                handle: i as u64 + 1,
                kind,
                interface: format!("if{i}"),
                dns: vec![],
            })
            .collect(),
        }),
        bound: Mutex::new(vec![]),
        reject,
    })
}
fn options(strategy: NetworkStrategy) -> DialOptions {
    DialOptions {
        network_strategy: Some(strategy),
        ..Default::default()
    }
}
fn handles(plan: &Plan) -> (Vec<u64>, Vec<u64>) {
    (
        plan.primary.iter().map(|n| n.key.handle).collect(),
        plan.fallback.iter().map(|n| n.key.handle).collect(),
    )
}

#[test]
fn selection_matches_the_android_version_and_never_duplicates_a_network() {
    let host = make_host(vec![]);
    for (strategy, expected) in [
        (NetworkStrategy::Default, (vec![1], vec![])),
        (NetworkStrategy::Hybrid, (vec![1, 2, 3], vec![])),
        (NetworkStrategy::Fallback, (vec![1], vec![2, 3])),
    ] {
        let mut config = options(strategy);
        assert_eq!(
            handles(
                &NetworkPolicy::with_platform(&config, host.clone())
                    .plan()
                    .unwrap()
            ),
            expected
        );
        config.network_type = vec![PhysicalNetworkKind::Wifi, PhysicalNetworkKind::Cellular];
        config.fallback_network_type =
            vec![PhysicalNetworkKind::Cellular, PhysicalNetworkKind::Ethernet];
        let policy = NetworkPolicy::with_platform(&config, host.clone());
        assert_eq!(
            handles(&policy.plan().unwrap()),
            (
                vec![1, 2],
                if strategy == NetworkStrategy::Fallback {
                    vec![3]
                } else {
                    vec![]
                }
            )
        );
    }
    host.snapshot.lock().default_handle = None;
    let policy = NetworkPolicy::with_platform(&options(NetworkStrategy::Fallback), host.clone());
    assert_eq!(handles(&policy.plan().unwrap()), (vec![1, 2, 3], vec![]));
    let config = DialOptions {
        network_type: vec![PhysicalNetworkKind::Other],
        ..options(NetworkStrategy::Default)
    };
    assert!(
        NetworkPolicy::with_platform(&config, host.clone())
            .plan()
            .is_err()
    );
    host.snapshot.lock().networks.clear();
    assert!(policy.plan().is_err());
}

#[test]
fn udp_tries_only_binding_failures_and_never_the_default_protector() {
    let host = make_host(vec![1]);
    let policy = NetworkPolicy::with_platform(&options(NetworkStrategy::Fallback), host.clone());
    let handle = policy
        .udp(|binding| {
            let binding = binding.unwrap();
            binding.protect(123)?;
            Ok(binding.key.handle)
        })
        .unwrap();
    assert_eq!(handle, 2);
    assert_eq!(*host.bound.lock(), vec![1, 2]);
    let rejected = make_host(vec![1, 2, 3]);
    let policy = NetworkPolicy::with_platform(&options(NetworkStrategy::Hybrid), rejected.clone());
    assert_eq!(
        policy
            .udp(|binding| binding.unwrap().protect(123))
            .unwrap_err()
            .kind(),
        io::ErrorKind::PermissionDenied
    );
    assert_eq!(*rejected.bound.lock(), vec![1, 2, 3]);
}

#[test]
fn bindings_do_not_survive_snapshot_changes_or_host_retirement() {
    let host = make_host(vec![]);
    let policy = NetworkPolicy::with_platform(&options(NetworkStrategy::Default), host.clone());
    let binding = policy.plan().unwrap().primary.remove(0);
    binding.protect(123).unwrap();
    host.snapshot.lock().generation += 1;
    assert_eq!(
        binding.protect(123).unwrap_err().kind(),
        io::ErrorKind::NotConnected
    );
    let fresh = policy.plan().unwrap().primary.remove(0);
    fresh.protect(123).unwrap();
    policy.source.as_ref().unwrap().retire();
    assert_eq!(
        fresh.protect(123).unwrap_err().kind(),
        io::ErrorKind::NotConnected
    );
    assert!(policy.plan().is_err());
}

struct PendingGuard(Arc<AtomicUsize>);
impl PendingGuard {
    fn new(count: Arc<AtomicUsize>) -> Self {
        count.fetch_add(1, Ordering::SeqCst);
        Self(count)
    }
}
impl Drop for PendingGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[tokio::test(start_paused = true)]
async fn fallback_starts_after_delay_and_cancels_losing_connections() {
    let policy =
        NetworkPolicy::with_platform(&options(NetworkStrategy::Fallback), make_host(vec![]));
    let active = Arc::new(AtomicUsize::new(0));
    let start = Instant::now();
    let result = policy
        .tcp(start + Duration::from_secs(10), |network| {
            let active = active.clone();
            async move {
                let _guard = PendingGuard::new(active);
                let handle = network.unwrap().key.handle;
                if handle == 2 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    Ok(handle)
                } else {
                    std::future::pending().await
                }
            }
        })
        .await
        .unwrap();
    assert_eq!(result, 2);
    assert_eq!(Instant::now() - start, Duration::from_millis(310));
    assert_eq!(active.load(Ordering::SeqCst), 0);
    assert!(policy.fast.lock().started.is_some());
}

#[tokio::test(start_paused = true)]
async fn any_primary_failure_starts_fallback_without_waiting_for_other_primaries() {
    let mut config = options(NetworkStrategy::Fallback);
    config.network_type = vec![PhysicalNetworkKind::Wifi, PhysicalNetworkKind::Cellular];
    let policy = NetworkPolicy::with_platform(&config, make_host(vec![]));
    let started = Instant::now();
    let result = policy
        .tcp(started + Duration::from_secs(10), |network| async move {
            match network.unwrap().key.handle {
                1 => {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                    Err(io::Error::other("primary refused"))
                }
                2 => std::future::pending().await,
                handle => Ok(handle),
            }
        })
        .await
        .unwrap();
    assert_eq!(result, 3);
    assert_eq!(Instant::now() - started, Duration::from_millis(25));
}

#[tokio::test(start_paused = true)]
async fn default_type_filter_and_hybrid_race_every_selected_primary() {
    for strategy in [NetworkStrategy::Default, NetworkStrategy::Hybrid] {
        let mut config = options(strategy);
        config.network_type = vec![PhysicalNetworkKind::Wifi, PhysicalNetworkKind::Cellular];
        let policy = NetworkPolicy::with_platform(&config, make_host(vec![]));
        let started = Instant::now();
        assert_eq!(
            policy
                .tcp(started + Duration::from_secs(10), |network| async move {
                    let handle = network.unwrap().key.handle;
                    if handle == 1 {
                        std::future::pending::<()>().await;
                    }
                    Ok(handle)
                })
                .await
                .unwrap(),
            2
        );
        assert_eq!(Instant::now(), started);
    }
}

#[tokio::test(start_paused = true)]
async fn absent_primary_does_not_delay_fallback_and_deadline_cancels_all_attempts() {
    let mut config = options(NetworkStrategy::Fallback);
    config.network_type = vec![PhysicalNetworkKind::Other];
    let policy = NetworkPolicy::with_platform(&config, make_host(vec![]));
    let started = Instant::now();
    policy
        .tcp(started + Duration::from_secs(1), |_| async { Ok(()) })
        .await
        .unwrap();
    assert_eq!(Instant::now(), started);
    let active = Arc::new(AtomicUsize::new(0));
    let error = policy
        .tcp(started + Duration::from_secs(1), |_| {
            let active = active.clone();
            async move {
                let _guard = PendingGuard::new(active);
                std::future::pending::<io::Result<()>>().await
            }
        })
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(active.load(Ordering::SeqCst), 0);
    assert_eq!(Instant::now() - started, Duration::from_secs(1));
}

#[tokio::test(start_paused = true)]
async fn cancelling_a_dial_releases_both_network_groups() {
    let config = DialOptions {
        fallback_delay: Some(DialDuration(Duration::from_millis(5))),
        ..options(NetworkStrategy::Fallback)
    };
    let policy = NetworkPolicy::with_platform(&config, make_host(vec![]));
    let active = Arc::new(AtomicUsize::new(0));
    let future = policy.tcp(Instant::now() + Duration::from_secs(10), |_| {
        let active = active.clone();
        async move {
            let _guard = PendingGuard::new(active);
            std::future::pending::<io::Result<()>>().await
        }
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(50), future)
            .await
            .is_err()
    );
    assert_eq!(active.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn fast_fallback_expires_and_primary_recovery_is_tracked_and_bounded() {
    let host = make_host(vec![]);
    let policy = NetworkPolicy::with_platform(&options(NetworkStrategy::Fallback), host.clone());
    let deadline = Instant::now() + Duration::from_secs(30);
    let slow_primary = |network: Option<NetworkBinding>| async move {
        let handle = network.unwrap().key.handle;
        if handle == 1 {
            std::future::pending::<()>().await;
        }
        Ok(handle)
    };
    assert_eq!(policy.tcp(deadline, slow_primary).await.unwrap(), 2);
    let recorded = policy.fast.lock().started.unwrap();
    let lifetime = crate::network_tasks::NetworkLifetime::default();
    let active = Arc::new(AtomicUsize::new(0));
    lifetime
        .scope(async {
            assert_eq!(
                policy
                    .tcp(deadline, |network| {
                        let active = active.clone();
                        async move {
                            let _guard = PendingGuard::new(active);
                            let handle = network.unwrap().key.handle;
                            if handle == 1 {
                                tokio::time::sleep(Duration::from_millis(40)).await;
                            }
                            Ok(handle)
                        }
                    })
                    .await
                    .unwrap(),
                2
            );
        })
        .await;
    assert_eq!(Instant::now(), recorded);
    tokio::time::sleep(Duration::from_millis(50)).await;
    lifetime.cancel();
    lifetime.wait().await;
    assert_eq!(active.load(Ordering::SeqCst), 0);
    assert!(policy.fast.lock().started.is_none());
    policy.tcp(deadline, slow_primary).await.unwrap();
    tokio::time::sleep(FAST_FALLBACK_WINDOW).await;
    let started = Instant::now();
    policy.tcp(deadline, slow_primary).await.unwrap();
    assert_eq!(Instant::now() - started, FALLBACK_DELAY);
    host.snapshot.lock().generation += 1;
    let started = Instant::now();
    policy.tcp(deadline, slow_primary).await.unwrap();
    assert_eq!(Instant::now() - started, FALLBACK_DELAY);
}

#[test]
fn network_options_conflicts_and_duration_are_validated_before_socket_creation() {
    for strategy in [
        NetworkStrategy::Default,
        NetworkStrategy::Hybrid,
        NetworkStrategy::Fallback,
    ] {
        let mut config = options(strategy);
        assert!(config.validate_binding(Some("wlan0")).is_err());
        config.tcp_fast_open = true;
        assert!(config.validate().is_err());
    }
    for invalid in [
        serde_json::json!({"network_strategy":"unknown"}),
        serde_json::json!({"network_type":["bluetooth"]}),
        serde_json::json!({"fallback_delay":"-1ms"}),
    ] {
        assert!(serde_json::from_value::<DialOptions>(invalid).is_err());
    }
}

#[tokio::test(start_paused = true)]
async fn late_ready_primary_does_not_reset_the_fast_fallback_window() {
    let policy =
        NetworkPolicy::with_platform(&options(NetworkStrategy::Fallback), make_host(vec![]));
    let key = policy.plan().unwrap().primary[0].key;
    let started = Instant::now();
    *policy.fast.lock() = FastFallback {
        key: Some(key),
        started: Some(started),
    };
    let lifetime = crate::network_tasks::NetworkLifetime::default();
    let polls = Arc::new(AtomicUsize::new(0));
    let waker = Arc::new(Mutex::new(None::<std::task::Waker>));
    lifetime
        .scope(async {
            assert_eq!(
                policy
                    .tcp(started + Duration::from_secs(2), |network| {
                        let polls = polls.clone();
                        let waker = waker.clone();
                        let handle = network.unwrap().key.handle;
                        futures::future::poll_fn(move |cx| {
                            if handle == 1 && polls.fetch_add(1, Ordering::SeqCst) == 0 {
                                *waker.lock() = Some(cx.waker().clone());
                                std::task::Poll::Pending
                            } else {
                                std::task::Poll::Ready(Ok(handle))
                            }
                        })
                    })
                    .await
                    .unwrap(),
                2
            );
        })
        .await;
    // The observer first polls this ready result after its deadline. Tokio's
    // timeout polls inner work before the timer; that result must not reset state.
    waker.lock().take().unwrap().wake();
    tokio::time::advance(Duration::from_millis(350)).await;
    tokio::task::yield_now().await;
    lifetime.cancel();
    lifetime.wait().await;
    assert!(polls.load(Ordering::SeqCst) >= 2);
    assert_eq!(policy.fast.lock().started, Some(started));
}

#[tokio::test(start_paused = true)]
async fn an_old_host_cannot_replace_a_new_hosts_fast_fallback_state() {
    let config = options(NetworkStrategy::Default);
    let mut policy = NetworkPolicy::with_platform(&config, make_host(vec![]));
    let previous = policy.plan().unwrap();
    let previous_key = previous.primary[0].key;
    policy.source = Some(PlatformNetworks::new(make_host(vec![])).unwrap());
    let current_key = policy.plan().unwrap().primary[0].key;
    assert!(previous_key.is_older_than(current_key));
    let deadline = Instant::now() + Duration::from_secs(1);
    policy.tcp(deadline, |_| async { Ok(()) }).await.unwrap();
    let error = policy
        .tcp_plan(previous, deadline, |_| async {
            panic!("stale host attempted a new connection");
            #[allow(unreachable_code)]
            Ok(())
        })
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::NotConnected);
    assert_eq!(policy.fast.lock().key, Some(current_key));
}
