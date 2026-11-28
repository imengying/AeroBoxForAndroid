//! Physical network selection is independent of DNS address-family racing.
//! Only connected TCP carriers compete; UDP selects one successfully bound
//! socket before any datagram is sent.
use std::sync::atomic::{AtomicU64, Ordering};
use std::{fmt, future::Future, io, sync::Arc, time::Duration};

use futures::{StreamExt, stream::FuturesUnordered};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use tokio::time::Instant;

use crate::embedding::{PhysicalNetworkKind, PhysicalNetworkSnapshot, Platform};

const FALLBACK_DELAY: Duration = Duration::from_millis(300);
const FAST_FALLBACK_WINDOW: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkStrategy {
    #[default]
    Default,
    Hybrid,
    Fallback,
}

/// A lease ties handles to one host instance. Retiring it waits for any
/// synchronous callback already in progress, then rejects every stale binding.
pub(crate) struct PlatformNetworks {
    identity: u64,
    platform: RwLock<Option<Arc<dyn Platform>>>,
}
static CURRENT: RwLock<Option<Arc<PlatformNetworks>>> = RwLock::new(None);
static NEXT_CONTEXT: AtomicU64 = AtomicU64::new(1);

impl fmt::Debug for PlatformNetworks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PlatformNetworks").finish_non_exhaustive()
    }
}
impl PlatformNetworks {
    fn new(platform: Arc<dyn Platform>) -> io::Result<Arc<Self>> {
        let identity = NEXT_CONTEXT
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| io::Error::other("physical network context identifiers exhausted"))?;
        Ok(Arc::new(Self {
            identity,
            platform: RwLock::new(Some(platform)),
        }))
    }
    pub(crate) fn install(platform: Arc<dyn Platform>) -> io::Result<Arc<Self>> {
        let this = Self::new(platform)?;
        *CURRENT.write() = Some(this.clone());
        Ok(this)
    }
    pub(crate) fn retire(self: &Arc<Self>) {
        {
            let mut current = CURRENT.write();
            if current
                .as_ref()
                .is_some_and(|value| Arc::ptr_eq(value, self))
            {
                current.take();
            }
        }
        self.platform.write().take();
    }
    fn snapshot(&self) -> io::Result<PhysicalNetworkSnapshot> {
        let guard = self.platform.read();
        let snapshot = guard.as_ref().ok_or_else(retired)?.physical_networks()?;
        snapshot.validate()?;
        Ok(snapshot)
    }
}
fn retired() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotConnected,
        "physical network context has retired",
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct NetworkKey {
    context: u64,
    pub generation: u64,
    pub handle: u64,
}
impl NetworkKey {
    pub(crate) fn is_older_than(self, other: Self) -> bool {
        self.context < other.context
            || (self.context == other.context && self.generation < other.generation)
    }
    pub(crate) fn same_snapshot(self, other: Self) -> bool {
        self.context == other.context && self.generation == other.generation
    }
}

#[derive(Debug, Clone)]
pub(crate) struct NetworkBinding {
    source: Arc<PlatformNetworks>,
    key: NetworkKey,
}
impl NetworkBinding {
    pub(crate) fn key(&self) -> NetworkKey {
        self.key
    }
    pub(crate) fn protect(&self, fd: i32) -> io::Result<()> {
        let guard = self.source.platform.read();
        guard.as_ref().ok_or_else(retired)?.protect_on_network(
            fd,
            self.key.generation,
            self.key.handle,
        )
    }
}

#[derive(Debug, Default)]
struct FastFallback {
    key: Option<NetworkKey>,
    started: Option<Instant>,
}

#[derive(Debug)]
pub(crate) struct NetworkPolicy {
    #[cfg(test)]
    source: Option<Arc<PlatformNetworks>>,
    enabled: bool,
    strategy: NetworkStrategy,
    preferred: Vec<PhysicalNetworkKind>,
    fallback: Vec<PhysicalNetworkKind>,
    delay: Duration,
    fast: Arc<Mutex<FastFallback>>,
}

struct Plan {
    primary: Vec<NetworkBinding>,
    fallback: Vec<NetworkBinding>,
}

impl NetworkPolicy {
    pub(crate) fn new(options: &crate::dial_options::DialOptions) -> Self {
        Self {
            #[cfg(test)]
            source: None,
            enabled: options.has_network_policy(),
            strategy: options.network_strategy.unwrap_or_default(),
            preferred: options.network_type.clone(),
            fallback: options.fallback_network_type.clone(),
            delay: options
                .fallback_delay
                .map(|d| d.0)
                .filter(|d| !d.is_zero())
                .unwrap_or(FALLBACK_DELAY),
            fast: Arc::default(),
        }
    }
    pub(crate) fn enabled(&self) -> bool {
        self.enabled
    }

    #[cfg(test)]
    pub(crate) fn with_platform(
        options: &crate::dial_options::DialOptions,
        platform: Arc<dyn Platform>,
    ) -> Self {
        let mut this = Self::new(options);
        this.source = Some(PlatformNetworks::new(platform).unwrap());
        this
    }

    fn plan(&self) -> io::Result<Plan> {
        #[cfg(test)]
        if let Some(source) = &self.source {
            return self.plan_with(source.clone());
        }
        let source = CURRENT.read().clone().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "network strategy requires physical-network platform callbacks",
            )
        })?;
        self.plan_with(source)
    }

    fn plan_with(&self, source: Arc<PlatformNetworks>) -> io::Result<Plan> {
        let snapshot = source.snapshot()?;
        let mut primary = Vec::new();
        let mut fallback = Vec::new();
        for network in &snapshot.networks {
            let preferred = if !self.preferred.is_empty() {
                self.preferred.contains(&network.kind)
            } else {
                self.strategy == NetworkStrategy::Hybrid
                    || snapshot.default_handle.is_none()
                    || snapshot.default_handle == Some(network.handle)
            };
            let binding = NetworkBinding {
                key: NetworkKey {
                    context: source.identity,
                    generation: snapshot.generation,
                    handle: network.handle,
                },
                source: source.clone(),
            };
            if preferred {
                primary.push(binding);
            } else if self.strategy == NetworkStrategy::Fallback
                && (self.fallback.is_empty() || self.fallback.contains(&network.kind))
            {
                // Overlapping type filters must not dial the same network twice.
                fallback.push(binding);
            }
        }
        if primary.is_empty() && fallback.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NetworkUnreachable,
                "no physical network matches the outbound policy",
            ));
        }
        Ok(Plan { primary, fallback })
    }

    /// UDP and QUIC bind serially. A successful bind commits to that network;
    /// no application datagram is used to race or probe other candidates.
    pub(crate) fn udp<T>(
        &self,
        mut create: impl FnMut(Option<&NetworkBinding>) -> io::Result<T>,
    ) -> io::Result<T> {
        if !self.enabled {
            return create(None);
        }
        Self::udp_plan(self.plan()?, &mut create)
    }
    fn udp_plan<T>(
        plan: Plan,
        mut create: impl FnMut(Option<&NetworkBinding>) -> io::Result<T>,
    ) -> io::Result<T> {
        let mut error = retired();
        for binding in plan.primary.iter().chain(&plan.fallback) {
            match create(Some(binding)) {
                Ok(socket) => return Ok(socket),
                Err(failure) => error = failure,
            }
        }
        Err(error)
    }

    pub(crate) async fn tcp<T, F>(
        &self,
        deadline: Instant,
        mut connect: impl FnMut(Option<NetworkBinding>) -> F,
    ) -> io::Result<T>
    where
        T: Send + 'static,
        F: Future<Output = io::Result<T>> + Send + 'static,
    {
        if !self.enabled {
            return connect(None).await;
        }
        self.tcp_plan(self.plan()?, deadline, connect).await
    }

    async fn tcp_plan<T, F>(
        &self,
        plan: Plan,
        deadline: Instant,
        mut connect: impl FnMut(Option<NetworkBinding>) -> F,
    ) -> io::Result<T>
    where
        T: Send + 'static,
        F: Future<Output = io::Result<T>> + Send + 'static,
    {
        let started = Instant::now();
        let key = plan
            .primary
            .first()
            .or_else(|| plan.fallback.first())
            .unwrap()
            .key;
        let fast_started = {
            let mut fast = self.fast.lock();
            if fast.key.is_some_and(|old| key.is_older_than(old)) {
                return Err(retired());
            }
            if fast.key.is_none_or(|old| !old.same_snapshot(key)) {
                *fast = FastFallback {
                    key: Some(key),
                    started: None,
                };
            }
            fast.started
                .filter(|at| started.saturating_duration_since(*at) < FAST_FALLBACK_WINDOW)
        };
        let fast_mode = fast_started.is_some();
        let mut primary: FuturesUnordered<_> = plan
            .primary
            .into_iter()
            .map(|binding| connect(Some(binding)))
            .collect();
        let mut pending = Some(plan.fallback);
        let mut fallback = FuturesUnordered::new();
        let mut launch = fast_mode || primary.is_empty();
        let delay_until = started
            .checked_add(self.delay)
            .unwrap_or(deadline)
            .min(deadline);
        let mut error = io::Error::new(
            io::ErrorKind::NetworkUnreachable,
            "all physical networks failed",
        );
        loop {
            if launch {
                for binding in pending.take().unwrap_or_default() {
                    fallback.push(connect(Some(binding)));
                }
                launch = false;
            }
            if primary.is_empty() && fallback.is_empty() && pending.is_none() {
                return Err(error);
            }
            tokio::select! {
                biased;
                result = primary.next(), if !primary.is_empty() => {
                    match result.unwrap() {
                        Ok(stream) => {
                            if fast_mode && Instant::now() <= delay_until {
                                clear_fast(&self.fast, key, fast_started);
                            }
                            return Ok(stream);
                        }
                        Err(failure) => { error = failure; launch = pending.is_some(); }
                    }
                }
                result = fallback.next(), if !fallback.is_empty() => {
                    match result.unwrap() {
                        Ok(stream) => {
                            if !fast_mode {
                                let mut fast = self.fast.lock();
                                if fast.key.is_some_and(|old| old.same_snapshot(key)) {
                                    fast.started = Some(Instant::now());
                                }
                            } else if !primary.is_empty() && Instant::now() < delay_until {
                                // Match the upstream recovery observation, bounded by the
                                // original deadline and owned by the network lifetime.
                                let state = self.fast.clone();
                                crate::network_tasks::spawn(async move {
                                    let observe = async {
                                        while let Some(result) = primary.next().await {
                                            if let Ok(stream) = result {
                                                drop(stream);
                                                // timeout_at polls its inner future first, so
                                                // an already-ready late result still needs a
                                                // wall-clock check before changing recovery state.
                                                if Instant::now() <= delay_until {
                                                    clear_fast(&state, key, fast_started);
                                                }
                                                break;
                                            }
                                        }
                                    };
                                    let _ = tokio::time::timeout_at(delay_until, observe).await;
                                });
                            }
                            return Ok(stream);
                        }
                        Err(failure) => error = failure,
                    }
                }
                _ = tokio::time::sleep_until(delay_until), if pending.is_some() => launch = true,
                _ = tokio::time::sleep_until(deadline) => return Err(io::Error::new(
                    io::ErrorKind::TimedOut, "physical network connect timeout")),
            }
        }
    }
}

fn clear_fast(state: &Mutex<FastFallback>, key: NetworkKey, started: Option<Instant>) {
    let mut state = state.lock();
    if state.key.is_some_and(|old| old.same_snapshot(key)) && state.started == started {
        state.started = None;
    }
}

#[cfg(test)]
pub(crate) mod tests;
