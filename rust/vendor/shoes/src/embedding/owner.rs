//! Bounded best-effort attribution of original TUN tuples. No tuple cache and
//! no platform Binder work on network workers or under lifecycle locks.
use super::Platform;
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use std::{
    io,
    net::SocketAddr,
    sync::{Arc, OnceLock},
    time::Duration,
};
use tokio::{sync::Semaphore, time::Instant};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectionOwnerQuery {
    pub ip_protocol: u8,
    pub source: SocketAddr,
    pub destination: SocketAddr,
}
impl ConnectionOwnerQuery {
    pub fn validate(&self) -> io::Result<()> {
        if !matches!(self.ip_protocol, 6 | 17)
            || self.source.port() == 0
            || self.destination.port() == 0
            || self.source.is_ipv4() != self.destination.is_ipv4()
            || self.source.ip().is_unspecified()
            || self.destination.ip().is_unspecified()
            || self.source.ip().is_multicast()
            || self.destination.ip().is_multicast()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid connection owner tuple",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionOwner {
    pub uid: u32,
    pub packages: Vec<String>,
}
impl ConnectionOwner {
    pub fn from_json(json: &str) -> io::Result<Option<Self>> {
        if json.len() > 32768 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "connection owner JSON exceeds limit",
            ));
        }
        let owner: Option<Self> = serde_json::from_str(json)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        owner.map(Self::validated).transpose()
    }
    pub(crate) fn validated(mut self) -> io::Result<Self> {
        if self.packages.len() > 64
            || self.packages.iter().any(|name| {
                name.is_empty()
                    || name.len() > 255
                    || !name.split('.').all(|part| {
                        let mut bytes = part.bytes();
                        bytes
                            .next()
                            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
                            && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'$')
                    })
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid connection owner package list",
            ));
        }
        self.packages.sort_unstable();
        self.packages.dedup();
        Ok(self)
    }
}

#[derive(Debug, Default)]
struct State {
    value: Mutex<Option<ConnectionOwner>>,
    cancelled: CancellationToken,
}

/// One lookup follows an inlet through preparation, routing and connection
/// setup into its registered flow. Dropping any failed/cancelled stage retires it.
#[derive(Debug, Default)]
pub(crate) struct FlowOwner {
    state: Arc<State>,
}
impl FlowOwner {
    pub(crate) fn start(query: ConnectionOwnerQuery) -> Self {
        let context = CURRENT.read().clone();
        match context {
            Some(context) => Self::with_context(context, query),
            None => Self::default(),
        }
    }
    fn with_context(context: Arc<OwnerContext>, query: ConnectionOwnerQuery) -> Self {
        let this = Self::default();
        let state = Arc::downgrade(&this.state);
        let cancelled = this.state.cancelled.clone();
        let deadline = Instant::now() + TIMEOUT;
        crate::network_tasks::spawn(async move {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return;
            };
            let result = lookup(
                context,
                query,
                cancelled.clone(),
                CancellationToken::new(),
                remaining,
            )
            .await;
            if let (Some(owner), Some(state)) = (result, state.upgrade()) {
                if !cancelled.is_cancelled() {
                    *state.value.lock() = Some(owner);
                }
            }
        });
        this
    }
    pub(crate) fn snapshot(&self) -> Option<ConnectionOwner> {
        self.state.value.lock().clone()
    }
    pub(crate) fn close(&self) {
        self.state.cancelled.cancel();
    }
}
impl Drop for FlowOwner {
    fn drop(&mut self) {
        self.close();
    }
}

pub(crate) struct OwnerContext {
    platform: Arc<dyn Platform>,
    cancelled: CancellationToken,
}
static CURRENT: RwLock<Option<Arc<OwnerContext>>> = RwLock::new(None);
static CAPACITY: OnceLock<Arc<Semaphore>> = OnceLock::new();
const MAX_PENDING: usize = 4;
const TIMEOUT: Duration = Duration::from_millis(50);
impl OwnerContext {
    pub(crate) fn install(platform: Arc<dyn Platform>) -> Arc<Self> {
        let this = Arc::new(Self {
            platform,
            cancelled: CancellationToken::new(),
        });
        *CURRENT.write() = Some(this.clone());
        this
    }
    pub(crate) fn retire(self: &Arc<Self>) {
        self.cancelled.cancel();
        let mut current = CURRENT.write();
        if current.as_ref().is_some_and(|c| Arc::ptr_eq(c, self)) {
            current.take();
        }
    }
}

async fn lookup(
    context: Arc<OwnerContext>,
    query: ConnectionOwnerQuery,
    cancelled: CancellationToken,
    flow_cancelled: CancellationToken,
    timeout: Duration,
) -> Option<ConnectionOwner> {
    query.validate().ok()?;
    if context.cancelled.is_cancelled() || cancelled.is_cancelled() || flow_cancelled.is_cancelled()
    {
        return None;
    }
    let permit = CAPACITY
        .get_or_init(|| Arc::new(Semaphore::new(MAX_PENDING)))
        .clone()
        .try_acquire_owned()
        .ok()?;
    let deadline = Instant::now() + timeout;
    let platform = context.platform.clone();
    let host_cancelled = context.cancelled.clone();
    let worker_cancelled = cancelled.child_token();
    // Aborting a network task also invalidates work still queued in the
    // blocking pool. Already-running Binder calls retain the capacity permit.
    let _dispatch = worker_cancelled.clone().drop_guard();
    let worker_flow_cancelled = flow_cancelled.clone();
    let worker = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        // Queued work may have expired before a blocking worker becomes free.
        if Instant::now() >= deadline
            || host_cancelled.is_cancelled()
            || worker_cancelled.is_cancelled()
            || worker_flow_cancelled.is_cancelled()
        {
            return None;
        }
        platform
            .connection_owner(query)
            .ok()
            .flatten()?
            .validated()
            .ok()
    });
    let result = tokio::select! {
        biased;
        _ = context.cancelled.cancelled() => None,
        _ = cancelled.cancelled() => None,
        _ = flow_cancelled.cancelled() => None,
        result = tokio::time::timeout_at(deadline, worker) => result.ok()?.ok()?,
    };
    if Instant::now() >= deadline
        || context.cancelled.is_cancelled()
        || cancelled.is_cancelled()
        || flow_cancelled.is_cancelled()
    {
        return None;
    }
    result
}

#[cfg(test)]
#[path = "owner_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "owner_ingress_tests.rs"]
mod ingress_tests;
