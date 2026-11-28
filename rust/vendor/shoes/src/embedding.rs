//! Controlled embedding API for the AeroBox host.
//!
//! Configuration is a JSON array of shoes `Config` values, not sing-box JSON.
//! The runtime owns duplicates of supplied TUN descriptors. Call `shutdown`
//! before destroying the Tokio runtime so connection cleanup can finish.

use crate::{config::Config, resolver::Resolver};
use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio::task::JoinHandle;
pub use tokio_util::sync::CancellationToken as StartCancellation;
mod network;
pub use network::{PhysicalNetwork, PhysicalNetworkKind, PhysicalNetworkSnapshot};
pub(crate) mod owner;
pub use owner::{ConnectionOwner, ConnectionOwnerQuery};
mod probe;
pub(crate) use probe::run as run_probe_document;
mod standalone;
pub use standalone::StandaloneProbes;

/// Exact physical-network identity for an asynchronous system DNS query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlatformNetwork {
    pub generation: u64,
    pub handle: u64,
}
#[derive(Debug)]
pub struct PlatformDnsQuery {
    pub network: PlatformNetwork,
    pub message: Vec<u8>,
    pub deadline: tokio::time::Instant,
}

/// Android must supply the current physical network's DNS servers and protect
/// every outgoing socket before connect/bind. Callbacks must not reenter the core.
pub trait Platform: Send + Sync + 'static {
    fn protect(&self, fd: i32) -> io::Result<()>;
    fn dns_servers(&self) -> io::Result<Vec<SocketAddr>>;

    /// Best-effort diagnostics. Called on a bounded blocking worker, never
    /// under lifecycle locks; unsupported platforms return an unknown owner.
    fn connection_owner(
        &self,
        _query: ConnectionOwnerQuery,
    ) -> io::Result<Option<ConnectionOwner>> {
        Ok(None)
    }

    fn supports_system_dns(&self) -> bool {
        false
    }
    /// The future must cancel the platform query on drop. Android's callback
    /// completion may reenter only its dedicated result dispatcher, never host APIs.
    fn exchange_system_dns(
        self: Arc<Self>,
        _query: PlatformDnsQuery,
    ) -> crate::resolver::DnsExchangeFuture {
        Box::pin(async {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "platform system DNS unavailable",
            ))
        })
    }

    /// One coherent non-VPN network inventory. Handles and generations are u64
    /// identifiers, never floating-point values. Explicit strategies fail when
    /// the host has no such capability; ordinary protect/DNS remain compatible.
    fn physical_networks(&self) -> io::Result<PhysicalNetworkSnapshot> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "platform does not expose physical networks",
        ))
    }

    /// Protect and bind a newly created, unconnected socket to a network from
    /// this exact inventory generation. A stale/missing handle must fail closed.
    /// This must not call the default protect callback first or switch DNS policy.
    fn protect_on_network(&self, _fd: i32, _generation: u64, _handle: u64) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "platform does not support explicit physical-network binding",
        ))
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Stats {
    pub upload_total: u64,
    pub download_total: u64,
    pub active_connections: usize,
}

type Reply<T> = oneshot::Sender<io::Result<T>>;
pub(crate) enum Command {
    Reload(Vec<Config>, Reply<()>),
    NetworkChanged(Reply<()>),
    Stats(Reply<Stats>),
    Connections(Reply<serde_json::Value>),
    Close(String, Reply<()>),
    UrlTest {
        name: String,
        url: String,
        timeout_ms: u64,
        reply: Reply<u16>,
    },
    ProbeDocument {
        configs: Vec<Config>,
        name: String,
        url: String,
        timeout_ms: u64,
        reply: Reply<u16>,
    },
    Shutdown(Reply<()>),
}

/// One running core. The backend's resource limits and Android socket callback
/// are process-wide, so starting a second instance returns `AlreadyExists`.
pub struct EmbeddedCore {
    commands: mpsc::Sender<Command>,
    task: Mutex<Option<JoinHandle<io::Result<()>>>>,
    running: Arc<AtomicBool>,
}

impl EmbeddedCore {
    pub fn parse_json(json: &str) -> io::Result<Vec<Config>> {
        serde_json::from_str(json)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
    }

    pub async fn check(configs: Vec<Config>) -> io::Result<()> {
        crate::process::check_embedded(configs).await
    }

    pub async fn check_json(json: &str) -> io::Result<()> {
        Self::check(Self::parse_json(json)?).await
    }

    /// Validate configuration and local files without fetching remote rules.
    /// Returned remote identifiers are fully validated only during start.
    pub async fn check_document(configs: Vec<Config>) -> io::Result<Vec<String>> {
        crate::process::check_embedded_document(configs).await
    }

    pub async fn start_json(json: &str, platform: Option<Arc<dyn Platform>>) -> io::Result<Self> {
        Self::start(Self::parse_json(json)?, platform).await
    }

    pub async fn start(
        configs: Vec<Config>,
        platform: Option<Arc<dyn Platform>>,
    ) -> io::Result<Self> {
        Self::start_cancellable(configs, platform, StartCancellation::new()).await
    }

    pub async fn start_cancellable(
        configs: Vec<Config>,
        platform: Option<Arc<dyn Platform>>,
        cancellation: StartCancellation,
    ) -> io::Result<Self> {
        let context = PlatformContext::acquire(platform)?;
        // JNI callers may have only a 1 MiB stack. Keep the nested preparation
        // and actor futures on the heap before entering their polling frames.
        let process = Box::pin(crate::process::EmbeddedProcess::start(
            configs,
            &context,
            &cancellation,
        ))
        .await?;
        let (commands, receiver) = mpsc::channel(32);
        let running = Arc::new(AtomicBool::new(true));
        let state = running.clone();
        let task = tokio::spawn(async move {
            struct RunningFlag(Arc<AtomicBool>);
            impl Drop for RunningFlag {
                fn drop(&mut self) {
                    self.0.store(false, Ordering::Release);
                }
            }
            let _running = RunningFlag(state);
            Box::pin(process.run(receiver, context)).await
        });
        Ok(Self {
            commands,
            task: Mutex::new(Some(task)),
            running,
        })
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }

    async fn request<T>(&self, make: impl FnOnce(Reply<T>) -> Command) -> io::Result<T> {
        let (reply, received) = oneshot::channel();
        self.commands
            .send(make(reply))
            .await
            .map_err(|_| stopped())?;
        received.await.map_err(|_| stopped())?
    }

    pub async fn reload(&self, configs: Vec<Config>) -> io::Result<()> {
        self.request(|reply| Command::Reload(configs, reply)).await
    }
    pub async fn reload_json(&self, json: &str) -> io::Result<()> {
        self.reload(Self::parse_json(json)?).await
    }
    pub async fn network_changed(&self) -> io::Result<()> {
        self.request(Command::NetworkChanged).await
    }
    pub async fn stats(&self) -> io::Result<Stats> {
        self.request(Command::Stats).await
    }
    /// At most 500 live connection records; totals include every tracked flow.
    pub async fn connections(&self) -> io::Result<serde_json::Value> {
        self.request(Command::Connections).await
    }
    pub async fn close_connection(&self, id: String) -> io::Result<()> {
        self.request(|reply| Command::Close(id, reply)).await
    }
    pub async fn urltest(&self, name: String, url: String, timeout_ms: u64) -> io::Result<u16> {
        self.request(|reply| Command::UrlTest {
            name,
            url,
            timeout_ms,
            reply,
        })
        .await
    }

    pub async fn probe_document(
        &self,
        configs: Vec<Config>,
        name: String,
        url: String,
        timeout_ms: u64,
    ) -> io::Result<u16> {
        self.request(|reply| Command::ProbeDocument {
            configs,
            name,
            url,
            timeout_ms,
            reply,
        })
        .await
    }

    pub async fn probe_standalone(
        configs: Vec<Config>,
        name: String,
        url: String,
        timeout_ms: u64,
        platform: Option<Arc<dyn Platform>>,
    ) -> io::Result<u16> {
        let context = StandaloneProbes::new(platform)?;
        let result = context.probe(configs, name, url, timeout_ms).await;
        context.shutdown().await;
        result
    }
    pub async fn shutdown(&self) -> io::Result<()> {
        let mut task = self.task.lock().await;
        let Some(worker) = task.take() else {
            return Ok(());
        };
        // The worker also shuts down when all command senders are dropped.
        let _ = self.request(Command::Shutdown).await;
        worker.await.map_err(io::Error::other)?
    }
}

fn stopped() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "embedded core is stopped")
}

struct Bootstrap {
    resolver: Arc<dyn Resolver>,
    endpoints: Vec<SocketAddr>,
}
static BOOTSTRAP: parking_lot::RwLock<Option<Bootstrap>> = parking_lot::RwLock::new(None);

pub(crate) fn platform_resolver() -> Option<Arc<dyn Resolver>> {
    BOOTSTRAP
        .read()
        .as_ref()
        .map(|state| state.resolver.clone())
}
pub(crate) fn platform_dns_endpoints() -> Option<Vec<SocketAddr>> {
    BOOTSTRAP
        .read()
        .as_ref()
        .map(|state| state.endpoints.clone())
}

pub(crate) struct PlatformContext {
    networks: Option<Arc<crate::network_dial::PlatformNetworks>>,
    owners: Option<Arc<owner::OwnerContext>>,
    platform: Option<Arc<dyn Platform>>,
    #[cfg(any(
        target_os = "android",
        target_os = "ios",
        all(unix, feature = "embedded-platform")
    ))]
    protector: Arc<dyn crate::tun::SocketProtector>,
    _lease: OwnedSemaphorePermit,
}

impl PlatformContext {
    fn acquire(platform: Option<Arc<dyn Platform>>) -> io::Result<Self> {
        #[cfg(target_os = "android")]
        if platform.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Android requires protect and physical-network DNS callbacks",
            ));
        }
        #[cfg(not(any(
            target_os = "android",
            target_os = "ios",
            all(unix, feature = "embedded-platform")
        )))]
        if platform.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "platform socket callbacks require the embedded-platform feature on this target",
            ));
        }
        static ACTIVE: OnceLock<Arc<Semaphore>> = OnceLock::new();
        let lease = ACTIVE
            .get_or_init(|| Arc::new(Semaphore::new(1)))
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "an embedded core is already active",
                )
            })?;
        let networks = platform
            .clone()
            .map(crate::network_dial::PlatformNetworks::install)
            .transpose()?;
        #[cfg(any(
            target_os = "android",
            target_os = "ios",
            all(unix, feature = "embedded-platform")
        ))]
        let protector: Arc<dyn crate::tun::SocketProtector> = {
            let platform = platform.clone();
            Arc::new(crate::tun::FnSocketProtector::new(move |fd| {
                platform
                    .as_ref()
                    .map_or(Ok(()), |platform| platform.protect(fd))
            }))
        };
        #[cfg(any(
            target_os = "android",
            target_os = "ios",
            all(unix, feature = "embedded-platform")
        ))]
        crate::tun::set_global_socket_protector(protector.clone());
        let owners = platform.clone().map(owner::OwnerContext::install);
        Ok(Self {
            networks,
            owners,
            platform,
            #[cfg(any(
                target_os = "android",
                target_os = "ios",
                all(unix, feature = "embedded-platform")
            ))]
            protector,
            _lease: lease,
        })
    }

    pub(crate) fn refresh_dns(&self) -> io::Result<()> {
        let Some(platform) = &self.platform else {
            return Ok(());
        };
        let system = platform.supports_system_dns();
        let (resolver, endpoints) = if system {
            // The platform owns its DNS transport, including Private DNS. It
            // does not need plain port-53 endpoints, even during disconnection.
            (
                crate::dns::platform::resolver(platform.clone())?,
                Vec::new(),
            )
        } else {
            let endpoints = platform.dns_servers()?;
            if endpoints.is_empty()
                || endpoints.iter().any(|endpoint| {
                    endpoint.port() == 0
                        || endpoint.ip().is_unspecified()
                        || endpoint.ip().is_multicast()
                })
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "physical network has no usable DNS endpoints",
                ));
            }
            (crate::dns::controlled_bootstrap(&endpoints)?, endpoints)
        };
        let old = BOOTSTRAP.write().replace(Bootstrap {
            resolver,
            endpoints,
        });
        if let Some(old) = old {
            old.resolver.retire();
        }
        Ok(())
    }
}

impl Drop for PlatformContext {
    fn drop(&mut self) {
        if let Some(owners) = self.owners.take() {
            owners.retire();
        }
        if let Some(networks) = self.networks.take() {
            networks.retire();
        }
        let previous = BOOTSTRAP.write().take();
        if let Some(previous) = previous {
            previous.resolver.retire();
        }
        #[cfg(any(
            target_os = "android",
            target_os = "ios",
            all(unix, feature = "embedded-platform")
        ))]
        crate::tun::clear_global_socket_protector_if_current(&self.protector);
    }
}
