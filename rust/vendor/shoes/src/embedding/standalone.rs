use super::{Platform, PlatformContext, probe};
use crate::{config::Config, network_tasks::NetworkLifetime};
use std::{io, sync::Arc};
use tokio::sync::{Mutex, oneshot};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, PartialEq, Eq)]
struct SnapshotIdentity {
    generation: u64,
    default_handle: Option<u64>,
}

struct Epoch {
    identity: Option<SnapshotIdentity>,
    network: NetworkLifetime,
}

/// A short-lived, shared physical-network context for concurrent probes while
/// no service is running. New probes refresh a changed physical-network epoch;
/// hosts still cancel and join the whole context before starting a service.
pub struct StandaloneProbes {
    epoch: Mutex<Epoch>,
    cancelled: CancellationToken,
    platform: PlatformContext,
}

impl StandaloneProbes {
    pub fn new(platform: Option<Arc<dyn Platform>>) -> io::Result<Self> {
        let platform = PlatformContext::acquire(platform)?;
        // Read before refreshing: a concurrent change must never label an old
        // resolver with a newer identity and suppress the next probe's refresh.
        let identity = snapshot_identity(&platform)?;
        platform.refresh_dns()?;
        Ok(Self {
            epoch: Mutex::new(Epoch {
                identity,
                network: NetworkLifetime::default(),
            }),
            cancelled: CancellationToken::new(),
            platform,
        })
    }

    /// Permanent cancellation is independent of the replaceable network epoch.
    pub fn cancel(&self) {
        self.cancelled.cancel();
    }

    pub async fn shutdown(&self) {
        self.cancel();
        let epoch = self.epoch.lock().await;
        epoch.network.cancel();
        epoch.network.wait().await;
    }

    pub async fn probe(
        &self,
        configs: Vec<Config>,
        name: String,
        url: String,
        timeout_ms: u64,
    ) -> io::Result<u16> {
        tokio::select! {
            biased;
            _ = self.cancelled.cancelled() => Err(cancelled()),
            result = async {
                let response = self.start(configs, name, url, timeout_ms).await?;
                response.await.map_err(|_| cancelled())?
            } => result,
        }
    }

    async fn start(
        &self,
        configs: Vec<Config>,
        name: String,
        url: String,
        timeout_ms: u64,
    ) -> io::Result<oneshot::Receiver<io::Result<u16>>> {
        // Only admission and retirement are serialized; probes in one epoch
        // run concurrently and share its system-DNS cache.
        let mut epoch = self.epoch.lock().await;
        if self.cancelled.is_cancelled() {
            return Err(cancelled());
        }
        let identity = match snapshot_identity(&self.platform) {
            Ok(identity) => identity,
            Err(error) => {
                epoch.network.cancel();
                epoch.network.wait().await;
                return Err(error);
            }
        };
        if epoch.identity != identity || epoch.network.cancelled.is_cancelled() {
            epoch.network.cancel();
            epoch.network.wait().await;
            if self.cancelled.is_cancelled() {
                return Err(cancelled());
            }
            // Cleanup may span another network event. Take a fresh identity
            // before installing DNS, retaining the cancelled epoch on error.
            let identity = snapshot_identity(&self.platform)?;
            self.platform.refresh_dns()?;
            if self.cancelled.is_cancelled() {
                return Err(cancelled());
            }
            *epoch = Epoch {
                identity,
                network: NetworkLifetime::default(),
            };
        }
        let (mut reply, response) = oneshot::channel();
        let stopped = self.cancelled.clone();
        // Track the probe itself, not just its child transports. Retiring an
        // epoch must drop its probe before waiting for all cleanup it schedules.
        // Receiver closure also cancels a caller that drops its probe future.
        epoch.network.spawn(async move {
            let result = tokio::select! {
                biased;
                _ = stopped.cancelled() => return,
                _ = reply.closed() => return,
                result = probe::run(configs, name, url, timeout_ms) => result,
            };
            let _ = reply.send(result);
        });
        Ok(response)
    }
}

fn snapshot_identity(platform: &PlatformContext) -> io::Result<Option<SnapshotIdentity>> {
    let Some(platform) = &platform.platform else {
        return Ok(None);
    };
    let snapshot = platform.physical_networks()?;
    snapshot.validate()?;
    Ok(Some(SnapshotIdentity {
        generation: snapshot.generation,
        default_handle: snapshot.default_handle,
    }))
}

fn cancelled() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "standalone probe cancelled")
}
