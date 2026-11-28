use std::{
    collections::HashMap,
    io,
    sync::{Arc, OnceLock},
    time::Duration,
};

use tokio::{sync::watch, time::Instant};
use tokio_util::task::AbortOnDropHandle;

use super::{Protocol, hysteria2, tuic, udp};
use crate::tcp::carrier_dialer::{
    CarrierDialer, ConfirmedQuicCarrier, EarlyDataOutcome, PendingQuicCarrier, QuicCarrier,
    RouteKey,
};

pub(super) const SETUP_TIMEOUT: Duration = Duration::from_secs(15);

// Exposes the inner io::Error to resource-exhaustion checks; Arc's Error impl skips it.
#[derive(Clone, Debug)]
struct Failure(Arc<io::Error>);
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}
impl Failure {
    fn from(error: io::Error) -> Self {
        Self(Arc::new(error))
    }
    fn error(&self) -> io::Error {
        io::Error::new(self.0.kind(), self.clone())
    }
}

type Outcome = Option<Result<Arc<Generation>, Failure>>;
type Readiness = Option<Result<EarlyDataOutcome, Failure>>;

struct Slot {
    result: watch::Receiver<Outcome>,
    task: AbortOnDropHandle<()>,
}

#[derive(Default)]
pub(super) struct Pool {
    slots: Arc<parking_lot::Mutex<HashMap<RouteKey, Slot>>>,
}

impl Pool {
    pub async fn get(
        &self,
        dialer: Arc<dyn CarrierDialer>,
        protocol: &Protocol,
        udp: bool,
    ) -> io::Result<Arc<Generation>> {
        let mut receiver = {
            let mut slots = self.slots.lock();
            slots.retain(|_, slot| match &*slot.result.borrow() {
                Some(Ok(generation)) => {
                    generation.usable() && (!udp || !generation.registry.lock().exhausted())
                }
                Some(Err(_)) => false,
                None => !slot.task.is_finished(),
            });
            slots
                .entry(dialer.route_key().clone())
                .or_insert_with(|| self.spawn_slot(dialer, protocol.clone()))
                .result
                .clone()
        };
        loop {
            let outcome = receiver.borrow_and_update().clone();
            if let Some(result) = outcome {
                let generation = result.map_err(|error| error.error())?;
                // Native UDP has no rejected-0RTT replay mechanism. Never create
                // an association or send a DATAGRAM before TLS and TUIC AUTH.
                if udp {
                    generation.ready().await?;
                }
                return Ok(generation);
            }
            receiver.changed().await.map_err(|_| retired())?;
        }
    }

    fn spawn_slot(&self, dialer: Arc<dyn CarrierDialer>, protocol: Protocol) -> Slot {
        let (sender, result) = watch::channel(None);
        let slots = Arc::downgrade(&self.slots);
        let key = dialer.route_key().clone();
        let task = crate::network_tasks::spawn(async move {
            let deadline = Instant::now() + SETUP_TIMEOUT;
            let initialization = tokio::time::timeout_at(
                deadline,
                Initialization::begin(dialer, protocol, deadline),
            )
            .await
            .unwrap_or_else(|_| Err(setup_timeout()));
            let initialization = match initialization {
                Ok(initialization) => initialization,
                Err(error) => {
                    let _ = sender.send(Some(Err(Failure::from(error))));
                    return;
                }
            };
            let generation = initialization.generation.clone();
            let exposed = initialization.exposed;
            if exposed {
                let _ = sender.send(Some(Ok(generation.clone())));
            }
            let readiness = initialization.finish().await;
            if !exposed {
                let outcome = readiness
                    .as_ref()
                    .map(|_| generation.clone())
                    .map_err(Clone::clone);
                let _ = sender.send(Some(outcome));
            }
            drop(sender);
            if readiness.is_err() {
                return;
            }

            // ECH may replace the provisional connection. Observe the final leg
            // only, and do not retain the generation after starting its watcher.
            let connection = generation.connection().clone();
            let identity = Arc::downgrade(&generation);
            drop(generation);
            connection.closed().await;
            let Some(slots) = slots.upgrade() else { return };
            let mut slots = slots.lock();
            let is_current = slots.get(&key).is_some_and(|slot| {
                matches!(&*slot.result.borrow(), Some(Ok(current))
                    if Arc::downgrade(current).ptr_eq(&identity))
            });
            if is_current {
                slots.remove(&key);
            }
        });
        Slot {
            result,
            task: AbortOnDropHandle::new(task),
        }
    }
}

struct Established {
    carrier: QuicCarrier,
    udp_enabled: bool,
    dissociate: Option<tokio::sync::mpsc::Sender<tuic::Dissociate>>,
    commands: Option<tuic::CommandWriter>,
    _tasks: Vec<AbortOnDropHandle<()>>,
}

pub(super) struct Generation {
    initial: QuicCarrier,
    established: OnceLock<Established>,
    readiness: watch::Receiver<Readiness>,
    setup_deadline: Instant,
    pub protocol: Protocol,
    pub registry: Arc<parking_lot::Mutex<udp::Registry>>,
    // Retain selected route identities for the entire pooled lifetime.
    _dialer: Arc<dyn CarrierDialer>,
}

/// This guard belongs to the pool's tracked task. Cancelling one foreground
/// waiter does not abort it; pool/network retirement does. Dropping mid-AUTH
/// closes the connection and closes the readiness channel for retained streams.
struct Initialization {
    generation: Arc<Generation>,
    sender: watch::Sender<Readiness>,
    completion: Option<futures::future::BoxFuture<'static, io::Result<ConfirmedQuicCarrier>>>,
    exposed: bool,
    completed: bool,
}

impl Initialization {
    async fn begin(
        dialer: Arc<dyn CarrierDialer>,
        protocol: Protocol,
        deadline: Instant,
    ) -> io::Result<Self> {
        let early = matches!(&protocol, Protocol::Tuic(config) if config.zero_rtt_handshake);
        let pending = if early {
            dialer.open_quic_early().await?
        } else {
            let carrier = dialer.open_quic().await?;
            PendingQuicCarrier {
                early: None,
                deadline,
                completion: Box::pin(async {
                    Ok(ConfirmedQuicCarrier {
                        carrier,
                        early_data: EarlyDataOutcome::NotAttempted,
                    })
                }),
            }
        };
        let deadline = deadline.min(pending.deadline);
        let (carrier, completion, exposed) = if let Some(carrier) = pending.early {
            (carrier, pending.completion, true)
        } else {
            let confirmed = tokio::time::timeout_at(deadline, pending.completion)
                .await
                .map_err(|_| setup_timeout())??;
            let carrier = confirmed.carrier.clone();
            let completion: futures::future::BoxFuture<'static, io::Result<ConfirmedQuicCarrier>> =
                Box::pin(async { Ok(confirmed) });
            (carrier, completion, false)
        };
        let maximum = match &protocol {
            Protocol::Hysteria2(_) => u32::MAX as u64,
            Protocol::Tuic(_) => u16::MAX as u64,
        };
        let (sender, readiness) = watch::channel(None);
        Ok(Self {
            generation: Arc::new(Generation {
                initial: carrier,
                established: OnceLock::new(),
                readiness,
                setup_deadline: deadline,
                protocol,
                registry: Arc::new(parking_lot::Mutex::new(udp::Registry::new(maximum))),
                _dialer: dialer,
            }),
            sender,
            completion: Some(completion),
            exposed,
            completed: false,
        })
    }

    async fn finish(mut self) -> Result<EarlyDataOutcome, Failure> {
        let completion = self.completion.take().expect("single initializer");
        let generation = self.generation.clone();
        let result = tokio::time::timeout_at(generation.setup_deadline, async {
            let confirmed = completion.await?;
            let outcome = confirmed.early_data;
            generation.initialize(confirmed.carrier).await?;
            Ok::<_, io::Error>(outcome)
        })
        .await
        .unwrap_or_else(|_| Err(setup_timeout()))
        .map_err(Failure::from);
        let result = if Instant::now() >= generation.setup_deadline {
            Err(Failure::from(setup_timeout()))
        } else {
            result
        };
        if result.is_err() {
            self.generation.registry.lock().close();
            self.generation
                .connection()
                .close(0u32.into(), b"QUIC authentication failed");
        }
        let _ = self.sender.send(Some(result.clone()));
        self.completed = result.is_ok();
        result
    }
}

impl Drop for Initialization {
    fn drop(&mut self) {
        if !self.completed {
            self.generation.registry.lock().close();
            self.generation
                .initial
                .connection
                .close(0u32.into(), b"QUIC initialization cancelled");
        }
    }
}

/// A replacement ECH carrier must also be closed if AUTH is cancelled before it
/// can be installed in the generation.
struct CarrierGuard(Option<QuicCarrier>);
impl Drop for CarrierGuard {
    fn drop(&mut self) {
        if let Some(carrier) = &self.0 {
            carrier
                .connection
                .close(0u32.into(), b"QUIC initialization failed");
        }
    }
}

impl Generation {
    async fn initialize(&self, carrier: QuicCarrier) -> io::Result<()> {
        let mut guard = CarrierGuard(Some(carrier));
        let connection = &guard.0.as_ref().unwrap().connection;
        if let Some(error) = connection.close_reason() {
            return Err(io::Error::other(error));
        }
        let mut tasks = Vec::new();
        let mut dissociate = None;
        let mut commands = None;
        let udp_enabled = match &self.protocol {
            Protocol::Hysteria2(config) => {
                let (enabled, task) = hysteria2::authenticate(connection, config).await?;
                tasks.push(task);
                config.udp_enabled && enabled
            }
            Protocol::Tuic(config) => {
                let writer = tuic::CommandWriter::new(connection.clone());
                // The ordinary TLS exporter is available only after carrier
                // completion authenticated the server Finished and identity.
                tuic::authenticate(&writer, config).await?;
                if connection.max_datagram_size().is_none() {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "TUIC requires QUIC datagrams for heartbeat",
                    ));
                }
                tasks.push(AbortOnDropHandle::new(crate::network_tasks::spawn(
                    tuic::heartbeat(connection.clone(), config.heartbeat_interval_secs),
                )));
                let (sender, receiver) = tokio::sync::mpsc::channel(64);
                dissociate = Some(sender);
                tasks.push(AbortOnDropHandle::new(crate::network_tasks::spawn(
                    tuic::dissociate_loop(writer.clone(), receiver),
                )));
                commands = Some(writer);
                config.udp_enabled
            }
        };
        tasks.push(AbortOnDropHandle::new(crate::network_tasks::spawn(
            udp::receive(
                connection.clone(),
                self.registry.clone(),
                matches!(self.protocol, Protocol::Tuic(_)),
            ),
        )));
        let established = Established {
            carrier: guard.0.take().unwrap(),
            udp_enabled,
            dissociate,
            commands,
            _tasks: tasks,
        };
        assert!(
            self.established.set(established).is_ok(),
            "one QUIC initializer"
        );
        Ok(())
    }

    pub async fn ready(&self) -> io::Result<EarlyDataOutcome> {
        let mut receiver = self.readiness.clone();
        loop {
            let outcome = receiver.borrow_and_update().clone();
            if let Some(result) = outcome {
                return result.map_err(|error| error.error());
            }
            receiver.changed().await.map_err(|_| retired())?;
        }
    }

    fn usable(&self) -> bool {
        match &*self.readiness.borrow() {
            Some(Ok(_)) => self.connection().close_reason().is_none(),
            Some(Err(_)) => false,
            // The provisional leg may close during an authenticated ECH retry.
            // It does not invalidate the shared initialization's final result.
            None => self.readiness.has_changed().is_ok(),
        }
    }

    pub fn confirmed(&self) -> bool {
        matches!(&*self.readiness.borrow(), Some(Ok(_)))
    }
    pub fn stream_deadline(&self) -> Instant {
        if self.confirmed() {
            Instant::now() + SETUP_TIMEOUT
        } else {
            self.setup_deadline
        }
    }
    pub fn connection(&self) -> &quinn::Connection {
        &self
            .established
            .get()
            .map_or(&self.initial, |ready| &ready.carrier)
            .connection
    }
    pub fn udp_enabled(&self) -> bool {
        self.established
            .get()
            .is_some_and(|ready| ready.udp_enabled)
    }
    pub fn dissociate(&self) -> Option<&tokio::sync::mpsc::Sender<tuic::Dissociate>> {
        self.established
            .get()
            .and_then(|ready| ready.dissociate.as_ref())
    }
    pub fn commands(&self) -> Option<&tuic::CommandWriter> {
        self.established
            .get()
            .and_then(|ready| ready.commands.as_ref())
    }
}

impl Drop for Generation {
    fn drop(&mut self) {
        self.registry.lock().close();
        if let Some(ready) = self.established.take() {
            if ready.carrier.connection.close_reason().is_none()
                && tokio::runtime::Handle::try_current().is_ok()
            {
                // Keep one bounded drain per generation for FIN and queued data.
                crate::network_tasks::spawn(async move {
                    let _ = tokio::time::timeout(
                        Duration::from_secs(3),
                        ready.carrier.connection.closed(),
                    )
                    .await;
                    ready
                        .carrier
                        .connection
                        .close(0u32.into(), b"client retired");
                    drop(ready);
                });
                return;
            }
            ready
                .carrier
                .connection
                .close(0u32.into(), b"client retired");
        }
        self.initial
            .connection
            .close(0u32.into(), b"client retired");
    }
}

fn setup_timeout() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "QUIC client setup timed out")
}
fn retired() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "QUIC client retired")
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        async_stream::AsyncStream,
        config::quic_client::{Hysteria2ClientConfig, Secret},
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug)]
    struct Stalled {
        key: RouteKey,
        started: AtomicUsize,
        done: tokio::sync::Notify,
    }
    #[derive(Debug)]
    struct Panics(RouteKey);
    #[async_trait::async_trait]
    impl CarrierDialer for Panics {
        fn route_key(&self) -> &RouteKey {
            &self.0
        }
        async fn open_stream(&self) -> io::Result<Box<dyn AsyncStream>> {
            unreachable!()
        }
        async fn open_quic(&self) -> io::Result<QuicCarrier> {
            panic!("test initializer panic")
        }
    }

    #[async_trait::async_trait]
    impl CarrierDialer for Stalled {
        fn route_key(&self) -> &RouteKey {
            &self.key
        }
        async fn open_stream(&self) -> io::Result<Box<dyn AsyncStream>> {
            unreachable!()
        }
        async fn open_quic(&self) -> io::Result<QuicCarrier> {
            self.started.fetch_add(1, Ordering::SeqCst);
            self.done.notified().await;
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "test auth rejected",
            ))
        }
    }
    fn protocol() -> Protocol {
        Protocol::Hysteria2(Hysteria2ClientConfig {
            up_mbps: 0,
            down_mbps: 0,
            password: Secret("test".into()),
            obfs: None,
            hopping: None,
            udp_enabled: true,
        })
    }

    fn stalled() -> Arc<Stalled> {
        Arc::new(Stalled {
            key: RouteKey(vec![1]),
            started: AtomicUsize::new(0),
            done: tokio::sync::Notify::new(),
        })
    }

    #[tokio::test]
    async fn panicked_initializers_do_not_poison_routes() {
        let pool = Pool::default();
        let protocol = protocol();
        assert!(
            pool.get(Arc::new(Panics(RouteKey(vec![1]))), &protocol, false)
                .await
                .is_err()
        );
        let dialer = stalled();
        let mut retry = Box::pin(pool.get(dialer.clone(), &protocol, false));
        assert!(futures::poll!(&mut retry).is_pending());
        tokio::task::yield_now().await;
        assert_eq!(dialer.started.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn cancellation_does_not_cancel_shared_initialization_and_failures_retry() {
        let pool = Pool::default();
        let protocol = protocol();
        let dialer = stalled();
        let mut first = Box::pin(pool.get(dialer.clone(), &protocol, false));
        assert!(futures::poll!(&mut first).is_pending());
        tokio::task::yield_now().await;
        drop(first);
        let mut second = Box::pin(pool.get(dialer.clone(), &protocol, false));
        assert!(futures::poll!(&mut second).is_pending());
        assert_eq!(dialer.started.load(Ordering::SeqCst), 1);
        dialer.done.notify_one();
        assert_eq!(
            second.await.err().unwrap().kind(),
            io::ErrorKind::PermissionDenied
        );
        let mut third = Box::pin(pool.get(dialer.clone(), &protocol, false));
        assert!(futures::poll!(&mut third).is_pending());
        tokio::task::yield_now().await;
        assert_eq!(dialer.started.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn initialization_has_a_deadline_even_without_waiters() {
        let pool = Pool::default();
        let dialer = stalled();
        assert_eq!(
            pool.get(dialer, &protocol(), false)
                .await
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::TimedOut
        );
    }
}
