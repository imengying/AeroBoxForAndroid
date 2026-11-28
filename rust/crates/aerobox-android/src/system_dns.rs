//! Nonblocking Java DNS completion bridge; no runtime/host lifecycle locks.
use shoes::embedding::PlatformDnsQuery;
use std::{
    collections::HashMap,
    io,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::sync::oneshot;

type Reply = oneshot::Sender<io::Result<Vec<u8>>>;
static QUERIES: OnceLock<Mutex<HashMap<u64, Reply>>> = OnceLock::new();
static NEXT: AtomicU64 = AtomicU64::new(1);
const MAX_PENDING: usize = 64;

pub(crate) trait DnsCallbacks: Send + Sync + 'static {
    fn start(&self, id: u64, query: &PlatformDnsQuery) -> io::Result<()>;
    fn cancel(&self, id: u64);
}

fn queries() -> &'static Mutex<HashMap<u64, Reply>> {
    QUERIES.get_or_init(|| Mutex::new(HashMap::new()))
}

struct Pending {
    id: u64,
    callbacks: Arc<dyn DnsCallbacks>,
}
impl Drop for Pending {
    fn drop(&mut self) {
        // A completion removes the same entry before publishing a result.
        // Never hold the registry lock during a possibly synchronous Java call.
        let removed = queries()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.id);
        if removed.is_some() {
            self.callbacks.cancel(self.id);
        }
    }
}

pub(crate) fn complete(id: u64, result: io::Result<Vec<u8>>) {
    let sender = queries()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&id);
    if let Some(sender) = sender {
        let result = result.and_then(|message| {
            if !(12..=65535).contains(&message.len()) {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid Android DNS response length",
                ))
            } else {
                Ok(message)
            }
        });
        let _ = sender.send(result);
    }
}

pub(crate) async fn exchange(
    callbacks: Arc<dyn DnsCallbacks>,
    query: PlatformDnsQuery,
) -> io::Result<Vec<u8>> {
    if tokio::time::Instant::now() >= query.deadline {
        return Err(io::ErrorKind::TimedOut.into());
    }
    if !(12..=65535).contains(&query.message.len()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Android DNS request length",
        ));
    }
    let (reply, received) = oneshot::channel();
    let id = {
        let mut pending = queries().lock().unwrap_or_else(|e| e.into_inner());
        if pending.len() >= MAX_PENDING {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "Android DNS query limit reached",
            ));
        }
        let id = NEXT
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| io::Error::other("Android DNS identifiers exhausted"))?;
        pending.insert(id, reply);
        id
    };
    let _pending = Pending {
        id,
        callbacks: callbacks.clone(),
    };
    // Registration precedes dispatch: completion is allowed within start().
    callbacks.start(id, &query)?;
    let result = tokio::time::timeout_at(query.deadline, received)
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
        .map_err(|_| io::Error::from(io::ErrorKind::ConnectionAborted))?;
    if tokio::time::Instant::now() >= query.deadline {
        return Err(io::ErrorKind::TimedOut.into());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    static GATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    #[derive(Default)]
    struct Callbacks {
        sync: bool,
        fail: bool,
        started: AtomicU64,
        cancelled: AtomicUsize,
    }
    impl DnsCallbacks for Callbacks {
        fn start(&self, id: u64, _: &PlatformDnsQuery) -> io::Result<()> {
            self.started.store(id, Ordering::SeqCst);
            if self.sync {
                complete(id, Ok(vec![0; 12]));
                complete(id, Err(io::Error::other("duplicate ignored")));
            }
            if self.fail {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            Ok(())
        }
        fn cancel(&self, _: u64) {
            self.cancelled.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn query() -> PlatformDnsQuery {
        PlatformDnsQuery {
            network: shoes::embedding::PlatformNetwork {
                generation: 1,
                handle: u64::MAX,
            },
            message: vec![0; 12],
            deadline: tokio::time::Instant::now() + std::time::Duration::from_secs(1),
        }
    }
    #[tokio::test]
    async fn synchronous_callback_and_duplicates_complete_once_without_deadlock() {
        let _gate = GATE.lock().await;
        let callbacks = Arc::new(Callbacks {
            sync: true,
            ..Default::default()
        });
        assert_eq!(
            exchange(callbacks.clone(), query()).await.unwrap(),
            vec![0; 12]
        );
        assert_eq!(callbacks.cancelled.load(Ordering::SeqCst), 0);
        assert!(queries().lock().unwrap().is_empty());
    }
    #[tokio::test]
    async fn dropped_queries_cancel_without_callback_and_late_results_cannot_reach_new_id() {
        let _gate = GATE.lock().await;
        let callbacks = Arc::new(Callbacks::default());
        let mut old = Box::pin(exchange(callbacks.clone(), query()));
        std::future::poll_fn(|cx| {
            assert!(old.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        let old_id = callbacks.started.load(Ordering::SeqCst);
        drop(old);
        assert_eq!(callbacks.cancelled.load(Ordering::SeqCst), 1);
        let mut current = Box::pin(exchange(callbacks.clone(), query()));
        std::future::poll_fn(|cx| {
            assert!(current.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        let current_id = callbacks.started.load(Ordering::SeqCst);
        assert_ne!(old_id, current_id);
        complete(old_id, Ok(vec![9; 12]));
        complete(current_id, Ok(vec![3; 12]));
        assert_eq!(current.await.unwrap(), vec![3; 12]);
        assert!(queries().lock().unwrap().is_empty());
    }
    #[tokio::test]
    async fn submission_error_removes_registration_and_cancels_partial_java_work() {
        let _gate = GATE.lock().await;
        let callbacks = Arc::new(Callbacks {
            fail: true,
            ..Default::default()
        });
        assert_eq!(
            exchange(callbacks.clone(), query())
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(callbacks.cancelled.load(Ordering::SeqCst), 1);
        assert!(queries().lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn capacity_is_global_and_cancel_restores_a_slot_without_a_callback() {
        let _gate = GATE.lock().await;
        let callbacks = Arc::new(Callbacks::default());
        let mut pending = Vec::new();
        for _ in 0..MAX_PENDING {
            let mut future = Box::pin(exchange(callbacks.clone(), query()));
            std::future::poll_fn(|cx| {
                assert!(future.as_mut().poll(cx).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
            pending.push(future);
        }
        assert_eq!(
            exchange(callbacks.clone(), query())
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        pending.pop();
        let immediate = Arc::new(Callbacks {
            sync: true,
            ..Default::default()
        });
        exchange(immediate, query()).await.unwrap();
        drop(pending);
        assert_eq!(callbacks.cancelled.load(Ordering::SeqCst), MAX_PENDING);
        assert!(queries().lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn expired_and_malformed_queries_do_not_dispatch_and_deadlines_cancel() {
        let _gate = GATE.lock().await;
        let callbacks = Arc::new(Callbacks::default());
        let mut expired = query();
        expired.deadline = tokio::time::Instant::now();
        assert_eq!(
            exchange(callbacks.clone(), expired)
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        for length in [0, 11, 65536] {
            let mut invalid = query();
            invalid.message = vec![0; length];
            assert_eq!(
                exchange(callbacks.clone(), invalid)
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidInput
            );
        }
        assert_eq!(callbacks.started.load(Ordering::SeqCst), 0);
        let mut timed = query();
        timed.deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(10);
        assert_eq!(
            exchange(callbacks.clone(), timed).await.unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(callbacks.cancelled.load(Ordering::SeqCst), 1);
        complete(callbacks.started.load(Ordering::SeqCst), Ok(vec![0; 12]));
        assert!(queries().lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn malformed_completion_releases_registration_but_keeps_error() {
        let _gate = GATE.lock().await;
        let callbacks = Arc::new(Callbacks::default());
        for length in [11, 65536] {
            let mut pending = Box::pin(exchange(callbacks.clone(), query()));
            std::future::poll_fn(|cx| {
                assert!(pending.as_mut().poll(cx).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
            complete(
                callbacks.started.load(Ordering::SeqCst),
                Ok(vec![0; length]),
            );
            assert_eq!(
                pending.await.unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
        assert_eq!(callbacks.cancelled.load(Ordering::SeqCst), 0);
        assert!(queries().lock().unwrap().is_empty());
    }
}
