//! A TUIC CONNECT stream whose bounded early writes can be recreated only after
//! an authenticated TLS early-data rejection. No reads/flush/FIN pass readiness.
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use futures::future::BoxFuture;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::Instant,
};

use super::session::Generation;
use crate::{
    async_stream::{AsyncPing, AsyncStream},
    resources::BudgetPermit,
    tcp::{carrier_dialer::EarlyDataOutcome, tcp_handler::TcpClientSetupResult},
};

const REPLAY_LIMIT: usize = 64 << 10;

struct Streams {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    cancel_on_drop: bool,
}
impl Drop for Streams {
    fn drop(&mut self) {
        if self.cancel_on_drop {
            // A cancelled partial CONNECT must not finish a truncated command.
            let _ = self.send.reset(0u32.into());
            let _ = self.recv.stop(0u32.into());
        }
    }
}

async fn open(
    connection: quinn::Connection,
    prefix: Vec<u8>,
    payload: Vec<u8>,
    deadline: Instant,
) -> io::Result<Streams> {
    if Instant::now() >= deadline {
        return Err(timed_out());
    }
    let streams = tokio::time::timeout_at(deadline, async move {
        let (send, recv) = connection.open_bi().await?;
        let mut streams = Streams {
            send,
            recv,
            cancel_on_drop: true,
        };
        streams.send.write_all(&prefix).await?;
        streams.send.write_all(&payload).await?;
        Ok::<_, io::Error>(streams)
    })
    .await
    .map_err(|_| timed_out())??;
    if Instant::now() >= deadline {
        return Err(timed_out());
    }
    Ok(streams)
}

pub(super) async fn connect(
    generation: Arc<Generation>,
    prefix: Vec<u8>,
) -> io::Result<TcpClientSetupResult> {
    let deadline = generation.stream_deadline();
    let source = generation.connection().clone();
    let source_id = source.stable_id();
    let mut retried = false;
    let streams = match open(source, prefix.clone(), Vec::new(), deadline).await {
        Ok(streams) => streams,
        Err(error) => {
            // A rejected early stream may fail during CONNECT itself. Wait for
            // the shared authenticated outcome before choosing a replacement.
            match generation.ready().await {
                Ok(EarlyDataOutcome::Rejected)
                    if should_replay_open_error(
                        &error,
                        source_id,
                        generation.connection().stable_id(),
                    ) =>
                {
                    retried = true;
                    open(
                        generation.connection().clone(),
                        prefix.clone(),
                        Vec::new(),
                        deadline,
                    )
                    .await?
                }
                Ok(_) => return Err(error),
                Err(error) => return Err(error),
            }
        }
    };
    let was_early = streams.recv.is_0rtt();
    let readiness_generation = generation.clone();
    let readiness: BoxFuture<'static, io::Result<EarlyDataOutcome>> =
        Box::pin(async move { readiness_generation.ready().await });
    // Quic stream setup exposes an early leg only for an actual TLS ticket.
    // Charge the entire maximum replay allowance before acknowledging any bytes.
    let permit = crate::resources::try_quic_memory(REPLAY_LIMIT)
        .ok_or_else(|| crate::resources::quic_memory_exhausted(REPLAY_LIMIT))?;
    Ok(TcpClientSetupResult {
        client_stream: Box::new(EarlyStream {
            generation,
            streams: Some(streams),
            prefix,
            replay: Vec::new(),
            permit: Some(permit),
            source_id,
            was_early,
            retried,
            deadline,
            readiness: Some(parking_lot::Mutex::new(readiness)),
            replacement: None,
            confirmed: false,
            deferred_error: None,
            failure: None,
        }),
        early_data: None,
    })
}

#[derive(Clone, Debug)]
struct Failure(Arc<io::Error>);
impl std::fmt::Display for Failure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}
impl Failure {
    fn error(&self) -> io::Error {
        io::Error::new(self.0.kind(), self.clone())
    }
}

struct EarlyStream {
    generation: Arc<Generation>,
    streams: Option<Streams>,
    prefix: Vec<u8>,
    replay: Vec<u8>,
    permit: Option<BudgetPermit>,
    source_id: usize,
    was_early: bool,
    retried: bool,
    deadline: Instant,
    // The stream trait is Sync. These futures are polled only through &mut self;
    // the mutex provides Sync without requiring the future itself to be Sync.
    readiness: Option<parking_lot::Mutex<BoxFuture<'static, io::Result<EarlyDataOutcome>>>>,
    replacement: Option<parking_lot::Mutex<BoxFuture<'static, io::Result<Streams>>>>,
    confirmed: bool,
    deferred_error: Option<io::Error>,
    failure: Option<Failure>,
}

impl EarlyStream {
    fn poison(&mut self, error: io::Error) -> io::Error {
        if let Some(streams) = &mut self.streams {
            streams.cancel_on_drop = true;
        }
        self.streams = None;
        self.readiness = None;
        self.replacement = None;
        self.replay = Vec::new();
        self.permit = None;
        self.deferred_error = None;
        let failure = Failure(Arc::new(error));
        let error = failure.error();
        self.failure = Some(failure);
        error
    }

    /// Pending means early writes remain permitted, but no received bytes or FIN
    /// may pass. A replacement operation blocks both directions until complete.
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(failure) = &self.failure {
            return Poll::Ready(Err(failure.error()));
        }
        if self.confirmed {
            return Poll::Ready(Ok(()));
        }
        if let Some(readiness) = &mut self.readiness {
            let result = std::task::ready!(readiness.get_mut().as_mut().poll(cx));
            self.readiness = None;
            let outcome = match result {
                Ok(outcome) => outcome,
                Err(error) => return Poll::Ready(Err(self.poison(error))),
            };
            let different_leg = self.source_id != self.generation.connection().stable_id();
            if outcome == EarlyDataOutcome::Rejected
                && !self.retried
                && (self.was_early || different_leg)
            {
                if let Some(streams) = &mut self.streams {
                    streams.cancel_on_drop = true;
                }
                self.streams = None;
                self.deferred_error = None;
                self.retried = true;
                let payload = std::mem::take(&mut self.replay);
                self.replacement = Some(parking_lot::Mutex::new(Box::pin(open(
                    self.generation.connection().clone(),
                    self.prefix.clone(),
                    payload,
                    self.deadline,
                ))));
            } else {
                // A changed carrier without explicit authenticated rejection is
                // a broken carrier contract, never permission to replay.
                if different_leg && !self.retried {
                    return Poll::Ready(Err(self.poison(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "QUIC carrier changed without authenticated early rejection",
                    ))));
                }
                if let Some(error) = self.deferred_error.take() {
                    return Poll::Ready(Err(self.poison(error)));
                }
                self.confirmed = true;
            }
        }
        if let Some(replacement) = &mut self.replacement {
            let result = std::task::ready!(replacement.get_mut().as_mut().poll(cx));
            self.replacement = None;
            match result {
                Ok(streams) => {
                    self.streams = Some(streams);
                    self.confirmed = true;
                }
                Err(error) => return Poll::Ready(Err(self.poison(error))),
            }
        }
        if self.confirmed {
            self.replay = Vec::new();
            self.permit = None;
            if let Some(streams) = &mut self.streams {
                streams.cancel_on_drop = false;
            }
            return Poll::Ready(Ok(()));
        }
        Poll::Pending
    }
}

impl AsyncRead for EarlyStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        std::task::ready!(this.poll_ready(cx))?;
        match Pin::new(&mut this.streams.as_mut().unwrap().recv).poll_read(cx, buffer) {
            Poll::Ready(Err(error)) => Poll::Ready(Err(this.poison(error))),
            result => result,
        }
    }
}

impl AsyncWrite for EarlyStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match this.poll_ready(cx) {
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending if this.replacement.is_some() || this.deferred_error.is_some() => {
                return Poll::Pending;
            }
            _ => {}
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let length = if this.confirmed {
            bytes.len()
        } else {
            bytes.len().min(REPLAY_LIMIT - this.replay.len())
        };
        if length == 0 {
            return Poll::Pending;
        }
        let result =
            Pin::new(&mut this.streams.as_mut().unwrap().send).poll_write(cx, &bytes[..length]);
        match result {
            Poll::Ready(Ok(written)) => {
                if !this.confirmed {
                    this.replay.extend_from_slice(&bytes[..written]);
                }
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(error)) if !this.confirmed => {
                // Quinn can report rejection before the shared TLS/AUTH result.
                // Preserve already-acknowledged bytes until that result decides.
                this.deferred_error = Some(error.into());
                Poll::Pending
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(this.poison(error.into()))),
            Poll::Pending => Poll::Pending,
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Quinn has no separate flush, but reporting flush before authentication
        // would let upper protocols expose an unverified transport to callers.
        self.get_mut().poll_ready(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        std::task::ready!(this.poll_ready(cx))?;
        match Pin::new(&mut this.streams.as_mut().unwrap().send).poll_shutdown(cx) {
            Poll::Ready(Err(error)) => Poll::Ready(Err(this.poison(error))),
            result => result,
        }
    }
}
impl AsyncPing for EarlyStream {
    fn supports_ping(&self) -> bool {
        false
    }
    fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}
impl AsyncStream for EarlyStream {}

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "TUIC stream setup timed out")
}

fn should_replay_open_error(error: &io::Error, initial_id: usize, final_id: usize) -> bool {
    initial_id != final_id
        || error
            .get_ref()
            .and_then(|source| source.downcast_ref::<quinn::WriteError>())
            .is_some_and(|error| matches!(error, quinn::WriteError::ZeroRttRejected))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn repeated_handshake_failure_preserves_resource_exhaustion_source() {
        let failure = Failure(Arc::new(crate::resources::exhausted()));
        for _ in 0..2 {
            assert!(crate::resources::is_exhausted(&failure.error()));
        }
    }

    #[test]
    fn confirmed_stream_io_error_is_not_replayed_for_an_old_rejection() {
        let generic = io::Error::new(
            io::ErrorKind::ConnectionReset,
            "peer stopped confirmed stream",
        );
        assert!(!should_replay_open_error(&generic, 1, 1));
        assert!(should_replay_open_error(&generic, 1, 2));
        let rejected: io::Error = quinn::WriteError::ZeroRttRejected.into();
        assert!(should_replay_open_error(&rejected, 1, 1));
    }
}
