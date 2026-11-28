//! sing-mux's first-stream bandwidth exchange. Kernel acceleration is optional
//! on the client; an unauthenticated/failed remote exchange is never ignored.
use std::{future::Future, io, time::Duration};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

use super::{client_session::Session, h2mux_protocol::decode_error_length};
use crate::{
    address::{Address, NetLocation},
    tcp::socket_control::{BrutalStatus, TcpSocketControl},
};

pub const EXCHANGE_DOMAIN: &str = "_BrutalBwExchange";
pub const MIN_RATE: u64 = 65_536;

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrutalConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub up_mbps: u64,
    #[serde(default)]
    pub down_mbps: u64,
}

impl BrutalConfig {
    pub fn rates(&self) -> io::Result<Option<(u64, u64)>> {
        if !self.enabled {
            return Ok(None);
        }
        let convert = |mbps: u64| {
            mbps.checked_mul(125_000)
                .filter(|rate| *rate >= MIN_RATE)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "TCP Brutal requires positive, non-overflowing up_mbps and down_mbps",
                    )
                })
        };
        Ok(Some((convert(self.up_mbps)?, convert(self.down_mbps)?)))
    }
}

pub(super) async fn negotiate(
    session: &Session,
    send: u64,
    receive: u64,
    control: io::Result<Option<TcpSocketControl>>,
) -> io::Result<()> {
    let target = NetLocation::new(Address::Hostname(EXCHANGE_DOMAIN.into()), 0);
    let mut stream = session.open(&target, true).await?;
    stream.write_all(&receive.to_be_bytes()).await?;
    stream.flush().await?;
    let remote_receive = read_response(&mut stream).await?;
    // The sing-mux server closes this control stream immediately after its
    // complete reply. H2 may already consider the stream inactive by the time
    // we send our END_STREAM. As in the reference client's ignored Close()
    // result, cleanup cannot invalidate an authenticated, complete exchange.
    // A refusal, truncated reply or transport error while reading still fails.
    if let Err(error) = stream.shutdown().await {
        log::trace!("TCP Brutal control stream already closed after reply: {error}");
    }
    match control {
        Ok(Some(control)) => match control.enable_brutal(send.min(remote_receive))? {
            BrutalStatus::Enabled => log::debug!(
                "TCP Brutal enabled locally at {} B/s",
                send.min(remote_receive)
            ),
            BrutalStatus::Unavailable(error) => log::debug!(
                "TCP Brutal local acceleration unavailable; remote exchange succeeded: {error}"
            ),
        },
        Ok(None) => log::debug!(
            "TCP Brutal local acceleration unavailable: carrier has no exclusive TCP socket"
        ),
        Err(error) => log::debug!("TCP Brutal local acceleration unavailable: {error}"),
    }
    Ok(())
}

async fn read_response(stream: &mut (impl AsyncRead + Unpin)) -> io::Result<u64> {
    match stream.read_u8().await? {
        1 => {
            let rate = stream.read_u64().await?;
            if rate < MIN_RATE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid TCP Brutal peer receive rate",
                ));
            }
            Ok(rate)
        }
        0 => {
            let mut prefix = Vec::with_capacity(2);
            let length = loop {
                prefix.push(stream.read_u8().await?);
                if let Some((length, _)) = decode_error_length(&prefix)? {
                    break length;
                }
            };
            let mut message = vec![0; length];
            stream.read_exact(&mut message).await?;
            // Escape control characters from an untrusted peer's diagnostics.
            Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!(
                    "TCP Brutal peer rejected exchange: {:?}",
                    String::from_utf8_lossy(&message)
                ),
            ))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid TCP Brutal response status",
        )),
    }
}

/// Apply one setup deadline, including capacity, dial, exchange and stream open.
/// The enclosing route may impose an earlier deadline by dropping this future.
pub(super) async fn bounded<T>(
    future: impl Future<Output = io::Result<T>>,
    timeout: Duration,
) -> io::Result<T> {
    let deadline = tokio::time::Instant::now() + timeout;
    bounded_at(future, deadline).await
}

pub(super) fn ensure_active(deadline: tokio::time::Instant) -> io::Result<()> {
    if tokio::time::Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "mux setup deadline exceeded",
        ));
    }
    if crate::network_tasks::NetworkTasks::current()
        .is_some_and(|network| network.cancelled.is_cancelled())
    {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "mux network lifetime retired",
        ));
    }
    Ok(())
}

pub(super) async fn bounded_at<T>(
    future: impl Future<Output = io::Result<T>>,
    deadline: tokio::time::Instant,
) -> io::Result<T> {
    let network = crate::network_tasks::NetworkTasks::current();
    let result = tokio::select! {
        biased;
        _ = async { match &network { Some(network) => network.cancelled.cancelled().await, None => std::future::pending().await } } => {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "mux network lifetime retired"));
        }
        result = tokio::time::timeout_at(deadline, future) => result
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "mux setup deadline exceeded"))?,
    };
    ensure_active(deadline)?;
    result
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod interop_tests;
