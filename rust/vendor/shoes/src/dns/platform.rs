//! Android's system resolver preserves Private DNS and per-Network policy.
//! Failures never fall back to raw port 53 or a different physical network.
use crate::{
    address::NetLocation,
    embedding::{Platform, PlatformDnsQuery, PlatformNetwork},
    resolver::{DnsExchangeFuture, ResolveFuture, Resolver},
};
use hickory_resolver::proto::op::{MessageType, OpCode};
use std::{fmt, io, sync::Arc, time::Duration};
use tokio::{sync::Semaphore, time::Instant};
use tokio_util::sync::CancellationToken;

const TIMEOUT: Duration = Duration::from_secs(5);
const MAX_QUERIES: usize = 64;

#[derive(Clone)]
struct Exchange {
    platform: Arc<dyn Platform>,
    network: Option<PlatformNetwork>,
    retired: CancellationToken,
    capacity: Arc<Semaphore>,
}
impl fmt::Debug for Exchange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PlatformDnsExchange")
            .field("network", &self.network)
            .finish_non_exhaustive()
    }
}

/// Cache lifetime must be checked before cache hits, too: old generations may
/// still be retained by flows while their network is being replaced.
#[derive(Debug)]
struct PlatformResolver {
    cached: Arc<dyn Resolver>,
    exchange: Arc<Exchange>,
}

pub(crate) fn resolver(platform: Arc<dyn Platform>) -> io::Result<Arc<dyn Resolver>> {
    let snapshot = platform.physical_networks()?;
    snapshot.validate()?;
    let exchange = Arc::new(Exchange {
        platform,
        // A context without a default network can still serve explicit IP
        // connections. DNS fails until a network refresh installs a new context.
        network: snapshot.default_handle.map(|handle| PlatformNetwork {
            generation: snapshot.generation,
            handle,
        }),
        retired: CancellationToken::new(),
        capacity: Arc::new(Semaphore::new(MAX_QUERIES)),
    });
    let cached = super::routing::RoutingResolver::new(
        crate::config::dns::DnsRoutingConfig {
            final_server: "platform".into(),
            ip_strategy: Default::default(),
            resolve_before_route: false,
            rules: Vec::new(),
        },
        |_| Some(exchange.clone() as Arc<dyn Resolver>),
    )?;
    Ok(Arc::new(PlatformResolver { cached, exchange }))
}

fn retired() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotConnected,
        "system DNS physical network is unavailable or retired",
    )
}

impl Exchange {
    fn current(&self) -> io::Result<PlatformNetwork> {
        if self.retired.is_cancelled() {
            return Err(retired());
        }
        let network = self.network.ok_or_else(retired)?;
        let snapshot = self.platform.physical_networks()?;
        snapshot.validate()?;
        if snapshot.generation != network.generation
            || snapshot.default_handle != Some(network.handle)
        {
            return Err(retired());
        }
        Ok(network)
    }
}

impl Resolver for Exchange {
    fn resolve_location(&self, _: &NetLocation) -> ResolveFuture {
        Box::pin(async {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "use platform DNS lookup adapter",
            ))
        })
    }
    fn request_timeout(&self) -> Option<Duration> {
        Some(TIMEOUT)
    }
    fn retire(&self) {
        self.retired.cancel();
    }
    fn exchange(&self, message: Vec<u8>) -> DnsExchangeFuture {
        self.exchange_with_deadline(message, Instant::now() + TIMEOUT)
    }
    fn exchange_with_deadline(&self, message: Vec<u8>, deadline: Instant) -> DnsExchangeFuture {
        let deadline = deadline.min(Instant::now() + TIMEOUT);
        let request = super::message::decode(&message).and_then(|request| {
            if request.metadata.message_type != MessageType::Query
                || request.metadata.op_code != OpCode::Query
                || request.queries.is_empty()
                || request.queries.len() > 16
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid platform DNS query",
                ));
            }
            Ok(request)
        });
        let this = self.clone();
        Box::pin(async move {
            let request = request?;
            let network = this.current()?;
            if Instant::now() >= deadline {
                return Err(io::ErrorKind::TimedOut.into());
            }
            let _permit = this
                .capacity
                .clone()
                .try_acquire_owned()
                .map_err(|_| crate::resources::exhausted())?;
            let raw = tokio::select! {
                biased;
                _ = this.retired.cancelled() => return Err(retired()),
                result = tokio::time::timeout_at(deadline, this.platform.clone().exchange_system_dns(PlatformDnsQuery { network, message, deadline })) => result.map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??,
            };
            this.current()?;
            if Instant::now() >= deadline {
                return Err(io::ErrorKind::TimedOut.into());
            }
            let reply = super::message::decode(&raw)?;
            if reply.metadata.message_type != MessageType::Response
                || reply.metadata.id != request.metadata.id
                || reply.metadata.op_code != request.metadata.op_code
                || reply.queries != request.queries
                || reply.metadata.truncation
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "platform DNS reply does not match its query",
                ));
            }
            // Keep the real response RCODE, including NXDOMAIN/SERVFAIL. A
            // transport error from Java must never be synthesized into one.
            Ok(raw)
        })
    }
}

impl Resolver for PlatformResolver {
    fn request_timeout(&self) -> Option<Duration> {
        Some(TIMEOUT)
    }
    fn retire(&self) {
        self.exchange.retire();
        self.cached.retire();
    }
    fn resolve_location(&self, target: &NetLocation) -> ResolveFuture {
        let exchange = self.exchange.clone();
        let cached = self.cached.clone();
        let target = target.clone();
        let deadline = Instant::now() + TIMEOUT;
        Box::pin(async move {
            exchange.current()?;
            let result = tokio::select! {
                biased;
                _ = exchange.retired.cancelled() => return Err(retired()),
                result = tokio::time::timeout_at(deadline, cached.resolve_location(&target)) => result.map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?,
            };
            exchange.current()?;
            if Instant::now() >= deadline {
                return Err(io::ErrorKind::TimedOut.into());
            }
            result
        })
    }
    fn exchange(&self, message: Vec<u8>) -> DnsExchangeFuture {
        self.exchange_with_deadline(message, Instant::now() + TIMEOUT)
    }
    fn exchange_with_deadline(&self, message: Vec<u8>, deadline: Instant) -> DnsExchangeFuture {
        let exchange = self.exchange.clone();
        let cached = self.cached.clone();
        let deadline = deadline.min(Instant::now() + TIMEOUT);
        Box::pin(async move {
            exchange.current()?;
            if Instant::now() >= deadline {
                return Err(io::ErrorKind::TimedOut.into());
            }
            let result = tokio::select! {
                biased;
                _ = exchange.retired.cancelled() => return Err(retired()),
                result = tokio::time::timeout_at(deadline, cached.exchange_with_deadline(message, deadline)) => result.map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?,
            };
            exchange.current()?;
            if Instant::now() >= deadline {
                return Err(io::ErrorKind::TimedOut.into());
            }
            result
        })
    }
}

#[cfg(test)]
#[path = "platform_tests.rs"]
mod tests;
