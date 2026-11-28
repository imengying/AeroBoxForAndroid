//! TUIC's optional provisional QUIC leg. The ordinary QUIC path stays confirmed.
use super::*;
use crate::tcp::carrier_dialer::{
    ConfirmedQuicCarrier, EarlyDataOutcome, PendingQuicCarrier, QuicCarrier,
};
use std::io;
use tokio::time::Instant;

/// A caller may hold streams or Connection clones after cancelling setup.
/// Explicitly close the provisional leg even when those clones keep it alive.
struct CloseUnconfirmed(Option<QuicCarrier>);
impl Drop for CloseUnconfirmed {
    fn drop(&mut self) {
        if let Some(carrier) = &self.0 {
            carrier
                .connection
                .close(0_u32.into(), b"QUIC setup cancelled or failed");
        }
    }
}

enum InitialHandshake {
    Full(quinn::Connecting),
    Early(quinn::ZeroRttAccepted),
}

struct Attempt {
    initial: InitialHandshake,
    guard: CloseUnconfirmed,
    endpoint: Arc<QuicEndpoint>,
    address: SocketAddr,
    domain: String,
    ech: Option<QuicEch>,
    prepared: Option<crate::ech::Prepared>,
}

fn verify_completed(connection: &quinn::Connection) -> io::Result<()> {
    if let Some(error) = connection.close_reason() {
        return Err(io::Error::other(error));
    }
    // ZeroRttAccepted also resolves false when its channel closes on error.
    // The ordinary exporter exists only after the authenticated TLS Finished;
    // do not classify an incomplete/failed handshake as replayable rejection.
    connection
        .export_keying_material(&mut [0; 1], b"aerobox-quic-handshake-complete", b"")
        .map_err(|_| io::Error::other("QUIC handshake has no authenticated exporter"))
}

impl Attempt {
    async fn finish(mut self) -> io::Result<ConfirmedQuicCarrier> {
        let attempted = matches!(&self.initial, InitialHandshake::Early(_));
        let initial = match self.initial {
            InitialHandshake::Full(connecting) => match connecting.await {
                Ok(connection) => {
                    self.guard.0 = Some(QuicCarrier {
                        connection,
                        _endpoint: self.endpoint.clone(),
                    });
                    Ok(EarlyDataOutcome::NotAttempted)
                }
                Err(error) => Err(io::Error::other(error)),
            },
            InitialHandshake::Early(accepted) => {
                let accepted = accepted.await;
                verify_completed(&self.guard.0.as_ref().unwrap().connection).map(|_| {
                    if accepted {
                        EarlyDataOutcome::Accepted
                    } else {
                        EarlyDataOutcome::Rejected
                    }
                })
            }
        };
        let outcome = match initial {
            Ok(outcome) => outcome,
            Err(error) => {
                let (Some(ech), Some(previous)) = (&self.ech, &self.prepared) else {
                    return Err(error);
                };
                let Some(mode) = previous.retry.take()? else {
                    return Err(error);
                };
                // RetryConfigs is populated only after strict outer-name
                // certificate verification and Finished. Retry once, retaining
                // the original total/attempt deadline around this future.
                let mut base = (*ech.base).clone();
                base.enable_early_data = false;
                let retry = crate::ech::Prepared::new(&Arc::new(base), Arc::new(mode))?;
                let connection = self
                    .endpoint
                    .connect_with(ech.client_config(&retry)?, self.address, &self.domain)?
                    .await
                    .map_err(io::Error::other)?;
                self.guard.0 = Some(QuicCarrier {
                    connection,
                    _endpoint: self.endpoint.clone(),
                });
                verify_completed(&self.guard.0.as_ref().unwrap().connection)?;
                ech.policy.accepted_retry(&previous.mode, retry.mode);
                if attempted {
                    EarlyDataOutcome::Rejected
                } else {
                    EarlyDataOutcome::NotAttempted
                }
            }
        };
        let carrier = self
            .guard
            .0
            .take()
            .expect("successful QUIC handshake has a leg");
        Ok(ConfirmedQuicCarrier {
            carrier,
            early_data: outcome,
        })
    }
}

impl SocketConnectorImpl {
    pub(super) fn quic_endpoint(&self, address: SocketAddr) -> io::Result<Arc<QuicEndpoint>> {
        let TransportConfig::Quic {
            endpoints,
            next_endpoint_index,
            hopping,
            network_endpoints,
            naive,
            ..
        } = &self.transport
        else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "not a QUIC socket connector",
            ));
        };
        if let Some(naive) = naive {
            self.network.udp(|binding| {
                naive.open(address, self.bind_interface.clone(), binding)
            })
        } else if let Some(hopping) = hopping {
            self.network
                .udp(|binding| hopping.open(address, self.bind_interface.clone(), binding.cloned()))
        } else if let Some(endpoints) = network_endpoints {
            self.network
                .udp(|binding| endpoints.open(address, binding.unwrap()))
        } else {
            let index =
                next_endpoint_index.fetch_add(1, Ordering::Relaxed) as usize % endpoints.len();
            Ok(endpoints[index].clone())
        }
    }

    pub(super) async fn connect_quic_early_candidates(
        &self,
        resolver: &Arc<dyn Resolver>,
        target: &ResolvedLocation,
        overall_deadline: Instant,
    ) -> io::Result<PendingQuicCarrier> {
        let TransportConfig::Quic {
            sni_hostname, ech, ..
        } = &self.transport
        else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "not a QUIC socket connector",
            ));
        };
        let mut addresses = match target.resolved_addr() {
            Some(address) => vec![address],
            None => resolve_addresses(resolver, target.location()).await?,
        };
        if target.address().hostname().is_some() {
            addresses.sort_by_key(SocketAddr::is_ipv6);
        }
        let name = target.address().to_string();
        let domain = sni_hostname.as_deref().unwrap_or(&name);
        let mut last_error = io::Error::other("no resolved addresses succeeded");
        for address in addresses {
            let deadline = overall_deadline.min(Instant::now() + NATIVE_QUIC_ATTEMPT_TIMEOUT);
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "QUIC connect timed out",
                ));
            }
            let endpoint = match self.quic_endpoint(address) {
                Ok(endpoint) => endpoint,
                Err(error) => {
                    last_error = error;
                    continue;
                }
            };
            let prepared = match ech {
                Some(ech) => Some(
                    tokio::time::timeout_at(deadline, ech.policy.prepare(&ech.base, resolver))
                        .await
                        .map_err(io::Error::from)??,
                ),
                None => None,
            };
            let connecting = match (ech, &prepared) {
                (Some(ech), Some(prepared)) => {
                    endpoint.connect_with(ech.client_config(prepared)?, address, domain)
                }
                _ => endpoint.connect(address, domain),
            };
            let connecting = match connecting {
                Ok(connecting) => connecting,
                Err(error) => {
                    last_error = error;
                    continue;
                }
            };
            let (initial, early) = match connecting.into_0rtt() {
                Ok((connection, accepted)) => (
                    InitialHandshake::Early(accepted),
                    Some(QuicCarrier {
                        connection,
                        _endpoint: endpoint.clone(),
                    }),
                ),
                Err(connecting) => (InitialHandshake::Full(connecting), None),
            };
            let attempt = Attempt {
                initial,
                guard: CloseUnconfirmed(early.clone()),
                endpoint,
                address,
                domain: domain.to_owned(),
                ech: ech.clone(),
                prepared,
            };
            let network = crate::network_tasks::NetworkTasks::current();
            let completion = Box::pin(async move {
                tokio::select! {
                    biased;
                    _ = async {
                        match network {
                            Some(network) => network.cancelled.cancelled_owned().await,
                            None => std::future::pending().await,
                        }
                    } => Err(io::Error::new(io::ErrorKind::Interrupted, "QUIC network retired")),
                    result = tokio::time::timeout_at(deadline, attempt.finish()) => {
                        let confirmed = result.map_err(io::Error::from)??;
                        // timeout_at polls its inner future first. A result that
                        // becomes ready after the deadline still fails closed.
                        if Instant::now() >= deadline {
                            confirmed.carrier.connection.close(0_u32.into(), b"QUIC setup timed out");
                            return Err(io::Error::new(io::ErrorKind::TimedOut, "QUIC connect timed out"));
                        }
                        Ok(confirmed)
                    },
                }
            });
            if early.is_some() {
                // Once a provisional leg is exposed, generic failures must not
                // redial another address and duplicate early application data.
                return Ok(PendingQuicCarrier {
                    early,
                    deadline,
                    completion,
                });
            }
            match completion.await {
                Ok(confirmed) => {
                    return Ok(PendingQuicCarrier::confirmed(confirmed.carrier, deadline));
                }
                Err(error) => {
                    last_error = error;
                }
            }
        }
        Err(last_error)
    }
}
