use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use hickory_proto::op::{Header, HeaderCounts, Message, ResponseCode};
use hickory_server::{
    Server,
    net::runtime::Time,
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    zone_handler::MessageResponseBuilder,
};
use tokio::{
    net::{TcpListener, UdpSocket},
    sync::{Semaphore, watch},
    task::JoinSet,
};

use crate::{
    config::{Config, Listener},
    resolver::{Resolver, local_response, validate_request},
    upstream::Forwarder,
};

mod doh;

#[derive(Clone)]
pub struct Handler {
    resolver: Arc<Resolver>,
    permits: Arc<Semaphore>,
    timeout: Duration,
}

impl Handler {
    pub fn new(resolver: Arc<Resolver>, max_inflight: usize, timeout: Duration) -> Self {
        Self {
            resolver,
            permits: Arc::new(Semaphore::new(max_inflight)),
            timeout,
        }
    }

    async fn resolve(&self, message: Message) -> Message {
        if let Some(code) = validate_request(&message) {
            return local_response(&message, code);
        }
        let Ok(_permit) = self.permits.try_acquire() else {
            return local_response(&message, ResponseCode::ServFail);
        };
        let result = match tokio::time::Instant::now().checked_add(self.timeout) {
            Some(deadline) => {
                self.resolver
                    .answer_with_deadline(message.clone(), deadline)
                    .await
            }
            // Match Tokio's duration-based timeout when the deadline cannot be represented.
            None => self.resolver.answer(message.clone()).await,
        };
        result.unwrap_or_else(|_| local_response(&message, ResponseCode::ServFail))
    }
}

#[async_trait]
impl RequestHandler for Handler {
    async fn handle_request<R: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let response = match Message::from_vec(request.as_slice()) {
            Ok(message) => self.resolve(message).await,
            Err(_) => Message::error_msg(
                request.metadata.id,
                request.metadata.op_code,
                ResponseCode::FormErr,
            ),
        };
        let mut builder = MessageResponseBuilder::from_message_request(request);
        // Use the downstream payload limit, not the upstream's advertised limit.
        let mut edns = response.edns.clone();
        if let Some(client_edns) = &request.edns {
            edns.get_or_insert_with(Default::default)
                .set_max_payload(client_edns.max_payload().clamp(512, 1232));
        } else {
            edns = None;
        }
        if let Some(edns) = &edns {
            builder.edns(edns);
        }
        let message = builder.build(
            response.metadata,
            &response.answers,
            &response.authorities,
            std::iter::empty(),
            &response.additionals,
        );
        response_handle
            .send_response(message)
            .await
            .unwrap_or_else(|_| {
                let mut metadata = response.metadata;
                metadata.response_code = ResponseCode::ServFail;
                Header {
                    metadata,
                    counts: HeaderCounts::default(),
                }
                .into()
            })
    }
}

pub async fn serve(config: Config) -> Result<()> {
    let upstream = Arc::new(Forwarder::new(&config.upstreams, config.upstream_timeout)?);
    let resolver = Arc::new(Resolver::new(config.policy, upstream));
    let handler = Handler::new(resolver, config.max_inflight, config.request_timeout);
    let mut server = Server::new(handler.clone());
    // Bind everything before starting listeners, so a partial startup is not advertised.
    let mut sockets = Vec::new();
    let mut http = Vec::new();
    for listener in &config.listeners {
        if let Listener::Dns { address } = listener {
            let udp = UdpSocket::bind(address)
                .await
                .with_context(|| format!("cannot bind UDP listener {address}"))?;
            let tcp = TcpListener::bind(address)
                .await
                .with_context(|| format!("cannot bind TCP listener {address}"))?;
            sockets.push((udp, tcp));
        } else {
            let bound = doh::BoundListener::bind(listener)
                .await
                .with_context(|| format!("cannot start DoH listener {}", listener.address()))?;
            http.push((listener, bound));
        }
    }
    let has_dns = !sockets.is_empty();
    for (udp, tcp) in sockets {
        server.register_socket(udp);
        server.register_listener(tcp, Duration::from_secs(30), 32);
    }
    let (shutdown, receiver) = watch::channel(false);
    let mut http_tasks = JoinSet::new();
    for (listener, bound) in http {
        let address = listener.address();
        let (protocol, path) = match listener {
            Listener::Http { path, .. } => ("HTTP", path),
            Listener::Https { path, .. } => ("HTTPS", path),
            Listener::Dns { .. } => unreachable!("HTTP listeners only"),
        };
        if bound.unauthenticated() {
            eprintln!(
                "warning: {protocol} listener {address} has no auth tokens; authentication is disabled"
            );
        }
        http_tasks.spawn(bound.run(
            handler.clone(),
            config.max_inflight,
            config.request_timeout,
            receiver.clone(),
        ));
        eprintln!("listening on {address} ({protocol}, {path})");
    }
    for listener in &config.listeners {
        if let Listener::Dns { address } = listener {
            eprintln!("listening on {address} (UDP/TCP)");
        }
    }
    let result = tokio::select! {
        result = server.block_until_done(), if has_dns => result.context("DNS server stopped"),
        result = http_tasks.join_next(), if !http_tasks.is_empty() => {
            match result.expect("HTTP tasks exist") {
                Ok(Err(error)) => Err(error),
                Err(error) => Err(error.into()),
                Ok(Ok(())) => Err(anyhow!("DoH listener stopped unexpectedly")),
            }
        }
        result = shutdown_signal() => result,
    };
    let _ = shutdown.send(true);
    let stopped = tokio::time::timeout(Duration::from_secs(5), async {
        server.shutdown_gracefully().await?;
        while let Some(result) = http_tasks.join_next().await {
            result??;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("DNS shutdown timed out")?;
    result.and(stopped)
}

async fn shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result?,
            _ = terminate.recv() => {},
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await?;
    Ok(())
}
