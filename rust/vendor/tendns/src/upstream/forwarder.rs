use std::{net::IpAddr, sync::Arc, time::Duration};

use anyhow::{Context, Result, bail, ensure};
use async_trait::async_trait;
use hickory_proto::op::{DnsRequest, Message, MessageType, ResponseCode};
use hickory_resolver::{
    ConnectionProvider, PoolContext, TlsConfig,
    config::{ConnectionConfig, ResolverOpts},
    net::{
        runtime::TokioRuntimeProvider,
        xfer::{DnsExchange, DnsHandle, FirstAnswer},
    },
};
use tokio::sync::Mutex;

use super::Exchange;
use crate::config::Upstream;

pub struct Forwarder {
    targets: Vec<Target>,
    context: Arc<PoolContext>,
    runtime: TokioRuntimeProvider,
    timeout: Duration,
}

struct Target {
    ip: IpAddr,
    connections: Vec<Connection>,
}

struct Connection {
    config: ConnectionConfig,
    handle: Mutex<Option<DnsExchange<TokioRuntimeProvider>>>,
}

impl Forwarder {
    pub fn new(upstreams: &[Upstream], timeout: Duration) -> Result<Self> {
        Self::with_tls(upstreams, timeout, TlsConfig::new()?)
    }

    pub fn with_tls(upstreams: &[Upstream], timeout: Duration, tls: TlsConfig) -> Result<Self> {
        ensure!(
            !upstreams.is_empty(),
            "configure at least one upstream to serve DNS"
        );
        let mut options = ResolverOpts::default();
        options.timeout = timeout;
        let context = Arc::new(PoolContext::new(options, tls));
        let mut targets = Vec::new();
        for upstream in upstreams {
            let (ips, configs) = match upstream {
                Upstream::Plain(addr) => {
                    let mut udp = ConnectionConfig::udp();
                    udp.port = addr.port();
                    let mut tcp = ConnectionConfig::tcp();
                    tcp.port = addr.port();
                    (vec![addr.ip()], vec![udp, tcp])
                }
                Upstream::Doh { url, bootstrap } => {
                    let mut path = url.path().to_owned();
                    if let Some(query) = url.query() {
                        path.push('?');
                        path.push_str(query);
                    }
                    let mut config = ConnectionConfig::https(
                        Arc::from(url.host_str().context("missing DoH host")?),
                        Some(Arc::from(path)),
                    );
                    config.port = url.port_or_known_default().context("missing DoH port")?;
                    (bootstrap.clone(), vec![config])
                }
            };
            for ip in ips {
                targets.push(Target {
                    ip,
                    connections: configs
                        .iter()
                        .map(|config| Connection {
                            config: config.clone(),
                            handle: Mutex::new(None),
                        })
                        .collect(),
                });
            }
        }
        Ok(Self {
            targets,
            context,
            runtime: TokioRuntimeProvider::default(),
            timeout,
        })
    }

    async fn send(&self, target: &Target, conn: &Connection, request: &Message) -> Result<Message> {
        let mut reconnect = true;
        let response = loop {
            let (handle, reused) = {
                let mut slot = conn.handle.lock().await;
                let reused = slot.is_some();
                if slot.is_none() {
                    *slot = Some(
                        self.runtime
                            .new_connection(target.ip, &conn.config, &self.context)?
                            .await?,
                    );
                }
                (slot.as_ref().expect("initialized handle").clone(), reused)
            };
            match handle
                .send(DnsRequest::from(request.clone()))
                .first_answer()
                .await
            {
                Ok(response) => break response.into_message(),
                Err(_) if reused && reconnect => {
                    // An idle TCP/HTTP2 connection may have closed since the last query.
                    *conn.handle.lock().await = None;
                    reconnect = false;
                }
                Err(error) => return Err(error.into()),
            }
        };
        ensure!(
            response.metadata.message_type == MessageType::Response
                && response.metadata.op_code == request.metadata.op_code,
            "invalid upstream response header"
        );
        ensure!(
            response.queries == request.queries,
            "upstream question does not match request"
        );
        Ok(response)
    }
}

#[async_trait]
impl Exchange for Forwarder {
    async fn exchange(&self, message: Message) -> Result<Message> {
        let mut last_dns_error = None;
        let mut last_error = None;
        for target in &self.targets {
            for conn in &target.connections {
                let result = tokio::time::timeout(self.timeout, self.send(target, conn, &message))
                    .await
                    .unwrap_or_else(|error| Err(error.into()));
                match result {
                    Ok(mut response) => {
                        if response.metadata.truncation {
                            continue;
                        }
                        response.metadata.id = message.metadata.id;
                        if matches!(
                            response.metadata.response_code,
                            ResponseCode::ServFail | ResponseCode::Refused
                        ) {
                            last_dns_error = Some(response);
                            break;
                        }
                        return Ok(response);
                    }
                    Err(error) => {
                        last_error = Some(error);
                        *conn.handle.lock().await = None;
                    }
                }
            }
        }
        if let Some(response) = last_dns_error {
            return Ok(response);
        }
        if let Some(error) = last_error {
            return Err(error.context("all configured upstreams failed"));
        }
        bail!("all configured upstreams failed")
    }
}
