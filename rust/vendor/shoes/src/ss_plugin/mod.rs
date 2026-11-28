//! In-process SIP003 transports. Native Shadowsocks UDP bypasses these TCP
//! transports; UoT and multiplex sessions pass through them with the TCP bytes.
pub(crate) mod quic;
#[cfg(test)]
mod quic_tests;
mod simple_obfs;
#[cfg(test)]
mod tests;
mod xray_mux;

use crate::{
    address::{NetLocation, ResolvedLocation},
    async_stream::{AsyncMessageStream, AsyncStream},
    resolver::Resolver,
    tcp::tcp_handler::{ClientTransport, TcpClientHandler, TcpClientSetupResult},
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{io, sync::Arc};

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ObfsMode {
    #[default]
    Http,
    Tls,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum V2rayMode {
    #[default]
    Websocket,
    Quic,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Config {
    ObfsLocal {
        #[serde(default)]
        mode: ObfsMode,
        #[serde(default)]
        host: String,
    },
    V2rayPlugin {
        #[serde(default)]
        mode: V2rayMode,
        #[serde(default = "default_ws_host")]
        host: String,
        #[serde(default = "default_ws_path")]
        path: String,
        #[serde(default = "default_mux")]
        mux: i32,
        #[serde(default)]
        tls: bool,
        #[serde(default)]
        sni_hostname: Option<String>,
        #[serde(default)]
        root_certificates: Vec<String>,
    },
}
fn default_ws_host() -> String {
    "cloudfront.com".into()
}
fn default_ws_path() -> String {
    "/".into()
}
fn default_mux() -> i32 {
    1
}

impl Config {
    pub fn validate(&self) -> io::Result<()> {
        match self {
            Self::ObfsLocal { host, .. } => {
                if host.len() > 255
                    || !host.is_ascii()
                    || host.bytes().any(|b| b <= b' ' || b == 127)
                {
                    return Err(invalid("invalid simple-obfs host"));
                }
                if !host.is_empty() {
                    host.parse::<http::uri::Authority>()
                        .map_err(io::Error::other)?;
                }
            }
            Self::V2rayPlugin {
                mode,
                host,
                path,
                tls,
                sni_hostname,
                root_certificates,
                ..
            } => {
                if *mode == V2rayMode::Quic && !tls {
                    return Err(invalid("v2ray-plugin QUIC requires TLS"));
                }
                if host.len() > 255 || host.is_empty() {
                    return Err(invalid("invalid v2ray-plugin host"));
                }
                host.parse::<http::uri::Authority>()
                    .map_err(io::Error::other)?;
                if path.len() > 8192
                    || !path.starts_with('/')
                    || path.bytes().any(|c| c <= b' ' || c == 127)
                {
                    return Err(invalid("invalid v2ray-plugin WebSocket path"));
                }
                path.parse::<http::uri::PathAndQuery>()
                    .map_err(io::Error::other)?;
                if let Some(name) = sni_hostname {
                    rustls::pki_types::ServerName::try_from(name.clone())
                        .map_err(io::Error::other)?;
                }
                if *tls {
                    tls_config(root_certificates)?;
                } else if !root_certificates.is_empty() {
                    return Err(invalid("v2ray-plugin trust certificates require TLS"));
                }
            }
        }
        Ok(())
    }
    pub(crate) fn roots_mut(&mut self) -> Option<&mut Vec<String>> {
        match self {
            Self::V2rayPlugin {
                root_certificates, ..
            } => Some(root_certificates),
            _ => None,
        }
    }
    pub(crate) fn is_quic(&self) -> bool {
        matches!(
            self,
            Self::V2rayPlugin {
                mode: V2rayMode::Quic,
                ..
            }
        )
    }
}

fn tls_config(roots: &[String]) -> io::Result<rustls::ClientConfig> {
    crate::rustls_config_util::try_create_client_config_with_options(
        true,
        vec![],
        vec!["http/1.1".into()],
        true,
        None,
        false,
        &Default::default(),
        &crate::config::tls::TlsClientOptions {
            root_certificates: roots.to_vec(),
            ..Default::default()
        },
    )
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[derive(Debug)]
pub struct Handler {
    options: Config,
    port: u16,
    carrier: Option<Box<dyn TcpClientHandler>>,
    inner: Box<dyn TcpClientHandler>,
}

impl Handler {
    pub fn new(
        options: Config,
        hop: &NetLocation,
        inner: Box<dyn TcpClientHandler>,
    ) -> io::Result<Self> {
        options.validate()?;
        let carrier = match &options {
            Config::V2rayPlugin {
                mode: V2rayMode::Websocket,
                host,
                path,
                tls,
                sni_hostname,
                root_certificates,
                ..
            } => {
                let mut handler: Box<dyn TcpClientHandler> =
                    Box::new(crate::websocket::WebsocketTcpClientHandler::new(
                        host.clone(),
                        Some(path.clone()),
                        None,
                        crate::config::WebsocketPingType::PingFrame,
                        Box::new(crate::port_forward_handler::PortForwardClientHandler),
                    ));
                if *tls {
                    let name = crate::tcp::tcp_client_handler_factory::tls_verification_name(
                        sni_hostname.clone(),
                        hop,
                    )?;
                    handler = Box::new(crate::tls_client_handler::TlsClientHandler::new(
                        Arc::new(tls_config(root_certificates)?),
                        None,
                        name,
                        handler,
                    ));
                }
                Some(handler)
            }
            _ => None,
        };
        Ok(Self {
            options,
            port: hop.port(),
            carrier,
            inner,
        })
    }

    async fn wrap(&self, stream: Box<dyn AsyncStream>) -> io::Result<Box<dyn AsyncStream>> {
        match &self.options {
            Config::V2rayPlugin {
                mode: V2rayMode::Quic,
                ..
            } => Ok(stream),
            Config::ObfsLocal { mode, host } => Ok(Box::new(simple_obfs::Stream::new(
                stream,
                *mode,
                host.clone(),
                self.port,
            ))),
            Config::V2rayPlugin { mux, .. } => {
                let stream = self
                    .carrier
                    .as_ref()
                    .expect("validated WebSocket carrier")
                    .setup_client_tcp_stream(
                        stream,
                        ResolvedLocation::new(NetLocation::from_ip_addr(
                            std::net::Ipv4Addr::LOCALHOST.into(),
                            self.port,
                        )),
                    )
                    .await?
                    .client_stream;
                Ok(if *mux > 0 {
                    Box::new(xray_mux::Stream::new(stream))
                } else {
                    stream
                })
            }
        }
    }
}

#[async_trait]
impl TcpClientHandler for Handler {
    fn has_session_pool(&self) -> bool {
        self.inner.has_session_pool()
    }
    fn supports_udp_over_tcp(&self) -> bool {
        self.inner.supports_udp_over_tcp()
    }
    async fn prepare_target(
        &self,
        target: ResolvedLocation,
        resolver: &Arc<dyn Resolver>,
    ) -> io::Result<ResolvedLocation> {
        self.inner.prepare_target(target, resolver).await
    }
    async fn connect_client_tcp(
        &self,
        transport: ClientTransport<'_>,
        target: ResolvedLocation,
    ) -> io::Result<TcpClientSetupResult> {
        self.inner
            .connect_client_tcp(transport.wrap(|stream| self.wrap(stream)), target)
            .await
    }
    async fn connect_client_udp(
        &self,
        transport: ClientTransport<'_>,
        target: ResolvedLocation,
    ) -> io::Result<Box<dyn AsyncMessageStream>> {
        self.inner
            .connect_client_udp(transport.wrap(|stream| self.wrap(stream)), target)
            .await
    }
    async fn setup_client_tcp_stream(
        &self,
        stream: Box<dyn AsyncStream>,
        target: ResolvedLocation,
    ) -> io::Result<TcpClientSetupResult> {
        self.inner
            .setup_client_tcp_stream(self.wrap(stream).await?, target)
            .await
    }
    async fn setup_client_udp_bidirectional(
        &self,
        stream: Box<dyn AsyncStream>,
        target: ResolvedLocation,
    ) -> io::Result<Box<dyn AsyncMessageStream>> {
        self.inner
            .setup_client_udp_bidirectional(self.wrap(stream).await?, target)
            .await
    }
}
