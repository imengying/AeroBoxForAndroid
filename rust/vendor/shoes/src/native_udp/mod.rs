//! Native UDP clients. Every datagram uses the selected route's carrier;
//! creating a UDP-capable leaf never bypasses intermediate proxy hops.
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use futures::ready;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{
    address::{Address, NetLocation, ResolvedLocation},
    async_stream::{
        AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage, AsyncShutdownMessage,
        AsyncStream, AsyncWriteMessage,
    },
    config::{ResolvedClientConfig, ResolvedClientProxyConfig, Transport},
    socks_handler::{CMD_UDP_ASSOCIATE, SocksTcpClientHandler},
    tcp::carrier_dialer::CarrierDialer,
};

mod shadowsocks;
#[cfg(test)]
mod tests;

const MAX_PACKET: usize = 65_507;

pub(crate) enum Client {
    Socks(SocksTcpClientHandler),
    Shadowsocks(Arc<shadowsocks::Client>),
}

impl std::fmt::Debug for Client {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Socks(_) => "NativeSocksUdp",
            Self::Shadowsocks(_) => "NativeShadowsocksUdp",
        })
    }
}

impl Client {
    pub(crate) fn from_config(config: &ResolvedClientConfig) -> io::Result<Option<Self>> {
        if config.transport != Transport::Tcp
            && !(config.transport == Transport::Quic
                && crate::ss_plugin::quic::resolved(&config.protocol).is_some()) {
            return Ok(None);
        }
        Ok(match &config.protocol {
            ResolvedClientProxyConfig::Socks { username, password } => {
                let auth = match (username, password) {
                    (None, None) => None,
                    (username, password) => Some((
                        username.clone().unwrap_or_default(),
                        password.clone().unwrap_or_default(),
                    )),
                };
                Some(Self::Socks(SocksTcpClientHandler::new(auth)))
            }
            ResolvedClientProxyConfig::Shadowsocks {
                config,
                udp_enabled: true,
                ..
            } => Some(Self::Shadowsocks(Arc::new(shadowsocks::Client::new(
                config.clone(),
            )?))),
            _ => None,
        })
    }

    pub(crate) async fn connect(
        &self,
        dialer: Arc<dyn CarrierDialer>,
        proxy: &NetLocation,
        target: ResolvedLocation,
    ) -> io::Result<Box<dyn AsyncMessageStream>> {
        let target = target
            .resolved_addr()
            .map(|address| NetLocation::from_ip_addr(address.ip(), address.port()))
            .unwrap_or_else(|| target.location().clone());
        let _ = crate::socks_handler::write_location_to_vec(&target)?;
        if target.port() == 0 {
            return Err(invalid("UDP destination port must not be zero"));
        }
        let (carrier, codec, control) = match self {
            Self::Shadowsocks(client) => (
                dialer.open_datagram(None).await?,
                Codec::Shadowsocks(client.session()?),
                None,
            ),
            Self::Socks(handler) => {
                let (control, relay, early) =
                    tokio::time::timeout(std::time::Duration::from_secs(10), async {
                        handler
                            .setup_command(
                                dialer.open_stream().await?,
                                NetLocation::from_ip_addr(
                                    std::net::Ipv4Addr::UNSPECIFIED.into(),
                                    0,
                                ),
                                CMD_UDP_ASSOCIATE,
                            )
                            .await
                    })
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "SOCKS UDP ASSOCIATE timed out")
                    })??;
                if early.is_some() {
                    return Err(invalid("unexpected SOCKS UDP control data"));
                }
                if relay.port() == 0 {
                    return Err(invalid("SOCKS UDP relay returned port zero"));
                }
                let relay = if relay
                    .to_socket_addr_nonblocking()
                    .is_some_and(|address| address.ip().is_unspecified())
                {
                    NetLocation::new(proxy.address().clone(), relay.port())
                } else {
                    relay
                };
                let carrier = dialer.open_datagram(Some(relay.into())).await?;
                (carrier, Codec::Socks, Some(control))
            }
        };
        Ok(Box::new(Datagrams {
            carrier,
            codec,
            control,
            target,
            read_buffer: vec![0; 65_535],
            pending: None,
        }))
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

enum Codec {
    Socks,
    Shadowsocks(shadowsocks::Session),
}
impl Codec {
    fn encode(&mut self, target: &NetLocation, payload: &[u8]) -> io::Result<Vec<u8>> {
        if payload.len() > MAX_PACKET {
            return Err(invalid("UDP payload exceeds datagram limit"));
        }
        let packet = match self {
            Self::Socks => {
                let mut packet = vec![0; 3];
                packet.extend(crate::socks_handler::write_location_to_vec(target)?);
                packet.extend_from_slice(payload);
                packet
            }
            Self::Shadowsocks(session) => session.encode(target, payload)?,
        };
        if packet.len() > MAX_PACKET {
            return Err(invalid(
                "UDP payload plus proxy header exceeds datagram limit",
            ));
        }
        Ok(packet)
    }

    fn decode(&mut self, target: &NetLocation, packet: &mut [u8]) -> io::Result<Vec<u8>> {
        match self {
            Self::Socks => {
                let (source, payload) = crate::socks5_udp_relay::parse_socks5_udp_packet(packet)?;
                check_source(target, &source)?;
                Ok(payload.to_vec())
            }
            Self::Shadowsocks(session) => session.decode(target, packet),
        }
    }
}

fn check_source(target: &NetLocation, source: &NetLocation) -> io::Result<()> {
    if target.port() != source.port() {
        return Err(invalid("unexpected proxy UDP response port"));
    }
    match (target.address(), source.address()) {
        (Address::Hostname(a), Address::Hostname(b)) if a.eq_ignore_ascii_case(b) => Ok(()),
        (Address::Hostname(_), Address::Ipv4(_) | Address::Ipv6(_)) => Ok(()),
        _ if target
            .to_socket_addr_nonblocking()
            .zip(source.to_socket_addr_nonblocking())
            .is_some_and(|(a, b)| a.ip().to_canonical() == b.ip().to_canonical()) =>
        {
            Ok(())
        }
        _ => Err(invalid("unexpected proxy UDP response address")),
    }
}

struct Datagrams {
    carrier: Box<dyn AsyncMessageStream>,
    codec: Codec,
    control: Option<Box<dyn AsyncStream>>,
    target: NetLocation,
    read_buffer: Vec<u8>,
    pending: Option<(Vec<u8>, Vec<u8>)>,
}

impl Datagrams {
    fn check_control(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if let Some(control) = &mut self.control {
            let mut byte = [0];
            let mut buf = ReadBuf::new(&mut byte);
            match Pin::new(control).poll_read(cx, &mut buf) {
                Poll::Pending => {}
                Poll::Ready(Err(error)) => return Err(error),
                Poll::Ready(Ok(())) => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "SOCKS UDP control connection ended",
                    ));
                }
            }
        }
        Ok(())
    }
}

impl AsyncReadMessage for Datagrams {
    fn read_message_eof_on_empty(&self) -> bool {
        false
    }
    fn poll_read_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        this.check_control(cx)?;
        for _ in 0..32 {
            let mut packet = ReadBuf::new(&mut this.read_buffer);
            ready!(Pin::new(&mut this.carrier).poll_read_message(cx, &mut packet))?;
            let size = packet.filled().len();
            if size == 0 && this.carrier.read_message_eof_on_empty() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "UDP carrier closed",
                )));
            }
            let decoded = this
                .codec
                .decode(&this.target, &mut this.read_buffer[..size]);
            match decoded {
                Ok(payload) => {
                    if payload.len() > buf.remaining() {
                        return Poll::Ready(Err(invalid("UDP receive buffer too small")));
                    }
                    buf.put_slice(&payload);
                    return Poll::Ready(Ok(()));
                }
                Err(_) => continue, // A bad/replayed datagram does not tear down the session.
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}
impl AsyncWriteMessage for Datagrams {
    fn poll_write_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        payload: &[u8],
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        this.check_control(cx)?;
        if this
            .pending
            .as_ref()
            .is_none_or(|(pending, _)| pending != payload)
        {
            let packet = this.codec.encode(&this.target, payload)?;
            this.pending = Some((payload.to_vec(), packet));
        }
        let packet = &this.pending.as_ref().unwrap().1;
        let result = ready!(Pin::new(&mut this.carrier).poll_write_message(cx, packet));
        this.pending = None;
        Poll::Ready(result)
    }
}
impl AsyncFlushMessage for Datagrams {
    fn poll_flush_message(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.carrier).poll_flush_message(cx)
    }
}
impl AsyncShutdownMessage for Datagrams {
    fn poll_shutdown_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.pending = None;
        if let Some(control) = &mut self.control {
            ready!(Pin::new(control).poll_shutdown(cx))?;
        }
        self.control = None;
        Pin::new(&mut self.carrier).poll_shutdown_message(cx)
    }
}
impl AsyncPing for Datagrams {
    fn supports_ping(&self) -> bool {
        false
    }
    fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}
impl AsyncMessageStream for Datagrams {}
