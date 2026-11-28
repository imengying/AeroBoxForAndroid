//! UDP encodings shared by VMess and VLESS clients.
use std::io::{self, ErrorKind};
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use serde::{Deserialize, Serialize};
use tokio::io::ReadBuf;

use crate::address::{Address, NetLocation, ResolvedLocation};
use crate::async_stream::{
    AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage, AsyncShutdownMessage,
    AsyncWriteMessage,
};
use crate::resolver::Resolver;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum PacketEncoding {
    #[default]
    #[serde(rename = "none", alias = "")]
    Native,
    #[serde(rename = "xudp")]
    Xudp,
    #[serde(rename = "packetaddr")]
    PacketAddr,
}

impl PacketEncoding {
    pub(crate) fn validate_vision(self) -> io::Result<()> {
        if self == Self::Xudp {
            Ok(())
        } else {
            Err(io::Error::new(
                ErrorKind::InvalidInput,
                "VLESS Vision UDP requires packet_encoding: xudp",
            ))
        }
    }
}

pub(crate) fn packet_addr_destination() -> NetLocation {
    NetLocation::new(Address::Hostname("sp.packet-addr.v2fly.arpa".into()), 0)
}

pub(crate) async fn packet_addr_target(
    target: ResolvedLocation,
    resolver: Option<&Arc<dyn Resolver>>,
) -> io::Result<SocketAddr> {
    if let Some(address) = target
        .resolved_addr()
        .or_else(|| target.location().to_socket_addr_nonblocking())
    {
        return Ok(SocketAddr::new(address.ip(), target.location().port()));
    }
    let resolver = resolver.ok_or_else(|| {
        io::Error::new(
            ErrorKind::InvalidInput,
            "packetaddr hostname requires a configured resolver",
        )
    })?;
    let addresses = resolver.resolve_location(target.location()).await?;
    addresses
        .first()
        .map(|address| SocketAddr::new(address.ip(), target.location().port()))
        .ok_or_else(|| io::Error::new(ErrorKind::NotFound, "packetaddr destination has no address"))
}

/// Packetaddr adds the IP endpoint inside each protocol datagram. Keep pending
/// reads and writes so cancellation and a small consumer buffer preserve packets.
pub(crate) struct PacketAddrStream {
    inner: Box<dyn AsyncMessageStream>,
    target: SocketAddr,
    write: Option<Vec<u8>>,
    read: Option<Vec<u8>>,
    eof: bool,
}

impl PacketAddrStream {
    pub(crate) fn new(inner: Box<dyn AsyncMessageStream>, target: SocketAddr) -> Self {
        Self {
            inner,
            target,
            write: None,
            read: None,
            eof: false,
        }
    }

    fn encode(&self, payload: &[u8]) -> io::Result<Vec<u8>> {
        let header_len = if self.target.is_ipv4() { 7 } else { 19 };
        if payload.len() + header_len > u16::MAX as usize {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "packetaddr datagram is too large",
            ));
        }
        let mut packet = Vec::with_capacity(header_len + payload.len());
        match self.target.ip() {
            IpAddr::V4(address) => {
                packet.push(1);
                packet.extend_from_slice(&address.octets());
            }
            IpAddr::V6(address) => {
                packet.push(2);
                packet.extend_from_slice(&address.octets());
            }
        }
        packet.extend_from_slice(&self.target.port().to_be_bytes());
        packet.extend_from_slice(payload);
        Ok(packet)
    }

    fn decode(packet: &[u8]) -> io::Result<(SocketAddr, &[u8])> {
        let (ip, end) = match packet.first() {
            Some(1) if packet.len() >= 7 => {
                (IpAddr::from(<[u8; 4]>::try_from(&packet[1..5]).unwrap()), 5)
            }
            Some(2) if packet.len() >= 19 => (
                IpAddr::from(<[u8; 16]>::try_from(&packet[1..17]).unwrap()),
                17,
            ),
            _ => {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "invalid packetaddr IP header",
                ));
            }
        };
        let port = u16::from_be_bytes(packet[end..end + 2].try_into().unwrap());
        Ok((SocketAddr::new(ip, port), &packet[end + 2..]))
    }

    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(packet) = &self.write {
            ready!(Pin::new(&mut self.inner).poll_write_message(cx, packet))?;
            self.write = None;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWriteMessage for PacketAddrStream {
    fn poll_write_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.eof {
            return Poll::Ready(Err(ErrorKind::BrokenPipe.into()));
        }
        let packet = this.encode(bytes)?;
        ready!(this.drain(cx))?;
        this.write = Some(packet);
        Poll::Ready(Ok(()))
    }
}
impl AsyncReadMessage for PacketAddrStream {
    fn read_message_eof_on_empty(&self) -> bool {
        self.eof
    }
    fn poll_read_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if let Some(packet) = &this.read {
                if out.remaining() < packet.len() {
                    return Poll::Ready(Err(io::Error::new(
                        ErrorKind::InvalidInput,
                        "packetaddr output buffer is too small",
                    )));
                }
                out.put_slice(packet);
                this.read = None;
                return Poll::Ready(Ok(()));
            }
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            let mut bytes = vec![0; 65535];
            let mut input = ReadBuf::new(&mut bytes);
            ready!(Pin::new(&mut this.inner).poll_read_message(cx, &mut input))?;
            if input.filled().is_empty() && this.inner.read_message_eof_on_empty() {
                this.eof = true;
                return Poll::Ready(Ok(()));
            }
            let (source, payload) = Self::decode(input.filled())?;
            if source != this.target {
                continue;
            }
            this.read = Some(payload.to_vec());
        }
    }
}
impl AsyncFlushMessage for PacketAddrStream {
    fn poll_flush_message(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.drain(cx))?;
        Pin::new(&mut this.inner).poll_flush_message(cx)
    }
}
impl AsyncShutdownMessage for PacketAddrStream {
    fn poll_shutdown_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_flush_message(cx))?;
        Pin::new(&mut self.inner).poll_shutdown_message(cx)
    }
}
impl AsyncPing for PacketAddrStream {
    fn supports_ping(&self) -> bool {
        self.inner.supports_ping()
    }
    fn poll_write_ping(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Pin::new(&mut self.inner).poll_write_ping(cx)
    }
}
impl AsyncMessageStream for PacketAddrStream {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vless::VlessMessageStream;
    use futures::future::poll_fn;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn packetaddr_vectors_retries_empty_packets_and_wrong_sources() {
        for (target, header) in [
            ("192.0.2.1:53", vec![1, 192, 0, 2, 1, 0, 53]),
            (
                "[2001:db8::1]:53",
                vec![
                    2, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 53,
                ],
            ),
        ] {
            let endpoint = target.parse().unwrap();
            let (wire, mut peer) = tokio::io::duplex(1024);
            let mut stream =
                PacketAddrStream::new(Box::new(VlessMessageStream::new(wire)), endpoint);
            for payload in [b"".as_slice(), b"data"] {
                poll_fn(|cx| Pin::new(&mut stream).poll_write_message(cx, payload))
                    .await
                    .unwrap();
                poll_fn(|cx| Pin::new(&mut stream).poll_flush_message(cx))
                    .await
                    .unwrap();
                let length = peer.read_u16().await.unwrap() as usize;
                let mut wire = vec![0; length];
                peer.read_exact(&mut wire).await.unwrap();
                let mut expected = header.clone();
                expected.extend_from_slice(payload);
                assert_eq!(wire, expected);
                // An unsolicited source on the association is ignored.
                let mut wrong = expected.clone();
                wrong[header.len() - 1] = 54;
                peer.write_all(&(wrong.len() as u16).to_be_bytes())
                    .await
                    .unwrap();
                peer.write_all(&wrong).await.unwrap();
                peer.write_all(&(expected.len() as u16).to_be_bytes())
                    .await
                    .unwrap();
                peer.write_all(&expected).await.unwrap();
                if !payload.is_empty() {
                    assert!(
                        poll_fn(|cx| Pin::new(&mut stream)
                            .poll_read_message(cx, &mut ReadBuf::new(&mut [0; 1])))
                        .await
                        .is_err()
                    );
                }
                let mut bytes = [0; 32];
                let mut output = ReadBuf::new(&mut bytes);
                poll_fn(|cx| Pin::new(&mut stream).poll_read_message(cx, &mut output))
                    .await
                    .unwrap();
                assert_eq!(output.filled(), payload);
                assert!(!stream.read_message_eof_on_empty());
            }
            assert!(PacketAddrStream::decode(&[3, 1, 2, 3]).is_err());
            for len in 0..header.len() {
                assert!(PacketAddrStream::decode(&header[..len]).is_err());
            }
            drop(peer);
            let mut bytes = [0; 32];
            let mut output = ReadBuf::new(&mut bytes);
            poll_fn(|cx| Pin::new(&mut stream).poll_read_message(cx, &mut output))
                .await
                .unwrap();
            assert!(output.filled().is_empty() && stream.read_message_eof_on_empty());
        }
    }
}
