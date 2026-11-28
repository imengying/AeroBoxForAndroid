use super::{
    H2MuxClientSession, H2MuxOptions, H2MuxPaddingStream, MuxProtocol,
    h2mux_protocol::{SessionRequest, StreamRequest, decode_error_length},
};
use crate::{
    address::NetLocation,
    async_stream::{AsyncPing, AsyncStream},
};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
#[derive(Clone)]
pub(super) enum Session {
    H2(H2MuxClientSession),
    Smux(super::smux::Session),
    Yamux(super::yamux::Session),
}
impl Session {
    pub async fn new(stream: Box<dyn AsyncStream>, options: &H2MuxOptions) -> io::Result<Self> {
        let rates = options
            .brutal
            .as_ref()
            .map(super::brutal::BrutalConfig::rates)
            .transpose()?
            .flatten();
        if let Some((send, receive)) = rates {
            let control = stream.tcp_socket_control();
            super::brutal::bounded(
                async {
                    let session = Self::raw(stream, options).await?;
                    // Cancelling negotiation must immediately stop the driver and
                    // close the carrier, instead of starting a graceful drain.
                    let guard = Uncommitted(Some(session));
                    super::brutal::negotiate(guard.0.as_ref().unwrap(), send, receive, control)
                        .await?;
                    Ok(guard)
                },
                std::time::Duration::from_secs(5),
            )
            .await
            .map(|mut guard| guard.0.take().unwrap())
        } else {
            Self::raw(stream, options).await
        }
    }
    async fn raw(mut stream: Box<dyn AsyncStream>, options: &H2MuxOptions) -> io::Result<Self> {
        if options.protocol == MuxProtocol::H2Mux {
            return Ok(Self::H2(H2MuxClientSession::new(stream, options).await?));
        }
        SessionRequest::new(options.protocol, options.padding)
            .write(&mut stream)
            .await?;
        if options.padding {
            stream = Box::new(H2MuxPaddingStream::new(stream));
        }
        Ok(match options.protocol {
            MuxProtocol::Smux => Self::Smux(super::smux::Session::new(stream)),
            MuxProtocol::Yamux => Self::Yamux(super::yamux::Session::new(stream)),
            _ => unreachable!(),
        })
    }
    pub fn abort(&self) {
        match self {
            Self::H2(s) => s.abort(),
            Self::Smux(s) => s.abort(),
            Self::Yamux(s) => s.abort(),
        }
    }
    pub fn is_ready(&self) -> bool {
        match self {
            Self::H2(s) => s.is_ready(),
            Self::Smux(s) => s.is_ready(),
            Self::Yamux(s) => s.is_ready(),
        }
    }
    pub async fn open(&self, target: &NetLocation, tcp: bool) -> io::Result<Box<dyn AsyncStream>> {
        if let Self::H2(s) = self {
            let mut s = s.clone();
            return if tcp {
                s.open_tcp(target).await
            } else {
                s.open_udp(target, false).await
            };
        }
        let mut raw = match self {
            Self::Smux(s) => s.open().await?,
            Self::Yamux(s) => s.open().await?,
            _ => unreachable!(),
        };
        let header = if tcp {
            StreamRequest::tcp(target.clone())
        } else {
            StreamRequest::udp(target.clone(), false)
        }
        .encode()?;
        raw.write_all(&header).await?;
        raw.flush().await?;
        // sing-mux may send its success only after receiving application data.
        Ok(Box::new(ResponseStream {
            raw,
            status: Vec::new(),
            ready: false,
        }))
    }
}
struct Uncommitted(Option<Session>);
impl Drop for Uncommitted {
    fn drop(&mut self) {
        if let Some(session) = &self.0 {
            session.abort();
        }
    }
}
struct ResponseStream {
    raw: Box<dyn AsyncStream>,
    status: Vec<u8>,
    ready: bool,
}
impl AsyncRead for ResponseStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        for _ in 0..64 {
            if self.ready {
                return Pin::new(&mut self.raw).poll_read(cx, out);
            }
            let mut byte = [0];
            let mut buf = ReadBuf::new(&mut byte);
            std::task::ready!(Pin::new(&mut self.raw).poll_read(cx, &mut buf))?;
            if buf.filled().is_empty() {
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
            self.status.push(byte[0]);
            match self.status[0] {
                0 => {
                    self.ready = true;
                    self.status.clear();
                }
                1 => {
                    if let Some((length, used)) = decode_error_length(&self.status[1..])? {
                        if self.status.len() == 1 + used + length {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::ConnectionRefused,
                                format!(
                                    "mux upstream: {}",
                                    String::from_utf8_lossy(&self.status[1 + used..])
                                ),
                            )));
                        }
                    }
                }
                _ => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid mux response status",
                    )));
                }
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}
impl AsyncWrite for ResponseStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        v: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.raw).poll_write(cx, v)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.raw).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.raw).poll_shutdown(cx)
    }
}
impl AsyncPing for ResponseStream {
    fn supports_ping(&self) -> bool {
        false
    }
    fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}
impl AsyncStream for ResponseStream {}
