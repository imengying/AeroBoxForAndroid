//! The one-stream Xray mux envelope used by Android's v2ray-plugin default.
//! Its destination is v1.mux.cool:666; it is independent of sing-box smux/h2mux.
use super::invalid;
use crate::{
    address::{Address, NetLocation},
    async_stream::{AsyncPing, AsyncStream},
    xudp::frame::{FrameMetadata, FrameOption, SessionStatus, TargetNetwork},
};
use bytes::{Buf, BufMut, BytesMut};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const MAX_PAYLOAD: usize = 8192 - 666;

pub(super) struct Stream {
    inner: Box<dyn AsyncStream>,
    read: BytesMut,
    write: BytesMut,
    remaining: usize,
    pending_length: bool,
    started: bool,
    ended: bool,
    closing: bool,
}
impl Stream {
    pub(super) fn new(inner: Box<dyn AsyncStream>) -> Self {
        Self {
            inner,
            read: BytesMut::new(),
            write: BytesMut::new(),
            remaining: 0,
            pending_length: false,
            started: false,
            ended: false,
            closing: false,
        }
    }
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.write.is_empty() {
            let count = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.write))?;
            if count == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.write.advance(count);
        }
        Poll::Ready(Ok(()))
    }
    fn receive(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        let mut bytes = [0; 8192];
        let mut input = ReadBuf::new(&mut bytes);
        ready!(Pin::new(&mut self.inner).poll_read(cx, &mut input))?;
        if input.filled().is_empty() {
            if self.read.is_empty() && self.remaining == 0 && !self.pending_length {
                self.ended = true;
                return Poll::Ready(Ok(false));
            }
            return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
        }
        self.read.extend_from_slice(input.filled());
        Poll::Ready(Ok(true))
    }
}
impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 || this.ended {
            return Poll::Ready(Ok(()));
        }
        for _ in 0..256 {
            if this.remaining != 0 {
                if this.read.is_empty() {
                    ready!(this.receive(cx))?;
                }
                let count = this.remaining.min(this.read.len()).min(output.remaining());
                output.put_slice(&this.read.split_to(count));
                this.remaining -= count;
                return Poll::Ready(Ok(()));
            }
            if this.pending_length {
                if this.read.len() < 2 {
                    ready!(this.receive(cx))?;
                    continue;
                }
                this.remaining = this.read.get_u16() as usize;
                this.pending_length = false;
                continue;
            }
            let Some(frame) = FrameMetadata::decode(&mut this.read)? else {
                if !ready!(this.receive(cx))? {
                    return Poll::Ready(Ok(()));
                }
                continue;
            };
            if frame.session_id != 0 || frame.option.raw() & !3 != 0 {
                return Poll::Ready(Err(invalid("invalid v2ray-plugin mux session or options")));
            }
            if frame.option.has_error() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "v2ray-plugin mux peer rejected stream",
                )));
            }
            match frame.status {
                SessionStatus::New => {
                    return Poll::Ready(Err(invalid(
                        "unexpected mux session from v2ray-plugin peer",
                    )));
                }
                SessionStatus::End => {
                    this.ended = true;
                    return Poll::Ready(Ok(()));
                }
                SessionStatus::Keep | SessionStatus::KeepAlive => {}
            }
            if frame
                .network
                .is_some_and(|network| network != TargetNetwork::Tcp)
            {
                return Poll::Ready(Err(invalid("unexpected UDP in v2ray-plugin TCP mux")));
            }
            this.pending_length = frame.option.has_data();
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}
impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.closing || this.ended {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        ready!(this.drain(cx))?;
        let count = bytes.len().min(MAX_PAYLOAD);
        FrameMetadata {
            session_id: 0,
            status: if this.started {
                SessionStatus::Keep
            } else {
                SessionStatus::New
            },
            option: FrameOption::new().with_data(),
            network: Some(TargetNetwork::Tcp),
            target: Some(NetLocation::new(
                Address::Hostname("v1.mux.cool".into()),
                666,
            )),
        }
        .encode(&mut this.write)?;
        this.write.put_u16(count as u16);
        this.write.extend_from_slice(&bytes[..count]);
        this.started = true;
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.drain(cx))?;
        if !this.closing {
            this.closing = true;
            if this.started {
                FrameMetadata {
                    session_id: 0,
                    status: SessionStatus::End,
                    option: FrameOption::new(),
                    network: None,
                    target: None,
                }
                .encode(&mut this.write)?;
            }
        }
        ready!(this.drain(cx))?;
        ready!(Pin::new(&mut this.inner).poll_flush(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}
impl AsyncPing for Stream {
    fn supports_ping(&self) -> bool {
        self.inner.supports_ping()
    }
    fn poll_write_ping(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        let this = self.get_mut();
        ready!(this.drain(cx))?;
        Pin::new(&mut this.inner).poll_write_ping(cx)
    }
}
impl AsyncStream for Stream {
    fn local_addr(&self) -> Option<std::net::SocketAddr> {
        self.inner.local_addr()
    }
    fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        self.inner.peer_addr()
    }
    fn flow(&self) -> Option<&std::sync::Arc<crate::control::flows::FlowEntry>> {
        self.inner.flow()
    }
}
