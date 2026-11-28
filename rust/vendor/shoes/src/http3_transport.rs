use std::task::{Context, Poll};

use bytes::Bytes;
use h3::{
    error::Code,
    quic::{self, BidiStream, OpenStreams, RecvStream, SendStream, StreamErrorIncoming},
};

pub struct Connection {
    inner: h3_quinn::Connection,
    opener: Opener,
}

impl Connection {
    pub fn new(connection: quinn::Connection) -> Self {
        let inner = h3_quinn::Connection::new(connection);
        let opener = Opener {
            inner: <h3_quinn::Connection as quic::Connection<Bytes>>::opener(&inner),
        };
        Self { inner, opener }
    }
}

#[derive(Clone)]
pub struct Opener {
    inner: h3_quinn::OpenStreams,
}

impl Opener {
    pub fn poll_reserve(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Bidi, StreamErrorIncoming>> {
        <h3_quinn::OpenStreams as OpenStreams<Bytes>>::poll_open_bidi(&mut self.inner, cx)
            .map_ok(Bidi::new)
    }
}

impl OpenStreams<Bytes> for Opener {
    type BidiStream = Bidi;
    type SendStream = h3_quinn::SendStream<Bytes>;

    fn poll_open_bidi(&mut self, cx: &mut Context<'_>) -> Poll<Result<Bidi, StreamErrorIncoming>> {
        self.poll_reserve(cx)
    }

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        self.inner.poll_open_send(cx)
    }

    fn close(&mut self, code: Code, reason: &[u8]) {
        <h3_quinn::OpenStreams as OpenStreams<Bytes>>::close(&mut self.inner, code, reason);
    }
}

impl OpenStreams<Bytes> for Connection {
    type BidiStream = Bidi;
    type SendStream = h3_quinn::SendStream<Bytes>;

    fn poll_open_bidi(&mut self, cx: &mut Context<'_>) -> Poll<Result<Bidi, StreamErrorIncoming>> {
        self.opener.poll_open_bidi(cx)
    }

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        self.opener.poll_open_send(cx)
    }

    fn close(&mut self, code: Code, reason: &[u8]) {
        self.opener.close(code, reason);
    }
}

impl quic::Connection<Bytes> for Connection {
    type RecvStream = h3_quinn::RecvStream;
    type OpenStreams = Opener;

    fn poll_accept_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::RecvStream, quic::ConnectionErrorIncoming>> {
        <h3_quinn::Connection as quic::Connection<Bytes>>::poll_accept_recv(&mut self.inner, cx)
    }

    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Bidi, quic::ConnectionErrorIncoming>> {
        <h3_quinn::Connection as quic::Connection<Bytes>>::poll_accept_bidi(&mut self.inner, cx)
            .map_ok(Bidi::new)
    }

    fn opener(&self) -> Opener {
        self.opener.clone()
    }
}

pub struct Bidi {
    send: Send,
    recv: Recv,
}

impl Bidi {
    fn new(stream: h3_quinn::BidiStream<Bytes>) -> Self {
        let (send, recv) = stream.split();
        Self {
            send: Send {
                inner: send,
                finished: false,
            },
            recv: Recv {
                id: recv.recv_id(),
                inner: Some(recv),
                pending: false,
                ended: false,
            },
        }
    }
}

pub struct Send {
    inner: h3_quinn::SendStream<Bytes>,
    finished: bool,
}

pub struct Recv {
    inner: Option<h3_quinn::RecvStream>,
    id: h3::quic::StreamId,
    pending: bool,
    ended: bool,
}

impl Drop for Recv {
    fn drop(&mut self) {
        if !self.ended
            && !self.pending
            && let Some(inner) = &mut self.inner
        {
            inner.stop_sending(Code::H3_REQUEST_CANCELLED.value());
        }
    }
}

impl RecvStream for Recv {
    type Buf = Bytes;
    fn poll_reset(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<u64>, StreamErrorIncoming>> {
        match &mut self.inner {
            Some(inner) => inner.poll_reset(cx),
            None => Poll::Ready(Ok(None)),
        }
    }
    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, StreamErrorIncoming>> {
        let Some(inner) = &mut self.inner else {
            return Poll::Ready(Ok(None));
        };
        let result = inner.poll_data(cx);
        self.pending = result.is_pending();
        if matches!(result, Poll::Ready(Ok(None))) {
            self.ended = true;
        }
        result
    }
    fn stop_sending(&mut self, code: u64) {
        // h3-quinn defers STOP until a pending read completes; dropping it cancels immediately.
        if self.pending {
            self.inner.take();
        } else if let Some(inner) = &mut self.inner {
            inner.stop_sending(code);
        }
        self.ended = true;
    }
    fn recv_id(&self) -> h3::quic::StreamId {
        self.id
    }
}

impl Drop for Send {
    fn drop(&mut self) {
        // Quinn otherwise sends FIN on drop, possibly after a partial HTTP/3 frame.
        if !self.finished {
            self.inner.reset(Code::H3_REQUEST_CANCELLED.value());
        }
    }
}

impl SendStream<Bytes> for Send {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.inner.poll_ready(cx)
    }
    fn send_data<T: Into<h3::quic::WriteBuf<Bytes>>>(
        &mut self,
        data: T,
    ) -> Result<(), StreamErrorIncoming> {
        self.inner.send_data(data)
    }
    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        let result = self.inner.poll_finish(cx);
        if matches!(result, Poll::Ready(Ok(()))) {
            self.finished = true;
        }
        result
    }
    fn reset(&mut self, code: u64) {
        self.inner.reset(code);
        self.finished = true;
    }
    fn send_id(&self) -> h3::quic::StreamId {
        self.inner.send_id()
    }
}

impl SendStream<Bytes> for Bidi {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.send.poll_ready(cx)
    }
    fn send_data<T: Into<h3::quic::WriteBuf<Bytes>>>(
        &mut self,
        data: T,
    ) -> Result<(), StreamErrorIncoming> {
        self.send.send_data(data)
    }
    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.send.poll_finish(cx)
    }
    fn reset(&mut self, code: u64) {
        self.send.reset(code);
    }
    fn send_id(&self) -> h3::quic::StreamId {
        self.send.send_id()
    }
}

impl RecvStream for Bidi {
    type Buf = Bytes;
    fn poll_reset(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<u64>, StreamErrorIncoming>> {
        self.recv.poll_reset(cx)
    }
    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, StreamErrorIncoming>> {
        self.recv.poll_data(cx)
    }
    fn stop_sending(&mut self, code: u64) {
        self.recv.stop_sending(code);
    }
    fn recv_id(&self) -> h3::quic::StreamId {
        self.recv.recv_id()
    }
}

impl BidiStream<Bytes> for Bidi {
    type SendStream = Send;
    type RecvStream = Recv;
    fn split(self) -> (Send, Recv) {
        (self.send, self.recv)
    }
}
