use std::{future::Future, io, pin::Pin, task::{Context, Poll}};
use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use crate::async_stream::{AsyncPing, AsyncStream};

/// Allows upload before response headers, as required by gRPC's late response.
pub(crate) struct LateH2Stream {
    response: Option<h2::client::ResponseFuture>,
    recv: Option<h2::RecvStream>,
    send: h2::SendStream<Bytes>,
    buffer: Bytes,
    shutdown: bool,
    ended: bool,
    grpc: bool,
    _reservation: crate::http2::client::StreamReservation,
}
impl LateH2Stream {
    pub fn new(response: h2::client::ResponseFuture, send: h2::SendStream<Bytes>, reservation: crate::http2::client::StreamReservation, grpc: bool) -> Self { Self { response: Some(response), recv: None, send, buffer: Bytes::new(), shutdown: false, ended: false, grpc, _reservation: reservation } }
}
impl AsyncRead for LateH2Stream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, output: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if output.remaining() == 0 { return Poll::Ready(Ok(())); }
        if let Some(response) = &mut self.response {
            let response = std::task::ready!(Pin::new(response).poll(cx)).map_err(io::Error::other)?;
            if response.status() != http::StatusCode::OK { return Poll::Ready(Err(super::invalid("HTTP tunnel rejected"))); }
            if self.grpc && !response.headers().get("content-type").and_then(|v| v.to_str().ok()).is_some_and(|v| v.starts_with("application/grpc")) { return Poll::Ready(Err(super::invalid("invalid gRPC response content type"))); }
            if response.headers().get("grpc-status").is_some_and(|v| v != "0") { return Poll::Ready(Err(super::invalid("gRPC request failed"))); }
            self.recv = Some(response.into_body()); self.response = None;
        }
        for _ in 0..32 {
            if !self.buffer.is_empty() {
                let len = self.buffer.len().min(output.remaining());
                output.put_slice(&self.buffer.split_to(len));
                self.recv.as_mut().unwrap().flow_control().release_capacity(len).map_err(io::Error::other)?;
                return Poll::Ready(Ok(()));
            }
            if self.ended { return Poll::Ready(Ok(())); }
            let recv = self.recv.as_mut().unwrap();
            match std::task::ready!(recv.poll_data(cx)) {
                Some(Ok(data)) => self.buffer = data,
                Some(Err(e)) => return Poll::Ready(Err(io::Error::other(e))),
                None => {
                    let trailers = std::task::ready!(recv.poll_trailers(cx)).map_err(io::Error::other)?;
                    if self.grpc && trailers.as_ref().and_then(|t| t.get("grpc-status")).is_some_and(|v| v != "0") { return Poll::Ready(Err(super::invalid("gRPC stream failed"))); }
                    self.ended = true;
                }
            }
        }
        cx.waker().wake_by_ref(); Poll::Pending
    }
}
impl AsyncWrite for LateH2Stream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        if bytes.is_empty() { return Poll::Ready(Ok(0)); }
        if self.shutdown { return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())); }
        self.send.reserve_capacity(bytes.len().min(16384));
        while self.send.capacity() == 0 {
            match std::task::ready!(self.send.poll_capacity(cx)) {
                Some(Ok(_)) => {}, Some(Err(e)) => return Poll::Ready(Err(io::Error::other(e))), None => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            }
        }
        let len = bytes.len().min(self.send.capacity()).min(16384);
        self.send.send_data(Bytes::copy_from_slice(&bytes[..len]), false).map_err(io::Error::other)?;
        Poll::Ready(Ok(len))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
    fn poll_shutdown(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.shutdown { self.send.send_data(Bytes::new(), true).map_err(io::Error::other)?; self.shutdown = true; }
        Poll::Ready(Ok(()))
    }
}
impl Drop for LateH2Stream { fn drop(&mut self) { if !self.ended || !self.shutdown { self.send.send_reset(h2::Reason::CANCEL); } } }
impl AsyncPing for LateH2Stream {
    fn supports_ping(&self) -> bool { false }
    fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> { Poll::Ready(Ok(false)) }
}
impl AsyncStream for LateH2Stream {}
