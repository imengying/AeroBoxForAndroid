//! V2Ray's cleartext HTTP transport switches to raw bytes after the response
//! head. It deliberately does not use HTTP chunk framing (sing-box HTTPConn).
use std::{io, pin::Pin, task::{Context, Poll}};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use crate::async_stream::{AsyncPing, AsyncStream};

pub(super) struct Http1Stream {
    inner: Box<dyn AsyncStream>,
    response: Vec<u8>,
    ready: bool,
}
impl Http1Stream {
    pub fn new(inner: Box<dyn AsyncStream>) -> Self { Self { inner, response: Vec::new(), ready: false } }
}
impl AsyncRead for Http1Stream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, output: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if output.remaining() == 0 { return Poll::Ready(Ok(())); }
        // Exact head consumption preserves bytes coalesced with the response.
        for _ in 0..256 {
            if self.ready { return Pin::new(&mut self.inner).poll_read(cx, output); }
            if self.response.len() >= 16384 { return Poll::Ready(Err(super::invalid("HTTP response exceeds 16 KiB"))); }
            let mut byte = [0]; let mut input = ReadBuf::new(&mut byte);
            std::task::ready!(Pin::new(&mut self.inner).poll_read(cx, &mut input))?;
            if input.filled().is_empty() { return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into())); }
            self.response.push(byte[0]);
            if self.response.ends_with(b"\r\n\r\n") {
                let mut headers = [httparse::EMPTY_HEADER; 64];
                let mut response = httparse::Response::new(&mut headers);
                response.parse(&self.response).map_err(io::Error::other)?;
                if response.code != Some(200) { return Poll::Ready(Err(super::invalid("HTTP transport rejected"))); }
                self.ready = true; self.response.clear();
            }
        }
        cx.waker().wake_by_ref(); Poll::Pending
    }
}
impl AsyncWrite for Http1Stream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> { Pin::new(&mut self.inner).poll_write(cx, bytes) }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> { Pin::new(&mut self.inner).poll_flush(cx) }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> { Pin::new(&mut self.inner).poll_shutdown(cx) }
}
impl AsyncPing for Http1Stream {
    fn supports_ping(&self) -> bool { self.inner.supports_ping() }
    fn poll_write_ping(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<bool>> { Pin::new(&mut self.inner).poll_write_ping(cx) }
}
impl AsyncStream for Http1Stream {
    fn tcp_socket_control(&self) -> std::io::Result<Option<crate::tcp::socket_control::TcpSocketControl>> {
        self.inner.tcp_socket_control()
    }
}
