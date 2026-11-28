use std::{io, pin::Pin, task::{Context, Poll}};
use bytes::{Buf, Bytes};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use crate::async_stream::{AsyncPing, AsyncStream};

pub(super) struct GrpcStream<S> { inner: S, header: Vec<u8>, remaining: usize, write: Bytes, shutdown: bool }
impl<S> GrpcStream<S> { pub fn new(inner: S) -> Self { Self { inner, header: Vec::with_capacity(11), remaining: 0, write: Bytes::new(), shutdown: false } } }
impl<S: AsyncRead + Unpin> AsyncRead for GrpcStream<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, output: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        if output.remaining() == 0 { return Poll::Ready(Ok(())); }
        for _ in 0..32 {
            if me.remaining != 0 {
                let limit = me.remaining.min(output.remaining());
                let mut limited = ReadBuf::new(output.initialize_unfilled_to(limit));
                std::task::ready!(Pin::new(&mut me.inner).poll_read(cx, &mut limited))?;
                let len = limited.filled().len();
                if len == 0 { return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into())); }
                me.remaining -= len;
                output.advance(len);
                return Poll::Ready(Ok(()));
            }
            let mut byte = [0]; let mut input = ReadBuf::new(&mut byte);
            std::task::ready!(Pin::new(&mut me.inner).poll_read(cx, &mut input))?;
            if input.filled().is_empty() { return if me.header.is_empty() { Poll::Ready(Ok(())) } else { Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into())) }; }
            me.header.push(byte[0]);
            if me.header.len() < 7 { continue; }
            if me.header[0] != 0 || me.header[5] != 0x0a { return Poll::Ready(Err(super::invalid("unsupported gRPC compression or message field"))); }
            if me.header.len() > 10 { return Poll::Ready(Err(super::invalid("oversized gRPC length varint"))); }
            if byte[0] & 0x80 != 0 { continue; }
            let mut length = 0usize;
            for (i, b) in me.header[6..].iter().enumerate() { length |= usize::from(b & 0x7f) << (7 * i); }
            let framed = u32::from_be_bytes(me.header[1..5].try_into().unwrap()) as usize;
            if length > 4 * 1024 * 1024 || framed != length + me.header.len() - 5 { return Poll::Ready(Err(super::invalid("invalid gRPC message length"))); }
            me.remaining = length; me.header.clear();
        }
        cx.waker().wake_by_ref(); Poll::Pending
    }
}
impl<S: AsyncWrite + Unpin> GrpcStream<S> {
    fn flush_frame(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.write.is_empty() {
            let len = std::task::ready!(Pin::new(&mut self.inner).poll_write(cx, &self.write))?;
            if len == 0 { return Poll::Ready(Err(io::ErrorKind::WriteZero.into())); }
            self.write.advance(len);
        }
        Poll::Ready(Ok(()))
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for GrpcStream<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        std::task::ready!(self.flush_frame(cx))?;
        if bytes.is_empty() { return Poll::Ready(Ok(0)); }
        if self.shutdown { return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())); }
        let length = bytes.len().min(16384); let mut varint = Vec::with_capacity(3); let mut v = length;
        while v > 127 { varint.push((v as u8 & 127) | 128); v >>= 7; } varint.push(v as u8);
        let mut frame = Vec::with_capacity(length + 9); frame.push(0); frame.extend_from_slice(&((length + 1 + varint.len()) as u32).to_be_bytes()); frame.push(0x0a); frame.extend_from_slice(&varint); frame.extend_from_slice(&bytes[..length]);
        self.write = frame.into();
        // Acceptance into a bounded buffer follows AsyncWrite semantics. flush/shutdown drains it.
        Poll::Ready(Ok(length))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> { std::task::ready!(self.flush_frame(cx))?; Pin::new(&mut self.inner).poll_flush(cx) }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> { std::task::ready!(self.flush_frame(cx))?; self.shutdown = true; Pin::new(&mut self.inner).poll_shutdown(cx) }
}
impl<S: AsyncStream> AsyncPing for GrpcStream<S> {
    fn supports_ping(&self) -> bool { self.inner.supports_ping() }
    fn poll_write_ping(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        std::task::ready!(self.flush_frame(cx))?;
        Pin::new(&mut self.inner).poll_write_ping(cx)
    }
}
impl<S: AsyncStream> AsyncStream for GrpcStream<S> {}
