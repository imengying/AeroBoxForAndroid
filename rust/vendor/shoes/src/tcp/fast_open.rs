//! Linux's TCP_FASTOPEN_CONNECT may return a writable socket before sending SYN.
//! Keep the original deadline until TCP establishes, and never allow that socket
//! to win an address race or escape through the raw-TCP relay fast path.

use std::future::{Future, poll_fn};
use std::io;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, AsyncWrite, Interest, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::{Instant, Sleep};

use crate::async_stream::{AsyncPing, AsyncStream};

#[derive(Debug)]
pub(crate) struct FastOpenStream {
    stream: Option<TcpStream>,
    deadline: Option<Pin<Box<Sleep>>>,
    started: bool,
    failure: Option<(io::ErrorKind, String)>,
}

impl FastOpenStream {
    pub(crate) fn new(stream: TcpStream, deadline: Instant) -> io::Result<Self> {
        let established = is_established(&stream)?;
        Ok(Self {
            stream: Some(stream),
            deadline: (!established).then(|| Box::pin(tokio::time::sleep_until(deadline))),
            started: established,
            failure: None,
        })
    }

    /// No payload is available for this connection (direct/read-first or an
    /// address race). A zero-length send triggers the deferred SYN on the same
    /// TFO socket, without inventing bytes or replaying data across candidates.
    pub(crate) async fn establish_without_data(&mut self) -> io::Result<()> {
        poll_fn(|cx| self.poll_establish(cx)).await
    }

    fn fail(&mut self, error: io::Error) -> io::Error {
        self.failure = Some((error.kind(), error.to_string()));
        self.deadline = None;
        self.stream = None;
        error
    }

    fn poll_deadline(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if let Some((kind, message)) = &self.failure {
            return Err(io::Error::new(*kind, message.clone()));
        }
        if let Some(deadline) = &mut self.deadline
            && deadline.as_mut().poll(cx).is_ready()
        {
            // A successful first write may be followed by an idle caller.
            // Such an established socket must not expire just because no I/O
            // polled its state in the meantime. Production setup flushes before
            // returning, so its active connect deadline is still enforced.
            if self.started {
                match is_established(self.stream.as_ref().unwrap()) {
                    Ok(true) => {
                        self.deadline = None;
                        return Ok(());
                    }
                    Ok(false) => {}
                    Err(error) => return Err(self.fail(error)),
                }
            }
            return Err(self.fail(io::Error::new(
                io::ErrorKind::TimedOut,
                "TCP Fast Open connection timed out before TCP established",
            )));
        }
        Ok(())
    }

    fn poll_establish(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_deadline(cx)?;
        if self.deadline.is_none() {
            return Poll::Ready(Ok(()));
        }
        let stream = self.stream.as_ref().unwrap();
        if !self.started {
            if let Err(error) = trigger_syn(stream) {
                return Poll::Ready(Err(self.fail(error)));
            }
            self.started = true;
        }
        loop {
            // TCP's deferred EPOLLOUT is not connection success. try_io clears
            // that cached readiness while SYN is in flight, and the real
            // establishment/error event wakes this operation again.
            if let Err(error) = ready!(stream.poll_write_ready(cx)) {
                return Poll::Ready(Err(self.fail(error)));
            }
            match stream.try_io(Interest::WRITABLE, || {
                if is_established(stream)? {
                    Ok(())
                } else {
                    Err(io::ErrorKind::WouldBlock.into())
                }
            }) {
                Ok(()) => {
                    self.deadline = None;
                    return Poll::Ready(Ok(()));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => return Poll::Ready(Err(self.fail(error))),
            }
        }
    }
}

impl AsyncRead for FastOpenStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        ready!(self.poll_establish(cx))?;
        Pin::new(self.stream.as_mut().unwrap()).poll_read(cx, buffer)
    }
}

impl AsyncWrite for FastOpenStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.poll_deadline(cx)?;
        if buffer.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.deadline.is_some() && !self.started {
            match ready!(Pin::new(self.stream.as_mut().unwrap()).poll_write(cx, buffer)) {
                Ok(0) => {
                    return Poll::Ready(Err(self.fail(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "TCP Fast Open accepted no initial bytes",
                    ))));
                }
                Ok(written) => {
                    // The kernel owns these bytes now. Never submit them again,
                    // including when an AsyncWrite future is cancelled. Flush,
                    // read and further writes await the actual establishment.
                    self.started = true;
                    return Poll::Ready(Ok(written));
                }
                Err(error) if error.raw_os_error() == Some(libc::EINPROGRESS) => {
                    // A valid Fast Open request can initiate TCP without
                    // accepting data. Retry that data only after establishment.
                    self.started = true;
                }
                Err(error) => return Poll::Ready(Err(self.fail(error))),
            }
        }
        ready!(self.poll_establish(cx))?;
        Pin::new(self.stream.as_mut().unwrap()).poll_write(cx, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_establish(cx))?;
        Pin::new(self.stream.as_mut().unwrap()).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_establish(cx))?;
        Pin::new(self.stream.as_mut().unwrap()).poll_shutdown(cx)
    }
}

impl AsyncPing for FastOpenStream {
    fn supports_ping(&self) -> bool {
        false
    }
    fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncStream for FastOpenStream {
    fn tcp_socket_control(&self) -> io::Result<Option<super::socket_control::TcpSocketControl>> {
        self.stream.as_ref().map_or(Ok(None), |stream| super::socket_control::TcpSocketControl::from_tcp(stream))
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        self.stream.as_ref()?.local_addr().ok()
    }
    fn peer_addr(&self) -> Option<SocketAddr> {
        self.stream.as_ref()?.peer_addr().ok()
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn plain_tcp(&self) -> Option<&TcpStream> {
        self.deadline
            .is_none()
            .then_some(self.stream.as_ref())
            .flatten()
    }
}

fn is_established(stream: &TcpStream) -> io::Result<bool> {
    if let Some(error) = stream.take_error()? {
        return Err(error);
    }
    let mut state = 0u8;
    let mut length = std::mem::size_of_val(&state) as libc::socklen_t;
    // SAFETY: TCP_INFO's first field is the u8 TCP state on Linux/Android.
    // A one-byte buffer requests only that stable prefix, avoiding kernel-
    // version-specific layout of the rest of struct tcp_info.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            std::ptr::from_mut(&mut state).cast(),
            &mut length,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    if length != 1 {
        return Err(io::Error::other("TCP_INFO omitted the connection state"));
    }
    match state {
        1 | 8 => Ok(true),  // TCP_ESTABLISHED / TCP_CLOSE_WAIT (peer already sent FIN)
        2 | 3 => Ok(false), // TCP_SYN_SENT / TCP_SYN_RECV
        _ => Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "TCP did not establish",
        )),
    }
}

fn trigger_syn(stream: &TcpStream) -> io::Result<()> {
    // SAFETY: a zero-length send reads no bytes; the FD belongs to stream.
    let result = unsafe {
        libc::send(
            stream.as_raw_fd(),
            std::ptr::null(),
            0,
            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
        )
    };
    if result >= 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::EINPROGRESS) || error.kind() == io::ErrorKind::WouldBlock
    {
        Ok(())
    } else {
        Err(error)
    }
}

#[cfg(test)]
mod tests;
