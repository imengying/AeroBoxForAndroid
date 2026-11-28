//! Split the first ClientHello at an SNI byte boundary without changing the
//! handshake transcript. Packet waits follow sing-box v1.14.4 tlsfragment;
//! the pending write and timer remain owned by the stream across cancellation.

use std::future::Future;
use std::io;
use std::ops::Range;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use rand::RngExt;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};

use crate::async_stream::{AsyncPing, AsyncStream};
use crate::dial_options::DialDuration;

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TlsFragmentOptions {
    pub fragment: bool,
    pub record_fragment: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fragment_fallback_delay: Option<DialDuration>,
}

impl TlsFragmentOptions {
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }

    pub fn enabled(&self) -> bool {
        self.fragment || self.record_fragment
    }

    pub fn validate(&self) -> io::Result<()> {
        if !self.fragment
            && self
                .fragment_fallback_delay
                .is_some_and(|delay| !delay.0.is_zero())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "fragment_fallback_delay requires fragment",
            ));
        }
        Ok(())
    }

    fn fallback_delay(&self) -> Duration {
        self.fragment_fallback_delay
            .filter(|delay| !delay.0.is_zero())
            .map_or(Duration::from_millis(500), |delay| delay.0)
    }

    pub(crate) fn wrap(&self, stream: Box<dyn AsyncStream>) -> io::Result<Box<dyn AsyncStream>> {
        self.validate()?;
        Ok(if self.enabled() {
            Box::new(FragmentStream::new(stream, self.clone()))
        } else {
            stream
        })
    }
}

enum WritePhase {
    First,
    FlushFirst,
    WaitAck {
        start: Instant,
        timer: Option<Pin<Box<Sleep>>>,
        fallback: bool,
    },
    Rest,
    FlushRest,
}

struct PendingFlight {
    bytes: Vec<u8>,
    split: Option<usize>,
    offset: usize,
    phase: WritePhase,
}

pub(crate) struct FragmentStream {
    inner: Box<dyn AsyncStream>,
    options: TlsFragmentOptions,
    collecting: bool,
    initial: Vec<u8>,
    pending: Option<PendingFlight>,
    original_nodelay: Option<bool>,
    failure: Option<(io::ErrorKind, String)>,
}

impl FragmentStream {
    fn new(inner: Box<dyn AsyncStream>, options: TlsFragmentOptions) -> Self {
        Self {
            inner,
            options,
            collecting: true,
            initial: Vec::new(),
            pending: None,
            original_nodelay: None,
            failure: None,
        }
    }

    fn check_failure(&self) -> io::Result<()> {
        match &self.failure {
            Some((kind, message)) => Err(io::Error::new(*kind, message.clone())),
            None => Ok(()),
        }
    }

    fn fail(&mut self, error: &io::Error) {
        if self.failure.is_none() {
            self.failure = Some((error.kind(), error.to_string()));
            self.initial.clear();
            self.pending = None;
            let _ = self.restore_nodelay();
        }
    }

    fn set_nodelay(&mut self) -> io::Result<()> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if self.original_nodelay.is_none()
            && let Some(tcp) = self.inner.plain_tcp()
        {
            let original = tcp.nodelay()?;
            tcp.set_nodelay(true)?;
            self.original_nodelay = Some(original);
        }
        Ok(())
    }

    fn restore_nodelay(&mut self) -> io::Result<()> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if let Some(original) = self.original_nodelay.take()
            && let Some(tcp) = self.inner.plain_tcp()
        {
            tcp.set_nodelay(original)?;
        }
        Ok(())
    }

    fn finish_initial(&mut self, complete_record: bool) -> io::Result<()> {
        if self.initial.is_empty() {
            return Ok(());
        }
        self.collecting = false;
        let input = std::mem::take(&mut self.initial);
        let sni = complete_record.then(|| server_name_range(&input)).flatten();
        let (bytes, split) = match sni {
            Some(name) if name.len() > 1 => {
                let split = rand::rng().random_range(name.start + 1..name.end);
                let bytes = if self.options.record_fragment {
                    split_record(&input, split)
                } else {
                    input
                };
                if self.options.fragment {
                    self.set_nodelay()?;
                }
                (bytes, self.options.fragment.then_some(split))
            }
            _ => (input, None),
        };
        self.pending = Some(PendingFlight {
            bytes,
            split,
            offset: 0,
            phase: WritePhase::First,
        });
        Ok(())
    }

    fn drive(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.check_failure()?;
        let result = self.drive_inner(cx);
        if let Poll::Ready(Err(error)) = &result {
            self.fail(error);
        }
        result
    }

    fn drive_inner(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            let Some(pending) = &mut self.pending else {
                return Poll::Ready(Ok(()));
            };
            match &mut pending.phase {
                WritePhase::First | WritePhase::Rest => {
                    let first = matches!(pending.phase, WritePhase::First);
                    let end = if first {
                        pending.split.unwrap_or(pending.bytes.len())
                    } else {
                        pending.bytes.len()
                    };
                    while pending.offset < end {
                        let count = ready!(
                            Pin::new(&mut self.inner)
                                .poll_write(cx, &pending.bytes[pending.offset..end])
                        )?;
                        if count == 0 {
                            return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                        }
                        pending.offset += count;
                    }
                    pending.phase = if first && pending.split.is_some() {
                        WritePhase::FlushFirst
                    } else {
                        WritePhase::FlushRest
                    };
                }
                WritePhase::FlushFirst => {
                    ready!(Pin::new(&mut self.inner).poll_flush(cx))?;
                    pending.phase = WritePhase::WaitAck {
                        start: Instant::now(),
                        timer: None,
                        fallback: false,
                    };
                    // TFO can expose the real TCP socket only after this flush
                    // finishes its deferred connect. Recheck before sending
                    // any later fragment and restore the original setting.
                    self.set_nodelay()?;
                }
                WritePhase::WaitAck {
                    start,
                    timer,
                    fallback,
                } => {
                    if let Some(sleep) = timer {
                        ready!(sleep.as_mut().poll(cx));
                        *timer = None;
                        if *fallback {
                            pending.phase = WritePhase::Rest;
                            continue;
                        }
                    }
                    let unacked = unacked_segments(self.inner.as_ref())?;
                    match unacked {
                        Some(0) if start.elapsed() > Duration::from_millis(20) => {
                            pending.phase = WritePhase::Rest;
                        }
                        Some(0) | None => {
                            *fallback = true;
                            *timer =
                                Some(Box::pin(tokio::time::sleep(self.options.fallback_delay())));
                        }
                        Some(_) => {
                            *timer = Some(Box::pin(tokio::time::sleep(Duration::from_millis(10))));
                        }
                    }
                }
                WritePhase::FlushRest => {
                    ready!(Pin::new(&mut self.inner).poll_flush(cx))?;
                    self.pending = None;
                    self.restore_nodelay()?;
                }
            }
        }
    }

    fn poll_flush_inner(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.check_failure()?;
        // A caller flushing an incomplete record must not deadlock waiting for
        // itself to write more. Preserve its bytes and disable this one-shot transform.
        if self.collecting && !self.initial.is_empty() {
            self.finish_initial(false)?;
        }
        ready!(self.drive(cx))?;
        Pin::new(&mut self.inner).poll_flush(cx)
    }
}

impl Drop for FragmentStream {
    fn drop(&mut self) {
        let _ = self.restore_nodelay();
    }
}

impl AsyncWrite for FragmentStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.check_failure()?;
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        ready!(this.drive(cx))?;
        if !this.collecting {
            return Pin::new(&mut this.inner).poll_write(cx, bytes);
        }
        let mut accepted = 0;
        if this.initial.len() < 5 {
            let count = (5 - this.initial.len()).min(bytes.len());
            this.initial.extend_from_slice(&bytes[..count]);
            accepted += count;
        }
        if this.initial.len() == 5 {
            if this.initial[0] != 22 || this.initial[1] != 3 {
                this.finish_initial(false)?;
                return Poll::Ready(Ok(accepted));
            }
        }
        if this.initial.len() >= 5 {
            let end = 5 + usize::from(u16::from_be_bytes([this.initial[3], this.initial[4]]));
            let count = (end - this.initial.len()).min(bytes.len() - accepted);
            this.initial
                .extend_from_slice(&bytes[accepted..accepted + count]);
            accepted += count;
            if this.initial.len() == end {
                if let Err(error) = this.finish_initial(true) {
                    this.fail(&error);
                    return Poll::Ready(Err(error));
                }
            }
        }
        Poll::Ready(Ok(accepted))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = this.poll_flush_inner(cx);
        if let Poll::Ready(Err(error)) = &result {
            this.fail(error);
        }
        result
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl AsyncRead for FragmentStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.check_failure()?;
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.get_mut().inner).poll_read(cx, output)
    }
}

impl AsyncPing for FragmentStream {
    fn supports_ping(&self) -> bool {
        self.inner.supports_ping()
    }
    fn poll_write_ping(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.get_mut().inner).poll_write_ping(cx)
    }
}

impl AsyncStream for FragmentStream {
    fn tcp_socket_control(&self) -> std::io::Result<Option<crate::tcp::socket_control::TcpSocketControl>> {
        self.inner.tcp_socket_control()
    }

    fn local_addr(&self) -> Option<std::net::SocketAddr> {
        self.inner.local_addr()
    }
    fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        self.inner.peer_addr()
    }
    fn flow(&self) -> Option<&std::sync::Arc<crate::control::flows::FlowEntry>> {
        self.inner.flow()
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn plain_tcp(&self) -> Option<&tokio::net::TcpStream> {
        if !self.collecting && self.pending.is_none() && self.failure.is_none() {
            self.inner.plain_tcp()
        } else {
            None
        }
    }
}

fn unacked_segments(stream: &dyn AsyncStream) -> io::Result<Option<u32>> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if let Some(tcp) = stream.plain_tcp() {
        use std::os::fd::AsRawFd;
        // Linux UAPI tcp_info has eight u8 fields, then rto/ato/snd_mss/rcv_mss,
        // followed by the native-endian u32 tcpi_unacked at offset 24. Request
        // only this stable prefix, also shared by Android's Linux kernel ABI.
        let mut info = [0u8; 28];
        let mut length = info.len() as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                tcp.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_INFO,
                info.as_mut_ptr().cast(),
                &mut length,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        if length < info.len() as libc::socklen_t {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "TCP_INFO lacks unacked counter",
            ));
        }
        return Ok(Some(u32::from_ne_bytes(info[24..28].try_into().unwrap())));
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let _ = stream;
    Ok(None)
}

fn split_record(record: &[u8], split: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(record.len() + 5);
    output.extend_from_slice(&record[..3]);
    output.extend_from_slice(&((split - 5) as u16).to_be_bytes());
    output.extend_from_slice(&record[5..split]);
    output.extend_from_slice(&record[..3]);
    output.extend_from_slice(&((record.len() - split) as u16).to_be_bytes());
    output.extend_from_slice(&record[split..]);
    output
}

fn server_name_range(record: &[u8]) -> Option<Range<usize>> {
    let header = record.get(..9)?;
    if header[0] != 22 || header[1] != 3 || header[5] != 1 {
        return None;
    }
    let record_end = 5 + usize::from(u16::from_be_bytes([header[3], header[4]]));
    if record_end != record.len() {
        return None;
    }
    let hello_len =
        (usize::from(header[6]) << 16) | (usize::from(header[7]) << 8) | usize::from(header[8]);
    let hello_end = 9usize.checked_add(hello_len)?;
    let hello = record.get(..hello_end)?;
    let mut cursor = 9 + 2 + 32;
    let session_len = usize::from(*hello.get(cursor)?);
    cursor += 1 + session_len;
    let length16 = |at: usize| -> Option<usize> {
        let bytes = hello.get(at..at + 2)?;
        Some(usize::from(u16::from_be_bytes([bytes[0], bytes[1]])))
    };
    let suites_len = length16(cursor)?;
    if suites_len == 0 || suites_len % 2 != 0 {
        return None;
    }
    cursor += 2 + suites_len;
    let compression_len = usize::from(*hello.get(cursor)?);
    cursor += 1 + compression_len;
    let extensions_len = length16(cursor)?;
    cursor += 2;
    let extensions_end = cursor.checked_add(extensions_len)?;
    if extensions_end != hello_end {
        return None;
    }
    while cursor < extensions_end {
        let kind = length16(cursor)?;
        let length = length16(cursor + 2)?;
        cursor += 4;
        let end = cursor.checked_add(length)?;
        if end > extensions_end {
            return None;
        }
        if kind == 0 {
            let list_length = length16(cursor)?;
            cursor += 2;
            if cursor.checked_add(list_length)? != end {
                return None;
            }
            while cursor < end {
                let name_type = *hello.get(cursor)?;
                let name_length = length16(cursor + 1)?;
                cursor += 3;
                let name_end = cursor.checked_add(name_length)?;
                if name_end > end {
                    return None;
                }
                if name_type == 0 {
                    return Some(cursor..name_end);
                }
                cursor = name_end;
            }
            return None;
        }
        cursor = end;
    }
    None
}

#[cfg(test)]
mod tests;
