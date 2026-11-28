//! H2MUX Client Handler
//!
//! Wraps an inner TcpClientHandler to multiplex multiple streams over h2mux.
//! Sessions are reused only within the same carrier route and have bounded capacity.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use bytes::BytesMut;
use log::debug;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::address::{Address, NetLocation, ResolvedLocation};
use crate::async_stream::{
    AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage, AsyncShutdownMessage,
    AsyncStream, AsyncWriteMessage,
};
use crate::tcp::tcp_handler::{TcpClientHandler, TcpClientSetupResult};

use super::client_session::Session;
use super::{H2MuxOptions, MUX_DESTINATION_HOST, MUX_DESTINATION_PORT};
use crate::tcp::{carrier_dialer::RouteKey, tcp_handler::ClientTransport};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// H2MUX client handler that multiplexes streams over HTTP/2.
///
/// This handler wraps an inner protocol handler (e.g., Shadowsocks, VLESS)
/// and establishes h2mux on the transport supplied by the proxy chain.
pub struct H2MuxClientHandler {
    /// Inner protocol handler used to establish connections to the proxy server
    inner: Arc<dyn TcpClientHandler>,
    /// H2MUX configuration options
    options: H2MuxOptions,
    pool: Arc<parking_lot::Mutex<Vec<Entry>>>,
    available: Arc<tokio::sync::Notify>,
}

impl H2MuxClientHandler {
    /// Create a new H2MUX client handler wrapping the given inner handler.
    pub fn new(inner: Arc<dyn TcpClientHandler>, options: H2MuxOptions) -> Self {
        Self {
            inner,
            options,
            pool: Default::default(),
            available: Arc::new(tokio::sync::Notify::new()),
        }
    }

    fn magic_location() -> ResolvedLocation {
        ResolvedLocation::new(NetLocation::new(
            Address::Hostname(MUX_DESTINATION_HOST.to_string()),
            MUX_DESTINATION_PORT,
        ))
    }

    async fn create_session(&self, stream: Box<dyn AsyncStream>) -> io::Result<Session> {
        let inner_result = self
            .inner
            .setup_client_tcp_stream(stream, Self::magic_location())
            .await?;

        debug!("H2MuxClientHandler: creating session from stream");

        // Session handles padding internally: sends request header on raw stream,
        // then applies padding layer before HTTP/2 handshake.
        Session::new(inner_result.client_stream, &self.options).await
    }
    async fn pooled(
        &self,
        transport: ClientTransport<'_>,
        target: ResolvedLocation,
        tcp: bool,
    ) -> io::Result<Box<dyn AsyncStream>> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let key = transport.route.route_key().clone();
        let brutal = self
            .options
            .brutal
            .as_ref()
            .is_some_and(|brutal| brutal.enabled);
        let max_connections = if brutal {
            1
        } else if self.options.max_connections == 0 {
            64
        } else {
            self.options.max_connections as usize
        };
        let max_streams = if self.options.max_streams == 0 {
            128
        } else {
            self.options.max_streams as usize
        }
        .min(128);
        let acquire = async {
            loop {
                let changed = self.available.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                let creating = {
                    let mut pool = self.pool.lock();
                    pool.retain(|e| {
                        e.session.as_ref().is_none_or(Session::is_ready)
                            && (e.lease.active.load(Ordering::Acquire) > 0
                                || e.lease.idle.lock().elapsed() < Duration::from_secs(60))
                    });
                    let count = pool.iter().filter(|e| e.key == key).count();
                    let best = pool
                        .iter()
                        .enumerate()
                        .filter(|(_, e)| {
                            e.key == key
                                && e.session.is_some()
                                && e.lease.active.load(Ordering::Acquire) < max_streams
                        })
                        .min_by_key(|(_, e)| e.lease.active.load(Ordering::Acquire))
                        .map(|(i, _)| i);
                    let expand = best.is_some_and(|i| {
                        count < max_connections
                            && pool[i].lease.active.load(Ordering::Acquire)
                                >= self.options.min_streams as usize
                    });
                    if let Some(index) = best.filter(|_| !expand) {
                        let entry = &pool[index];
                        entry.lease.active.fetch_add(1, Ordering::AcqRel);
                        return Ok::<_, io::Error>((
                            entry.session.as_ref().unwrap().clone(),
                            Lease(entry.lease.clone()),
                        ));
                    }
                    if count < max_connections {
                        let lease = Arc::new(LeaseState {
                            active: AtomicUsize::new(1),
                            idle: parking_lot::Mutex::new(Instant::now()),
                            available: self.available.clone(),
                        });
                        pool.push(Entry {
                            key: key.clone(),
                            _route: transport.route.clone(),
                            session: None,
                            lease: lease.clone(),
                        });
                        Some(Reservation {
                            pool: self.pool.clone(),
                            lease,
                            committed: false,
                        })
                    } else {
                        None
                    }
                };
                if let Some(mut reservation) = creating {
                    // The reserved slot counts towards capacity while dialing. Other
                    // routes and warm sessions continue without waiting on this I/O.
                    // Keep the complete transport until the inner handshake ends:
                    // TLS ECH can authenticate a retry config and need to replay
                    // all outer wrappers on a new carrier before sending mux bytes.
                    let inner = self
                        .inner
                        .connect_client_tcp(transport, Self::magic_location())
                        .await?;
                    let session = Session::new(inner.client_stream, &self.options).await?;
                    // A ready future can finish after its enclosing timeout in
                    // the same poll. Never publish that expired carrier.
                    if let Err(error) = super::brutal::ensure_active(deadline) {
                        session.abort();
                        return Err(error);
                    }
                    {
                        let mut pool = self.pool.lock();
                        let entry = pool
                            .iter_mut()
                            .find(|e| Arc::ptr_eq(&e.lease, &reservation.lease))
                            .expect("pending mux reservation");
                        entry.session = Some(session.clone());
                    }
                    reservation.committed = true;
                    self.available.notify_waiters();
                    return Ok((session, Lease(reservation.lease.clone())));
                }
                changed.await;
            }
        };
        super::brutal::bounded_at(
            async {
                let (session, lease) = acquire.await?;
                let stream = session.open(target.location(), tcp).await?;
                Ok(Box::new(LeasedStream {
                    stream,
                    _lease: lease,
                }) as Box<dyn AsyncStream>)
            },
            deadline,
        )
        .await
    }
}

#[async_trait]
impl TcpClientHandler for H2MuxClientHandler {
    fn has_session_pool(&self) -> bool {
        true
    }
    async fn connect_client_tcp(
        &self,
        transport: ClientTransport<'_>,
        target: ResolvedLocation,
    ) -> io::Result<TcpClientSetupResult> {
        Ok(TcpClientSetupResult {
            client_stream: self.pooled(transport, target, true).await?,
            early_data: None,
        })
    }
    async fn connect_client_udp(
        &self,
        transport: ClientTransport<'_>,
        target: ResolvedLocation,
    ) -> io::Result<Box<dyn AsyncMessageStream>> {
        Ok(Box::new(H2MuxUdpMessageStream::new(
            self.pooled(transport, target, false).await?,
        )))
    }
    async fn setup_client_tcp_stream(
        &self,
        client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> io::Result<TcpClientSetupResult> {
        super::brutal::bounded(
            async {
                let session = self.create_session(client_stream).await?;
                let location = remote_location.into_location();
                let stream = session.open(&location, true).await?;
                Ok(TcpClientSetupResult {
                    client_stream: stream,
                    early_data: None,
                })
            },
            Duration::from_secs(10),
        )
        .await
    }

    fn supports_udp_over_tcp(&self) -> bool {
        true
    }

    async fn setup_client_udp_bidirectional(
        &self,
        client_stream: Box<dyn AsyncStream>,
        target: ResolvedLocation,
    ) -> io::Result<Box<dyn AsyncMessageStream>> {
        super::brutal::bounded(
            async {
                let session = self.create_session(client_stream).await?;
                let location = target.into_location();
                let stream = session.open(&location, false).await?;
                Ok(Box::new(H2MuxUdpMessageStream::new(stream)) as Box<dyn AsyncMessageStream>)
            },
            Duration::from_secs(10),
        )
        .await
    }
}

/// Wrapper that adapts an H2MuxStream for UDP to AsyncMessageStream.
///
/// H2MUX UDP uses length-prefixed packets: [length:2][data]
struct H2MuxUdpMessageStream {
    stream: Box<dyn AsyncStream>,
    // Read state machine
    read_state: ReadState,
    read_header: [u8; 2],
    read_header_pos: usize,
    read_eof: bool,
    read_data_remaining: usize,
    read_buffer: Vec<u8>,
    // Write buffer for assembling length-prefixed messages
    write_buffer: BytesMut,
    write_pos: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadState {
    Header,
    Data,
}

impl H2MuxUdpMessageStream {
    fn new(stream: Box<dyn AsyncStream>) -> Self {
        Self {
            stream,
            read_state: ReadState::Header,
            read_header: [0u8; 2],
            read_header_pos: 0,
            read_eof: false,
            read_data_remaining: 0,
            read_buffer: Vec::new(),
            write_buffer: BytesMut::with_capacity(65537),
            write_pos: 0,
        }
    }

    fn poll_drain_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.write_pos < self.write_buffer.len() {
            let n = std::task::ready!(
                Pin::new(&mut self.stream).poll_write(cx, &self.write_buffer[self.write_pos..])
            )?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.write_pos += n;
        }
        self.write_buffer.clear();
        self.write_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl std::fmt::Debug for H2MuxUdpMessageStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H2MuxUdpMessageStream").finish()
    }
}

impl Unpin for H2MuxUdpMessageStream {}

impl AsyncReadMessage for H2MuxUdpMessageStream {
    fn read_message_eof_on_empty(&self) -> bool {
        self.read_eof
    }
    fn poll_read_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;

        loop {
            match this.read_state {
                ReadState::Header => {
                    while this.read_header_pos < 2 {
                        let mut temp_buf =
                            ReadBuf::new(&mut this.read_header[this.read_header_pos..]);
                        std::task::ready!(Pin::new(&mut this.stream).poll_read(cx, &mut temp_buf))?;
                        let n = temp_buf.filled().len();
                        if n == 0 {
                            if this.read_header_pos == 0 {
                                this.read_eof = true;
                                // EOF at message boundary - return empty
                                return Poll::Ready(Ok(()));
                            }
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "EOF while reading message header",
                            )));
                        }
                        this.read_header_pos += n;
                    }

                    let len = u16::from_be_bytes(this.read_header) as usize;
                    this.read_header_pos = 0;
                    this.read_data_remaining = len;
                    this.read_buffer.resize(len, 0);
                    this.read_state = ReadState::Data;

                    if len == 0 {
                        // Empty message
                        this.read_state = ReadState::Header;
                        return Poll::Ready(Ok(()));
                    }

                    if len > buf.remaining() {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("UDP packet too large: {} > {}", len, buf.remaining()),
                        )));
                    }
                }
                ReadState::Data => {
                    let offset = this.read_buffer.len() - this.read_data_remaining;
                    let mut temp_buf = ReadBuf::new(&mut this.read_buffer[offset..]);
                    std::task::ready!(Pin::new(&mut this.stream).poll_read(cx, &mut temp_buf))?;
                    let n = temp_buf.filled().len();
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "EOF while reading message data",
                        )));
                    }
                    this.read_data_remaining -= n;

                    if this.read_data_remaining == 0 {
                        this.read_state = ReadState::Header;
                        if this.read_buffer.len() > buf.remaining() {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "UDP receive buffer too small",
                            )));
                        }
                        buf.put_slice(&this.read_buffer);
                        return Poll::Ready(Ok(()));
                    }
                }
            }
        }
    }
}

impl AsyncWriteMessage for H2MuxUdpMessageStream {
    fn poll_write_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<()>> {
        use bytes::BufMut;

        if buf.len() > 65535 {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP packet too large",
            )));
        }
        std::task::ready!(self.poll_drain_write(cx))?;
        self.write_buffer.put_u16(buf.len() as u16);
        self.write_buffer.put_slice(buf);
        // Accept exactly once; subsequent writes and flush drain this bounded buffer.
        Poll::Ready(Ok(()))
    }
}

impl AsyncFlushMessage for H2MuxUdpMessageStream {
    fn poll_flush_message(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        std::task::ready!(self.poll_drain_write(cx))?;
        Pin::new(&mut self.stream).poll_flush(cx)
    }
}

impl AsyncShutdownMessage for H2MuxUdpMessageStream {
    fn poll_shutdown_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        std::task::ready!(self.as_mut().poll_flush_message(cx))?;
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl AsyncPing for H2MuxUdpMessageStream {
    fn supports_ping(&self) -> bool {
        self.stream.supports_ping()
    }

    fn poll_write_ping(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Pin::new(&mut self.stream).poll_write_ping(cx)
    }
}

impl AsyncMessageStream for H2MuxUdpMessageStream {}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn partial_message_read_preserves_payload_across_polls() {
        let packet = b"\0\x03abc";
        for split in 1..packet.len() {
            let (stream, mut peer) = tokio::io::duplex(1024);
            let mut stream = H2MuxUdpMessageStream::new(Box::new(stream));
            peer.write_all(&packet[..split]).await.unwrap();
            let waker = futures::task::noop_waker();
            let mut cx = Context::from_waker(&waker);
            let mut storage = [0; 32];
            let mut first = ReadBuf::new(&mut storage);
            assert!(
                Pin::new(&mut stream)
                    .poll_read_message(&mut cx, &mut first)
                    .is_pending()
            );
            assert!(first.filled().is_empty());
            peer.write_all(&packet[split..]).await.unwrap();
            let mut next = ReadBuf::new(&mut storage);
            assert!(matches!(
                Pin::new(&mut stream).poll_read_message(&mut cx, &mut next),
                Poll::Ready(Ok(()))
            ));
            assert_eq!(next.filled(), b"abc");
        }
    }

    #[tokio::test]
    async fn message_read_distinguishes_eof_from_truncated_frames() {
        for (packet, expected_error) in [
            (b"".as_slice(), None),
            (b"\0".as_slice(), Some("EOF while reading message header")),
            (
                b"\0\x03a".as_slice(),
                Some("EOF while reading message data"),
            ),
        ] {
            let (stream, mut peer) = tokio::io::duplex(1024);
            let mut stream = H2MuxUdpMessageStream::new(Box::new(stream));
            peer.write_all(packet).await.unwrap();
            peer.shutdown().await.unwrap();

            let mut storage = [0; 32];
            let mut buffer = ReadBuf::new(&mut storage);
            let result = futures::future::poll_fn(|cx| {
                Pin::new(&mut stream).poll_read_message(cx, &mut buffer)
            })
            .await;
            if let Some(message) = expected_error {
                let error = result.unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
                assert_eq!(error.to_string(), message);
            } else {
                result.unwrap();
            }
            assert!(buffer.filled().is_empty());
        }
    }

    #[tokio::test]
    async fn pending_write_and_shutdown_preserve_packet_boundaries() {
        let (stream, mut peer) = tokio::io::duplex(1);
        let mut stream = H2MuxUdpMessageStream::new(Box::new(stream));
        let writer = tokio::spawn(async move {
            for payload in [b"abc".as_slice(), b"defg".as_slice()] {
                futures::future::poll_fn(|cx| {
                    Pin::new(&mut stream).poll_write_message(cx, payload)
                })
                .await
                .unwrap();
            }
            futures::future::poll_fn(|cx| Pin::new(&mut stream).poll_shutdown_message(cx))
                .await
                .unwrap();
        });
        let mut bytes = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            peer.read_to_end(&mut bytes),
        )
        .await
        .unwrap()
        .unwrap();
        writer.await.unwrap();
        assert_eq!(&bytes, b"\0\x03abc\0\x04defg");
    }
}

impl std::fmt::Debug for H2MuxClientHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MuxClientHandler")
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}
struct Entry {
    key: RouteKey,
    _route: Arc<dyn crate::tcp::carrier_dialer::CarrierDialer>,
    session: Option<Session>,
    lease: Arc<LeaseState>,
}
struct Reservation {
    pool: Arc<parking_lot::Mutex<Vec<Entry>>>,
    lease: Arc<LeaseState>,
    committed: bool,
}
impl Drop for Reservation {
    fn drop(&mut self) {
        if !self.committed {
            self.pool
                .lock()
                .retain(|entry| !Arc::ptr_eq(&entry.lease, &self.lease));
            self.lease.available.notify_waiters();
        }
    }
}
struct LeaseState {
    active: AtomicUsize,
    idle: parking_lot::Mutex<Instant>,
    available: Arc<tokio::sync::Notify>,
}
struct Lease(Arc<LeaseState>);
impl Drop for Lease {
    fn drop(&mut self) {
        if self.0.active.fetch_sub(1, Ordering::AcqRel) == 1 {
            *self.0.idle.lock() = Instant::now();
        }
        self.0.available.notify_waiters();
    }
}
struct LeasedStream {
    stream: Box<dyn AsyncStream>,
    _lease: Lease,
}
impl AsyncRead for LeasedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, out)
    }
}
impl AsyncWrite for LeasedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        v: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, v)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
impl AsyncPing for LeasedStream {
    fn supports_ping(&self) -> bool {
        self.stream.supports_ping()
    }
    fn poll_write_ping(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Pin::new(&mut self.stream).poll_write_ping(cx)
    }
}
impl AsyncStream for LeasedStream {}
