//! Naive CONNECT over HTTP/3. Each selected route owns a bounded session cache.
use super::{
    naive_padding_stream::{NaivePaddingStream, PaddingDirection, PaddingType},
    options::Options,
};
use crate::{
    address::{NetLocation, ResolvedLocation},
    async_stream::{AsyncMessageStream, AsyncPing, AsyncStream},
    config::{ResolvedClientConfig, ResolvedClientProxyConfig},
    http3_transport as transport,
    tcp::{
        carrier_dialer::{CarrierDialer, QuicCarrier},
        proxy_connector::ProxyConnector,
        tcp_handler::TcpClientSetupResult,
    },
};
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::{Buf, Bytes};
use h3::ConnectionState;
use std::{
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, ready},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{mpsc, oneshot},
};
use tokio_util::{sync::PollSender, task::AbortOnDropHandle};

struct Session {
    sender: h3::client::SendRequest<transport::Opener, Bytes>,
    carrier: QuicCarrier,
    _driver: AbortOnDropHandle<()>,
}
impl Drop for Session {
    fn drop(&mut self) {
        self.carrier
            .connection
            .close(0u32.into(), b"Naive session released");
    }
}
struct Slot {
    route: Arc<dyn CarrierDialer>,
    lane: usize,
    session: tokio::sync::Mutex<Option<Arc<Session>>>,
}
pub(crate) struct Client {
    location: NetLocation,
    authorization: String,
    padding: bool,
    options: Options,
    next: AtomicUsize,
    slots: parking_lot::Mutex<Vec<Arc<Slot>>>,
}
impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NaiveHttp3Client")
            .field("location", &self.location)
            .finish_non_exhaustive()
    }
}
impl Client {
    pub fn new(config: ResolvedClientConfig) -> io::Result<Self> {
        crate::quic_client::validate_resolved(&config, true)?;
        let ResolvedClientProxyConfig::Naiveproxy {
            settings: options,
            username,
            password,
            padding,
        } = config.protocol
        else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected Naive QUIC",
            ));
        };
        if !options.quic {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected Naive QUIC",
            ));
        }
        Ok(Self {
            location: config.address,
            authorization: if username.is_empty() {
                String::new()
            } else {
                format!(
                    "Basic {}",
                    STANDARD.encode(format!("{username}:{password}"))
                )
            },
            padding,
            options,
            next: AtomicUsize::new(0),
            slots: parking_lot::Mutex::new(Vec::new()),
        })
    }
    async fn session(&self, route: Arc<dyn CarrierDialer>) -> io::Result<Arc<Session>> {
        let lane = self.next.fetch_add(1, Ordering::Relaxed) % self.options.insecure_concurrency;
        let slot = {
            let mut slots = self.slots.lock();
            if let Some(index) = slots
                .iter()
                .position(|s| s.lane == lane && s.route.route_key() == route.route_key())
            {
                let slot = slots.remove(index);
                slots.push(slot.clone());
                slot
            } else {
                let slot = Arc::new(Slot {
                    route,
                    lane,
                    session: tokio::sync::Mutex::new(None),
                });
                if slots.len() == self.options.session_cache_capacity() {
                    slots.remove(0);
                }
                slots.push(slot.clone());
                slot
            }
        };
        let mut stored = slot.session.lock().await;
        if let Some(session) = stored.as_ref().filter(|s| {
            s.carrier.connection.close_reason().is_none()
                && !s._driver.is_finished()
                && !s.sender.is_closing()
                && s.sender.get_conn_error().is_none()
        }) {
            return Ok(session.clone());
        }
        let carrier = slot.route.open_quic().await?;
        // open_quic awaits the authenticated handshake. ALPS can constrain the
        // first CONNECT before the peer's control stream has arrived.
        let mut builder = h3::client::builder();
        builder
            .max_field_section_size(256 * 1024)
            .qpack_decoder(64 * 1024, 100)
            .send_grease(false);
        if let Some(data) = carrier
            .connection
            .handshake_data()
            .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
            && let Some(settings) = data.peer_application_settings.as_deref()
        {
            if let Err(error) = builder.peer_alps(settings) {
                carrier
                    .connection
                    .close(0x109u32.into(), b"invalid HTTP/3 ALPS");
                return Err(io::Error::other(error));
            }
        }
        let (mut driver, sender) = builder
            .build(transport::Connection::new(carrier.connection.clone()))
            .await
            .map_err(io::Error::other)?;
        let task = crate::network_tasks::spawn(async move {
            let _ = driver.wait_idle().await;
        });
        let session = Arc::new(Session {
            sender,
            carrier,
            _driver: AbortOnDropHandle::new(task),
        });
        *stored = Some(session.clone());
        Ok(session)
    }
    async fn connect(
        &self,
        route: Arc<dyn CarrierDialer>,
        target: &ResolvedLocation,
    ) -> io::Result<TcpClientSetupResult> {
        tokio::time::timeout(Duration::from_secs(20), async {
            let mut retried = false;
            loop {
                let session = self.session(route.clone()).await?;
                let request = super::request::connect_request(
                    target.location(),
                    &self.authorization,
                    self.padding,
                    &self.options.extra_headers,
                    http::Version::HTTP_3,
                )?;
                let mut stream = match session.sender.clone().send_request(request).await {
                    Ok(stream) => stream,
                    // h3 reports RemoteClosing only before sending HEADERS. It is
                    // safe to retry this request once on the replacement session.
                    Err(h3::error::StreamError::RemoteClosing) if !retried => {
                        retried = true;
                        continue;
                    }
                    Err(error) => return Err(io::Error::other(error)),
                };
                let response = stream.recv_response().await.map_err(io::Error::other)?;
                if response.status() != http::StatusCode::OK {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!("Naive CONNECT failed: {}", response.status()),
                    ));
                }
                let padding = super::request::response_padding(response.headers(), self.padding)?;
                let stream = Tunnel::new(stream, session);
                let client_stream: Box<dyn AsyncStream> = if padding == PaddingType::None {
                    Box::new(stream)
                } else {
                    Box::new(NaivePaddingStream::new(
                        stream,
                        PaddingDirection::Client,
                        padding,
                    ))
                };
                return Ok(TcpClientSetupResult {
                    client_stream,
                    early_data: None,
                });
            }
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Naive HTTP/3 CONNECT timed out"))?
    }
}
#[async_trait]
impl ProxyConnector for Client {
    fn proxy_location(&self) -> &NetLocation {
        &self.location
    }
    fn supports_udp(&self) -> bool {
        self.options.udp_over_tcp.is_some()
    }
    fn needs_carrier_dialer(&self) -> bool {
        true
    }
    async fn connect_tcp_with_dialer(
        &self,
        route: Arc<dyn CarrierDialer>,
        target: &ResolvedLocation,
    ) -> io::Result<TcpClientSetupResult> {
        self.connect(route, target).await
    }
    async fn connect_udp_with_dialer(
        &self,
        route: Arc<dyn CarrierDialer>,
        target: ResolvedLocation,
    ) -> io::Result<Box<dyn AsyncMessageStream>> {
        let version = self
            .options
            .udp_over_tcp
            .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "Naive UDP disabled"))?;
        let result = self
            .connect(route, &super::request::uot_target(version))
            .await?;
        crate::uot::client::frame(version, result, target).await
    }
    async fn setup_tcp_stream(
        &self,
        _: Box<dyn AsyncStream>,
        _: &ResolvedLocation,
    ) -> io::Result<TcpClientSetupResult> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Naive HTTP/3 requires a QUIC carrier",
        ))
    }
    async fn setup_udp_bidirectional(
        &self,
        _: Box<dyn AsyncStream>,
        _: ResolvedLocation,
    ) -> io::Result<Box<dyn AsyncMessageStream>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Naive HTTP/3 requires a QUIC carrier",
        ))
    }
}

enum Command {
    Data(Bytes),
    Flush(oneshot::Sender<()>),
    Finish(oneshot::Sender<()>),
}
#[derive(Default)]
struct Failure {
    error: parking_lot::Mutex<Option<String>>,
    wake: futures::task::AtomicWaker,
}
impl Failure {
    fn get(&self) -> io::Error {
        io::Error::new(
            io::ErrorKind::BrokenPipe,
            self.error
                .lock()
                .clone()
                .unwrap_or_else(|| "Naive HTTP/3 upload closed".into()),
        )
    }
}
/// Upload queue holds at most 64 KiB. Flush/FIN wait for the HTTP/3 writer,
/// and dropping a stream resets any partially written DATA frame.
struct Tunnel {
    receive: h3::client::RequestStream<transport::Recv, Bytes>,
    pending: Bytes,
    send: PollSender<Command>,
    ack: Option<(bool, oneshot::Receiver<()>)>,
    finished: bool,
    failure: Arc<Failure>,
    _task: AbortOnDropHandle<()>,
    _session: Arc<Session>,
}
impl Tunnel {
    fn new(
        stream: h3::client::RequestStream<transport::Bidi, Bytes>,
        session: Arc<Session>,
    ) -> Self {
        let (mut upload, receive) = stream.split();
        let (sender, mut queue) = mpsc::channel(4);
        let failure = Arc::new(Failure::default());
        let writer_failure = failure.clone();
        let task = crate::network_tasks::spawn(async move {
            let result: io::Result<()> = async {
                while let Some(command) = queue.recv().await {
                    match command {
                        Command::Data(data) => {
                            upload.send_data(data).await.map_err(io::Error::other)?
                        }
                        Command::Flush(done) => {
                            let _ = done.send(());
                        }
                        Command::Finish(done) => {
                            upload.finish().await.map_err(io::Error::other)?;
                            let _ = done.send(());
                            return Ok(());
                        }
                    }
                }
                Ok(())
            }
            .await;
            if let Err(error) = result {
                *writer_failure.error.lock() = Some(error.to_string());
                writer_failure.wake.wake();
            }
        });
        Self {
            receive,
            pending: Bytes::new(),
            send: PollSender::new(sender),
            ack: None,
            finished: false,
            failure,
            _task: AbortOnDropHandle::new(task),
            _session: session,
        }
    }
    fn poll_ack(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some((finish, ack)) = &mut self.ack {
            ready!(Pin::new(ack).poll(cx)).map_err(|_| self.failure.get())?;
            self.finished = *finish;
            self.ack = None;
        }
        Poll::Ready(Ok(()))
    }
    fn flush(&mut self, cx: &mut Context<'_>, finish: bool) -> Poll<io::Result<()>> {
        if self.ack.is_some() {
            let was_finish = self.ack.as_ref().unwrap().0;
            ready!(self.poll_ack(cx))?;
            if was_finish || !finish {
                return Poll::Ready(Ok(()));
            }
        }
        if self.finished {
            return Poll::Ready(Ok(()));
        }
        ready!(self.send.poll_reserve(cx)).map_err(|_| self.failure.get())?;
        let (done, ack) = oneshot::channel();
        self.send
            .send_item(if finish {
                Command::Finish(done)
            } else {
                Command::Flush(done)
            })
            .map_err(|_| self.failure.get())?;
        self.ack = Some((finish, ack));
        self.poll_ack(cx)
    }
}
impl AsyncRead for Tunnel {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        me.failure.wake.register(cx.waker());
        loop {
            if !me.pending.is_empty() {
                let count = out.remaining().min(me.pending.len());
                out.put_slice(&me.pending.split_to(count));
                return Poll::Ready(Ok(()));
            }
            let failed = me.failure.error.lock().is_some();
            if failed {
                return Poll::Ready(Err(me.failure.get()));
            }
            match ready!(me.receive.poll_recv_data(cx)).map_err(io::Error::other)? {
                Some(mut bytes) => {
                    me.pending = bytes.copy_to_bytes(bytes.remaining());
                }
                None => return Poll::Ready(Ok(())),
            }
        }
    }
}
impl AsyncWrite for Tunnel {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        ready!(me.poll_ack(cx))?;
        if me.finished {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        ready!(me.send.poll_reserve(cx)).map_err(|_| me.failure.get())?;
        let size = data.len().min(16 * 1024);
        me.send
            .send_item(Command::Data(Bytes::copy_from_slice(&data[..size])))
            .map_err(|_| me.failure.get())?;
        Poll::Ready(Ok(size))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().flush(cx, false)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().flush(cx, true)
    }
}
impl AsyncPing for Tunnel {
    fn supports_ping(&self) -> bool {
        false
    }
    fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}
impl AsyncStream for Tunnel {}

#[cfg(test)]
#[path = "h3_goaway_tests.rs"]
mod goaway_tests;
