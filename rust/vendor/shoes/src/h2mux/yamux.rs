//! Yamux driver with bounded stream opens and cancellation on last owner drop.
use crate::async_stream::{AsyncPing, AsyncStream};
use futures::future::poll_fn;
use std::{
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{mpsc, oneshot},
};
use tokio_util::{
    compat::{Compat, FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt},
    sync::CancellationToken,
};
#[derive(Clone)]
pub(super) struct Session {
    owner: Arc<Owner>,
    open: mpsc::Sender<oneshot::Sender<io::Result<yamux::Stream>>>,
}
struct Owner {
    cancel: CancellationToken,
    closed: Arc<AtomicBool>,
    network: Option<CancellationToken>,
}
impl Drop for Owner {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
impl Session {
    pub fn new(stream: Box<dyn AsyncStream>) -> Self {
        let mut config = yamux::Config::default();
        config.set_max_num_streams(128);
        config.set_max_connection_receive_window(Some(32 * 1024 * 1024));
        let mut connection = yamux::Connection::new(stream.compat(), config, yamux::Mode::Client);
        let (send, mut requests) = mpsc::channel::<oneshot::Sender<io::Result<yamux::Stream>>>(32);
        let cancel = CancellationToken::new();
        let closed = Arc::new(AtomicBool::new(false));
        let owner = Arc::new(Owner {
            cancel: cancel.clone(),
            closed: closed.clone(),
            network: crate::network_tasks::NetworkTasks::current().map(|n| n.cancelled),
        });
        crate::network_tasks::spawn(async move {
            let mut pending: Option<oneshot::Sender<io::Result<yamux::Stream>>> = None;
            let driver = poll_fn(|cx| {
                // Poll socket traffic on every turn, including while opening.
                match connection.poll_next_inbound(cx) {
                    Poll::Ready(Some(Ok(stream))) => {
                        drop(stream);
                        cx.waker().wake_by_ref();
                    }
                    Poll::Ready(_) => return Poll::Ready(()),
                    Poll::Pending => {}
                }
                if pending.is_none() {
                    match requests.poll_recv(cx) {
                        Poll::Ready(Some(request)) => pending = Some(request),
                        Poll::Ready(None) => return Poll::Ready(()),
                        Poll::Pending => {}
                    }
                }
                if pending.is_some() {
                    if let Poll::Ready(result) = connection.poll_new_outbound(cx) {
                        let _ = pending
                            .take()
                            .unwrap()
                            .send(result.map_err(io::Error::other));
                        cx.waker().wake_by_ref();
                    }
                }
                Poll::Pending
            });
            tokio::select! {_=cancel.cancelled()=>{},_=driver=>{}}
            closed.store(true, Ordering::Release);
        });
        Self { owner, open: send }
    }
    pub fn abort(&self) {
        self.owner.cancel.cancel();
        self.owner.closed.store(true, Ordering::Release);
    }
    pub fn is_ready(&self) -> bool {
        !self.owner.closed.load(Ordering::Acquire)
            && !self.owner.cancel.is_cancelled()
            && self
                .owner
                .network
                .as_ref()
                .is_none_or(|n| !n.is_cancelled())
    }
    pub async fn open(&self) -> io::Result<Box<dyn AsyncStream>> {
        let (done, waiting) = oneshot::channel();
        self.open.send(done).await.map_err(io::Error::other)?;
        let stream = waiting.await.map_err(io::Error::other)??;
        Ok(Box::new(Stream {
            stream: stream.compat(),
            _session: self.clone(),
        }))
    }
}
struct Stream {
    stream: Compat<yamux::Stream>,
    _session: Session,
}
impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, out)
    }
}
impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
impl AsyncPing for Stream {
    fn supports_ping(&self) -> bool {
        false
    }
    fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}
impl AsyncStream for Stream {}
