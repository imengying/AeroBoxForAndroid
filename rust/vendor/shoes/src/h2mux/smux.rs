//! Bounded SMUX v1 client session (xtaci/smux wire protocol).
//! Version 1 has connection-level backpressure; each stream retains at most
//! 256 KiB. All workers belong to the active network lifetime.
use crate::async_stream::{AsyncPing, AsyncStream};
use bytes::{Buf, Bytes};
use std::{
    collections::HashMap,
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::{mpsc, oneshot},
};
use tokio_util::{
    sync::{CancellationToken, PollSender},
    task::AbortOnDropHandle,
};
const MAX_FRAME: usize = 16384;
const MAX_STREAMS: usize = 128;
#[derive(Clone)]
pub(super) struct Session {
    owner: Arc<Owner>,
    state: Arc<State>,
    output: mpsc::Sender<Write>,
}
struct Owner {
    cancel: CancellationToken,
}
impl Drop for Owner {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
struct State {
    streams: parking_lot::Mutex<HashMap<u32, Inbox>>,
    next: AtomicU32,
    dead: AtomicBool,
    network: Option<CancellationToken>,
}
struct Inbox {
    sender: mpsc::Sender<Bytes>,
    finished: Arc<AtomicBool>,
}
enum Write {
    Frame(u8, u32, Bytes),
    Flush(oneshot::Sender<io::Result<()>>),
}
impl Session {
    pub fn new(socket: Box<dyn AsyncStream>) -> Self {
        let cancel = CancellationToken::new();
        let state = Arc::new(State {
            streams: Default::default(),
            next: AtomicU32::new(1),
            dead: AtomicBool::new(false),
            network: crate::network_tasks::NetworkTasks::current().map(|n| n.cancelled),
        });
        let (output, mut rx) = mpsc::channel::<Write>(64);
        let (mut read, mut write) = tokio::io::split(socket);
        let session = Self {
            owner: Arc::new(Owner {
                cancel: cancel.clone(),
            }),
            state: state.clone(),
            output,
        };
        let reader_state = state.clone();
        let reader_cancel = cancel.clone();
        let reader = AbortOnDropHandle::new(crate::network_tasks::spawn(async move {
            let result: io::Result<()> = async {
                loop {
                    let mut header = [0; 8];
                    read.read_exact(&mut header).await?;
                    let len = u16::from_le_bytes([header[2], header[3]]) as usize;
                    let id = u32::from_le_bytes(header[4..].try_into().unwrap());
                    if header[0] != 1
                        || !matches!(header[1], 1 | 2 | 3)
                        || (header[1] != 2 && len != 0)
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid SMUX v1 frame",
                        ));
                    }
                    match header[1] {
                        1 => {
                            if let Some(inbox) = reader_state.streams.lock().remove(&id) {
                                inbox.finished.store(true, Ordering::Release);
                            }
                        }
                        2 => {
                            let mut data = vec![0; len];
                            read.read_exact(&mut data).await?;
                            let sender = reader_state
                                .streams
                                .lock()
                                .get(&id)
                                .map(|inbox| inbox.sender.clone());
                            if let Some(sender) = sender {
                                // Split peer frames to maintain the same bounded queue even when
                                // a peer selects SMUX's maximum 65535-byte wire frame.
                                for chunk in data.chunks(MAX_FRAME) {
                                    if sender.send(Bytes::copy_from_slice(chunk)).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                        3 => {}
                        _ => unreachable!(),
                    }
                }
            }
            .await;
            reader_state.dead.store(true, Ordering::Release);
            reader_state.streams.lock().clear();
            reader_cancel.cancel();
            result
        }));
        crate::network_tasks::spawn(async move {
            let _reader = reader;
            let job = async {
                while let Some(message) = rx.recv().await {
                    match message {
                        Write::Frame(cmd, id, data) => {
                            let mut header = [1, cmd, 0, 0, 0, 0, 0, 0];
                            header[2..4].copy_from_slice(&(data.len() as u16).to_le_bytes());
                            header[4..].copy_from_slice(&id.to_le_bytes());
                            write.write_all(&header).await?;
                            write.write_all(&data).await?;
                            write.flush().await?;
                        }
                        Write::Flush(done) => {
                            let result = write.flush().await;
                            let failed = result.is_err();
                            let _ = done.send(result);
                            if failed {
                                return Err(io::ErrorKind::BrokenPipe.into());
                            }
                        }
                    }
                }
                Ok::<_, io::Error>(())
            };
            tokio::select! {_=cancel.cancelled()=>{},_=job=>{}}
            state.dead.store(true, Ordering::Release);
            state.streams.lock().clear();
            cancel.cancel();
        });
        session
    }
    pub fn abort(&self) {
        self.owner.cancel.cancel();
        self.state.dead.store(true, Ordering::Release);
    }
    pub fn is_ready(&self) -> bool {
        !self.state.dead.load(Ordering::Acquire)
            && !self.owner.cancel.is_cancelled()
            && self
                .state
                .network
                .as_ref()
                .is_none_or(|n| !n.is_cancelled())
    }
    pub async fn open(&self) -> io::Result<Box<dyn AsyncStream>> {
        if !self.is_ready() {
            return Err(io::ErrorKind::NotConnected.into());
        }
        let id = self.state.next.fetch_add(2, Ordering::Relaxed);
        if id > u32::MAX - 2 {
            self.owner.cancel.cancel();
            return Err(io::Error::other("SMUX stream identifier exhausted"));
        }
        let (sender, input) = mpsc::channel(16);
        let finished = Arc::new(AtomicBool::new(false));
        {
            let mut map = self.state.streams.lock();
            if map.len() >= MAX_STREAMS {
                return Err(io::Error::other("SMUX stream limit"));
            }
            map.insert(
                id,
                Inbox {
                    sender,
                    finished: finished.clone(),
                },
            );
        }
        let stream = Stream {
            id,
            session: self.clone(),
            output: PollSender::new(self.output.clone()),
            input,
            finished,
            buffer: Bytes::new(),
            flush: None,
            shutdown: false,
        };
        self.output
            .send(Write::Frame(0, id, Bytes::new()))
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        Ok(Box::new(stream))
    }
}
struct Stream {
    id: u32,
    session: Session,
    output: PollSender<Write>,
    input: mpsc::Receiver<Bytes>,
    finished: Arc<AtomicBool>,
    buffer: Bytes,
    flush: Option<oneshot::Receiver<io::Result<()>>>,
    shutdown: bool,
}
impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        while self.buffer.is_empty() {
            match std::task::ready!(self.input.poll_recv(cx)) {
                Some(data) => self.buffer = data,
                None => {
                    return Poll::Ready(if self.finished.load(Ordering::Acquire) {
                        Ok(())
                    } else {
                        Err(io::ErrorKind::ConnectionReset.into())
                    });
                }
            }
        }
        let count = buf.remaining().min(self.buffer.len());
        buf.put_slice(&self.buffer[..count]);
        self.buffer.advance(count);
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.shutdown {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        std::task::ready!(self.output.poll_reserve(cx))
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        let count = data.len().min(MAX_FRAME);
        let id = self.id;
        self.output
            .send_item(Write::Frame(2, id, Bytes::copy_from_slice(&data[..count])))
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        Poll::Ready(Ok(count))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.flush.is_none() {
            std::task::ready!(self.output.poll_reserve(cx))
                .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
            let (done, waiting) = oneshot::channel();
            self.output
                .send_item(Write::Flush(done))
                .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
            self.flush = Some(waiting);
        }
        use std::future::Future;
        let result = std::task::ready!(Pin::new(self.flush.as_mut().unwrap()).poll(cx))
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        self.flush = None;
        Poll::Ready(result)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.shutdown {
            std::task::ready!(self.as_mut().poll_flush(cx))?;
            std::task::ready!(self.output.poll_reserve(cx))
                .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
            let id = self.id;
            self.output
                .send_item(Write::Frame(1, id, Bytes::new()))
                .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
            self.shutdown = true;
        }
        self.poll_flush(cx)
    }
}
impl Drop for Stream {
    fn drop(&mut self) {
        self.session.state.streams.lock().remove(&self.id);
        if !self.shutdown
            && self
                .session
                .output
                .try_send(Write::Frame(1, self.id, Bytes::new()))
                .is_err()
        {
            self.session.owner.cancel.cancel();
        }
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
