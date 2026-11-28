//! Bounded datagram socket backed by the selected proxy chain. No physical
//! socket is opened here; the chain owns socket protection and DNS policy.
use crate::{address::NetLocation, client_proxy_chain::ClientChainGroup, resolver::Resolver};
use parking_lot::Mutex;
use quinn::{AsyncUdpSocket, UdpPoller};
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::{io::ReadBuf, sync::mpsc};

type Packet = io::Result<Vec<u8>>;
pub(super) struct DatagramSocket {
    server: std::net::SocketAddr,
    local: std::net::SocketAddr,
    sender: mpsc::Sender<Vec<u8>>,
    receiver: Mutex<mpsc::Receiver<Packet>>,
    task: tokio::task::AbortHandle,
    _memory: Option<crate::resources::BudgetPermit>,
}
impl std::fmt::Debug for DatagramSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsProxyDatagram")
            .field("server", &self.server)
            .finish()
    }
}
impl DatagramSocket {
    pub(super) fn new(
        chain: Arc<ClientChainGroup>,
        resolver: Arc<dyn Resolver>,
        local: std::net::SocketAddr,
        server: std::net::SocketAddr,
        retirement: tokio_util::sync::CancellationToken,
        timeout: std::time::Duration,
        memory: Option<crate::resources::BudgetPermit>,
    ) -> io::Result<Arc<Self>> {
        if !chain.supports_udp() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "DNS detour cannot carry UDP",
            ));
        }
        let (sender, mut requests) = mpsc::channel::<Vec<u8>>(32);
        let (replies, receiver) = mpsc::channel(32);
        let work = async move {
            let operation = async {
                let mut stream = tokio::time::timeout(
                    timeout,
                    chain.connect_udp_with_info(
                        &resolver,
                        NetLocation::from_ip_addr(server.ip(), server.port()).into(),
                        Default::default(),
                    ),
                )
                .await
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "DNS proxy datagram setup timed out",
                    )
                })??;
                let mut outgoing: Option<Vec<u8>> = None;
                let mut buffer = vec![0; 65535];
                loop {
                    enum Event {
                        Again,
                        Data(Vec<u8>),
                        Closed,
                    }
                    let event = futures::future::poll_fn(|cx| -> Poll<io::Result<Event>> {
                        if let Some(bytes) = &outgoing {
                            match Pin::new(&mut *stream).poll_write_message(cx, bytes) {
                                Poll::Ready(result) => {
                                    result?;
                                    outgoing = None;
                                    return Poll::Ready(Ok(Event::Again));
                                }
                                Poll::Pending => {}
                            }
                        }
                        let mut output = ReadBuf::new(&mut buffer);
                        match Pin::new(&mut *stream).poll_read_message(cx, &mut output) {
                            Poll::Ready(Ok(())) => {
                                if output.filled().is_empty() && stream.read_message_eof_on_empty()
                                {
                                    return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                                }
                                return Poll::Ready(Ok(Event::Data(output.filled().to_vec())));
                            }
                            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                            Poll::Pending => {}
                        }
                        if outgoing.is_none() {
                            match requests.poll_recv(cx) {
                                Poll::Ready(Some(bytes)) => {
                                    outgoing = Some(bytes);
                                    return Poll::Ready(Ok(Event::Again));
                                }
                                Poll::Ready(None) => return Poll::Ready(Ok(Event::Closed)),
                                Poll::Pending => {}
                            }
                        }
                        Poll::Pending
                    })
                    .await?;
                    match event {
                        Event::Again => {}
                        Event::Data(bytes) => {
                            if replies.send(Ok(bytes)).await.is_err() {
                                return Ok(());
                            }
                        }
                        Event::Closed => return Ok(()),
                    }
                }
            };
            let result: io::Result<()> = tokio::select! {biased;_=retirement.cancelled()=>Err(io::Error::new(io::ErrorKind::ConnectionAborted,"DNS datagram transport retired")),result=operation=>result};
            if let Err(error) = result {
                let _ = replies.send(Err(error)).await;
            }
        };
        let task = crate::network_tasks::spawn(work).abort_handle();
        Ok(Arc::new(Self {
            server,
            local,
            sender,
            receiver: Mutex::new(receiver),
            task,
            _memory: memory,
        }))
    }
    pub(super) fn send(&self, bytes: &[u8], target: std::net::SocketAddr) -> io::Result<usize> {
        if target != self.server {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS datagram destination changed",
            ));
        }
        if bytes.len() > 65507 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS datagram too large",
            ));
        }
        self.sender.try_send(bytes.to_vec()).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => io::ErrorKind::WouldBlock,
            mpsc::error::TrySendError::Closed(_) => io::ErrorKind::BrokenPipe,
        })?;
        Ok(bytes.len())
    }
    pub(super) fn recv(
        &self,
        cx: &mut Context<'_>,
        bytes: &mut [u8],
    ) -> Poll<io::Result<(usize, std::net::SocketAddr)>> {
        match self.receiver.lock().poll_recv(cx) {
            Poll::Ready(Some(Ok(packet))) => {
                if packet.len() > bytes.len() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "DNS receive buffer too small",
                    )));
                }
                bytes[..packet.len()].copy_from_slice(&packet);
                Poll::Ready(Ok((packet.len(), self.server)))
            }
            Poll::Ready(Some(Err(error))) => Poll::Ready(Err(error)),
            Poll::Ready(None) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Poll::Pending => Poll::Pending,
        }
    }
    pub(super) fn poll_send(
        &self,
        cx: &mut Context<'_>,
        bytes: &[u8],
        target: std::net::SocketAddr,
        poller: &mut Writable,
    ) -> Poll<io::Result<usize>> {
        match self.send(bytes, target) {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                match Pin::new(poller).poll_writable(cx) {
                    Poll::Ready(Ok(())) => {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                    Poll::Pending => Poll::Pending,
                }
            }
            result => Poll::Ready(result),
        }
    }
    pub(super) fn writable(&self) -> Writable {
        Writable(tokio_util::sync::PollSender::new(self.sender.clone()))
    }
}
impl Drop for DatagramSocket {
    fn drop(&mut self) {
        self.task.abort();
    }
}
pub(super) struct Writable(tokio_util::sync::PollSender<Vec<u8>>);
impl std::fmt::Debug for Writable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DnsDatagramWritable")
    }
}
impl UdpPoller for Writable {
    fn poll_writable(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.0.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {
                self.0.abort_send();
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Poll::Pending => Poll::Pending,
        }
    }
}
impl AsyncUdpSocket for DatagramSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(self.writable())
    }
    fn try_send(&self, transmit: &quinn::udp::Transmit<'_>) -> io::Result<()> {
        if transmit
            .segment_size
            .is_some_and(|n| n < transmit.contents.len())
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "DNS datagram segmentation unsupported",
            ));
        }
        self.send(transmit.contents, transmit.destination)
            .map(|_| ())
    }
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        buffers: &mut [std::io::IoSliceMut<'_>],
        metadata: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if buffers.is_empty() || metadata.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match self.recv(cx, &mut buffers[0]) {
            Poll::Ready(Ok((len, addr))) => {
                metadata[0] = quinn::udp::RecvMeta {
                    addr,
                    len,
                    stride: len,
                    ecn: None,
                    dst_ip: None,
                };
                Poll::Ready(Ok(1))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        Ok(self.local)
    }
    fn may_fragment(&self) -> bool {
        false
    }
    fn max_transmit_segments(&self) -> usize {
        1
    }
    fn max_receive_segments(&self) -> usize {
        1
    }
}
