use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use crate::{
    address::ResolvedLocation,
    async_stream::AsyncStream,
    h2mux::{H2MuxClientHandler, H2MuxOptions, H2MuxServerSession},
    tcp::{
        carrier_dialer::{CarrierDialer, RouteKey},
        tcp_handler::{ClientTransport, TcpClientHandler, TcpClientSetupResult},
    },
};
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn options() -> H2MuxOptions {
    H2MuxOptions {
        max_connections: 4,
        min_streams: 1,
        max_streams: 4,
        brutal: Some(BrutalConfig {
            enabled: true,
            up_mbps: 8,
            down_mbps: 16,
        }),
        ..Default::default()
    }
}

#[test]
fn bandwidth_limits_are_checked_before_wire_io() {
    assert_eq!(
        options().brutal.unwrap().rates().unwrap(),
        Some((1_000_000, 2_000_000))
    );
    for (up, down) in [(0, 1), (1, 0), (u64::MAX, 1), (1, u64::MAX)] {
        assert!(
            BrutalConfig {
                enabled: true,
                up_mbps: up,
                down_mbps: down
            }
            .rates()
            .is_err()
        );
    }
    assert_eq!(BrutalConfig::default().rates().unwrap(), None);
}

#[tokio::test(start_paused = true)]
async fn an_already_ready_result_cannot_outlive_its_original_deadline() {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    tokio::time::advance(Duration::from_secs(2)).await;
    assert_eq!(
        bounded_at(async { Ok(()) }, deadline)
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut,
    );
    assert_eq!(
        ensure_active(deadline).unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
}

#[tokio::test]
async fn response_wire_acceptance_rejection_truncation_and_memory_bound() {
    let mut good = vec![1];
    good.extend_from_slice(&900_000u64.to_be_bytes());
    assert_eq!(read_response(&mut good.as_slice()).await.unwrap(), 900_000);
    let error = read_response(&mut &b"\0\x07denied\n"[..])
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
    assert!(!error.to_string().contains('\n'));
    for bytes in [
        vec![],
        vec![1],
        vec![1, 0, 0, 0, 0, 0, 0, 0, 0],
        vec![2],
        vec![0, 0x81, 0x80],
        vec![0, 0x81, 0x20],
        vec![0, 3, b'a'],
    ] {
        assert!(
            read_response(&mut bytes.as_slice()).await.is_err(),
            "{bytes:?}"
        );
    }
}

#[derive(Debug)]
struct Plain;
#[async_trait]
impl TcpClientHandler for Plain {
    async fn setup_client_tcp_stream(
        &self,
        stream: Box<dyn AsyncStream>,
        _: ResolvedLocation,
    ) -> io::Result<TcpClientSetupResult> {
        Ok(TcpClientSetupResult {
            client_stream: stream,
            early_data: None,
        })
    }
}

#[derive(Clone, Copy, Debug)]
enum Reply {
    Accept,
    Reject,
    Stall,
}
#[derive(Debug)]
struct Route {
    key: RouteKey,
    opens: AtomicUsize,
    exchanges: Arc<AtomicUsize>,
    reply: Reply,
    entered: Arc<tokio::sync::Notify>,
    closed: Arc<tokio::sync::Notify>,
}
impl Route {
    fn new(key: usize, reply: Reply) -> Arc<Self> {
        Arc::new(Self {
            key: RouteKey(vec![key]),
            opens: AtomicUsize::new(0),
            exchanges: Arc::default(),
            reply,
            entered: Arc::default(),
            closed: Arc::default(),
        })
    }
}
#[async_trait]
impl CarrierDialer for Route {
    fn route_key(&self) -> &RouteKey {
        &self.key
    }
    async fn open_stream(&self) -> io::Result<Box<dyn AsyncStream>> {
        self.opens.fetch_add(1, Ordering::SeqCst);
        let (client, peer) = tokio::io::duplex(16384);
        let (exchanges, entered, closed, reply) = (
            self.exchanges.clone(),
            self.entered.clone(),
            self.closed.clone(),
            self.reply,
        );
        tokio::spawn(async move {
            let mut session = H2MuxServerSession::new(peer).await.unwrap();
            let mut first = session.accept().await.unwrap();
            assert_eq!(first.request.destination.to_string(), "_BrutalBwExchange:0");
            assert!(!first.request.is_udp());
            assert_eq!(first.stream.read_u64().await.unwrap(), 2_000_000);
            exchanges.fetch_add(1, Ordering::SeqCst);
            entered.notify_one();
            match reply {
                Reply::Accept => {
                    first.stream.write_u8(1).await.unwrap();
                    first.stream.write_u64(500_000).await.unwrap();
                    first.stream.flush().await.unwrap();
                    first.stream.shutdown().await.unwrap();
                }
                Reply::Reject => {
                    first.stream.write_all(b"\0\x06denied").await.unwrap();
                    first.stream.flush().await.unwrap();
                    first.stream.shutdown().await.unwrap();
                }
                Reply::Stall => {}
            }
            // H2's flush only enqueues DATA. Dropping a still-open receive
            // half can RESET the stream before the rejection is transmitted.
            // Keep it until the rejecting client closes the whole carrier.
            // Accept deliberately drops immediately to exercise a peer that
            // has already closed the control stream when we send END_STREAM.
            let held = if matches!(reply, Reply::Stall | Reply::Reject) {
                Some(first)
            } else {
                drop(first);
                None
            };
            let mut jobs = tokio::task::JoinSet::new();
            while let Some(inbound) = session.accept().await {
                assert!(
                    matches!(reply, Reply::Accept),
                    "business stream before successful Brutal negotiation"
                );
                jobs.spawn(async move {
                    let (mut read, mut write) = tokio::io::split(inbound.stream);
                    let _ = tokio::io::copy(&mut read, &mut write).await;
                    let _ = write.shutdown().await;
                });
            }
            drop(held);
            closed.notify_one();
        });
        Ok(Box::new(client))
    }
}

fn transport(route: Arc<Route>) -> ClientTransport<'static> {
    ClientTransport {
        route: route.clone(),
        reopen: None,
        open: Box::pin(async move { route.open_stream().await }),
    }
}
fn target() -> ResolvedLocation {
    NetLocation::new(Address::Hostname("echo.example".into()), 443).into()
}

#[tokio::test]
async fn first_exchange_precedes_business_and_brutal_keeps_one_session_per_route() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let handler = H2MuxClientHandler::new(Arc::new(Plain), options());
        let route = Route::new(701, Reply::Accept);
        let other = Route::new(702, Reply::Accept);
        let mut streams = Vec::new();
        for _ in 0..4 {
            let mut stream = handler
                .connect_client_tcp(transport(route.clone()), target())
                .await
                .unwrap()
                .client_stream;
            stream.write_all(b"ok").await.unwrap();
            stream.flush().await.unwrap();
            let mut bytes = [0; 2];
            stream.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"ok");
            // Logical mux streams cannot retune the shared carrier's socket.
            assert!(stream.tcp_socket_control().unwrap().is_none());
            streams.push(stream);
        }
        assert_eq!(route.opens.load(Ordering::SeqCst), 1);
        assert_eq!(route.exchanges.load(Ordering::SeqCst), 1);
        let waiter = handler.connect_client_tcp(transport(route.clone()), target());
        tokio::pin!(waiter);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut waiter)
                .await
                .is_err()
        );
        let isolated = handler
            .connect_client_tcp(transport(other.clone()), target())
            .await
            .unwrap();
        assert_eq!(other.opens.load(Ordering::SeqCst), 1);
        drop(streams.pop());
        let released = waiter.await.unwrap();
        assert_eq!(route.opens.load(Ordering::SeqCst), 1);
        drop((streams, released, isolated));
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn remote_rejection_never_enters_pool_and_pending_cancellation_closes_carrier() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let handler = Arc::new(H2MuxClientHandler::new(Arc::new(Plain), options()));
        let route = Route::new(703, Reply::Reject);
        for _ in 0..2 {
            let result = handler
                .connect_client_tcp(transport(route.clone()), target())
                .await;
            let error = result.err().unwrap();
            assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused, "{error}");
            route.closed.notified().await;
        }
        assert_eq!(route.opens.load(Ordering::SeqCst), 2);
        let pending = Route::new(704, Reply::Stall);
        let child = handler.clone();
        let copy = pending.clone();
        let task =
            tokio::spawn(async move { child.connect_client_tcp(transport(copy), target()).await });
        pending.entered.notified().await;
        task.abort();
        assert!(matches!(task.await, Err(error) if error.is_cancelled()));
        pending.closed.notified().await;
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn deadline_includes_exchange_and_retired_network_cannot_finish_setup() {
    let network = crate::network_tasks::NetworkLifetime::default();
    let result = bounded(
        async {
            tokio::time::advance(Duration::from_secs(1)).await;
            Ok(())
        },
        Duration::from_millis(500),
    )
    .await;
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    network.cancel();
    let error = network
        .scope(bounded(async { Ok(()) }, Duration::from_secs(1)))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
}

#[tokio::test]
async fn all_mux_protocols_retire_before_their_driver_is_polled_again() {
    for protocol in [
        super::super::MuxProtocol::H2Mux,
        super::super::MuxProtocol::Smux,
        super::super::MuxProtocol::Yamux,
    ] {
        let network = crate::network_tasks::NetworkLifetime::default();
        let (stream, _peer) = tokio::io::duplex(16_384);
        let session = network
            .scope(Session::new(
                Box::new(stream),
                &H2MuxOptions {
                    protocol,
                    ..Default::default()
                },
            ))
            .await
            .unwrap();
        assert!(session.is_ready());
        network.cancel();
        // No yield: invalidation must not depend on an aborted driver's destructor.
        assert!(!session.is_ready());
    }
}
