use super::*;
use crate::{
    address::{NetLocation, ResolvedLocation},
    async_stream::AsyncStream,
    tcp::{
        carrier_dialer::{CarrierDialer, RouteKey},
        tcp_handler::{ClientTransport, TcpClientHandler, TcpClientSetupResult},
    },
};
use async_trait::async_trait;
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn smux_v1_wire_vectors_interleave_streams_and_preserve_fin() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (client, mut peer) = tokio::io::duplex(1024);
        let session = smux::Session::new(Box::new(client));
        let mut first = session.open().await.unwrap();
        let mut second = session.open().await.unwrap();
        first.write_all(b"one").await.unwrap();
        second.write_all(b"two").await.unwrap();
        let job = tokio::spawn(async move {
            let mut wire = [0; 38];
            peer.read_exact(&mut wire).await.unwrap();
            assert_eq!(
                &wire[..16],
                &[1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0]
            );
            assert_eq!(
                &wire[16..],
                &[
                    1, 2, 3, 0, 1, 0, 0, 0, b'o', b'n', b'e', 1, 2, 3, 0, 3, 0, 0, 0, b't', b'w',
                    b'o'
                ]
            );
            // Reply out of order. A FIN remains a clean EOF even if the whole
            // session closes immediately after delivering these buffered bytes.
            peer.write_all(&[
                1, 2, 3, 0, 3, 0, 0, 0, b'T', b'W', b'O', 1, 2, 3, 0, 1, 0, 0, 0, b'O', b'N', b'E',
                1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 3, 0, 0, 0,
            ])
            .await
            .unwrap();
        });
        drop(session);
        let mut a = Vec::new();
        let mut b = Vec::new();
        first.read_to_end(&mut a).await.unwrap();
        second.read_to_end(&mut b).await.unwrap();
        assert_eq!(a, b"ONE");
        assert_eq!(b, b"TWO");
        job.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn smux_truncation_is_an_error_and_open_count_is_bounded() {
    let (client, mut peer) = tokio::io::duplex(65536);
    let session = smux::Session::new(Box::new(client));
    let mut streams = Vec::new();
    for _ in 0..128 {
        streams.push(session.open().await.unwrap());
    }
    assert!(session.open().await.is_err());
    peer.write_all(&[1, 2, 4, 0, 1, 0, 0, 0, 42]).await.unwrap();
    drop(peer);
    let mut out = [0; 8];
    assert!(
        tokio::time::timeout(Duration::from_secs(2), streams[0].read(&mut out))
            .await
            .unwrap()
            .is_err()
    );
}

#[tokio::test]
async fn yamux_retains_driver_until_last_stream_and_carries_flow_control() {
    use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
    tokio::time::timeout(Duration::from_secs(10), async {
        let (client, peer) = tokio::io::duplex(1024);
        let session = yamux::Session::new(Box::new(client));
        let server = tokio::spawn(async move {
            let mut connection = ::yamux::Connection::new(
                peer.compat(),
                ::yamux::Config::default(),
                ::yamux::Mode::Server,
            );
            let mut jobs = tokio::task::JoinSet::new();
            while let Some(result) =
                futures::future::poll_fn(|cx| connection.poll_next_inbound(cx)).await
            {
                let stream = match result {
                    Ok(s) => s,
                    Err(_) => break,
                };
                jobs.spawn(async move {
                    let (mut read, mut write) = tokio::io::split(stream.compat());
                    tokio::io::copy(&mut read, &mut write).await.unwrap();
                    write.shutdown().await.unwrap();
                });
            }
        });
        let mut streams = Vec::new();
        for _ in 0..3 {
            streams.push(session.open().await.unwrap());
        }
        drop(session);
        let mut jobs = tokio::task::JoinSet::new();
        for (index, stream) in streams.into_iter().enumerate() {
            jobs.spawn(async move {
                let data = vec![index as u8; 512 * 1024];
                let expected = data.clone();
                let (mut read, mut write) = tokio::io::split(stream);
                let sent = async {
                    write.write_all(&data).await.unwrap();
                    write.shutdown().await.unwrap();
                };
                let received = async {
                    let mut result = Vec::new();
                    read.read_to_end(&mut result).await.unwrap();
                    assert_eq!(result, expected);
                };
                tokio::join!(sent, received);
            });
        }
        while let Some(result) = jobs.join_next().await {
            result.unwrap();
        }
        server.await.unwrap();
    })
    .await
    .unwrap();
}

#[derive(Debug)]
struct Plain;
#[async_trait]
impl TcpClientHandler for Plain {
    async fn setup_client_tcp_stream(
        &self,
        stream: Box<dyn AsyncStream>,
        target: ResolvedLocation,
    ) -> io::Result<TcpClientSetupResult> {
        assert_eq!(target.location().to_string(), "sp.mux.sing-box.arpa:444");
        Ok(TcpClientSetupResult {
            client_stream: stream,
            early_data: None,
        })
    }
}
#[derive(Debug)]
struct Route {
    key: RouteKey,
    opens: AtomicUsize,
}
#[async_trait]
impl CarrierDialer for Route {
    fn route_key(&self) -> &RouteKey {
        &self.key
    }
    async fn open_stream(&self) -> io::Result<Box<dyn AsyncStream>> {
        self.opens.fetch_add(1, Ordering::SeqCst);
        let (client, peer) = tokio::io::duplex(16384);
        tokio::spawn(async move {
            let mut session = H2MuxServerSession::new(peer).await.unwrap();
            let mut jobs = tokio::task::JoinSet::new();
            while let Some(inbound) = session.accept().await {
                jobs.spawn(async move {
                    let (mut read, mut write) = tokio::io::split(inbound.stream);
                    let _ = tokio::io::copy(&mut read, &mut write).await;
                    let _ = write.shutdown().await;
                });
            }
        });
        Ok(Box::new(client))
    }
}
async fn pooled(handler: &H2MuxClientHandler, route: Arc<Route>) -> Box<dyn AsyncStream> {
    let transport = ClientTransport {
        reopen: None,
        route: route.clone(),
        open: Box::pin(async move { route.open_stream().await }),
    };
    handler
        .connect_client_tcp(
            transport,
            ResolvedLocation::new(NetLocation::from_str("example.org:80", None).unwrap()),
        )
        .await
        .unwrap()
        .client_stream
}
#[tokio::test]
async fn pool_reuses_selected_route_and_waits_for_stream_capacity() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let handler = H2MuxClientHandler::new(
            Arc::new(Plain),
            H2MuxOptions {
                max_connections: 1,
                max_streams: 2,
                ..Default::default()
            },
        );
        let a = Arc::new(Route {
            key: RouteKey(vec![1]),
            opens: AtomicUsize::new(0),
        });
        let b = Arc::new(Route {
            key: RouteKey(vec![2]),
            opens: AtomicUsize::new(0),
        });
        let mut first = pooled(&handler, a.clone()).await;
        let second = pooled(&handler, a.clone()).await;
        let other = pooled(&handler, b.clone()).await;
        assert_eq!(a.opens.load(Ordering::SeqCst), 1);
        assert_eq!(b.opens.load(Ordering::SeqCst), 1);
        first.write_all(b"echo").await.unwrap();
        first.flush().await.unwrap();
        let mut out = [0; 4];
        first.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"echo");
        let waiter = pooled(&handler, a.clone());
        tokio::pin!(waiter);
        assert!(
            tokio::time::timeout(Duration::from_millis(30), &mut waiter)
                .await
                .is_err()
        );
        drop(first);
        let third = waiter.await;
        assert_eq!(a.opens.load(Ordering::SeqCst), 1);
        drop((second, other, third));
    })
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires AEROBOX_MUX_PEER built from tests/fixtures/mux-peer"]
async fn all_mux_protocols_exchange_tcp_and_udp_with_go_sing_mux() {
    use tokio::io::{AsyncBufReadExt, BufReader};
    tokio::time::timeout(Duration::from_secs(45), async {
        let binary = std::env::var_os("AEROBOX_MUX_PEER").expect("set AEROBOX_MUX_PEER");
        let mut child = tokio::process::Command::new(binary)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .await
            .unwrap();
        let port: u16 = line.trim().parse().unwrap();
        for protocol in [MuxProtocol::Smux, MuxProtocol::Yamux, MuxProtocol::H2Mux] {
            for padding in [false, true] {
                let socket = tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
                    .await
                    .unwrap();
                let session = client_session::Session::new(
                    Box::new(socket),
                    &H2MuxOptions {
                        protocol,
                        padding,
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
                let target = NetLocation::from_str("echo.example:4321", None).unwrap();
                let mut jobs = tokio::task::JoinSet::new();
                for index in 0..3 {
                    let stream = session.open(&target, true).await.unwrap();
                    jobs.spawn(async move {
                        let data = vec![index as u8; 512 * 1024];
                        let expected = data.clone();
                        let (mut read, mut write) = tokio::io::split(stream);
                        // SMUX v1 closes the full stream on FIN, so read the
                        // expected response before requesting a half-close.
                        let receive = async {
                            let mut out = vec![0; expected.len()];
                            read.read_exact(&mut out).await.unwrap();
                            assert_eq!(out, expected);
                        };
                        if protocol == MuxProtocol::Smux {
                            let send = async {
                                write.write_all(&data).await.unwrap();
                                write.flush().await.unwrap();
                            };
                            tokio::join!(send, receive);
                            write.shutdown().await.unwrap();
                        } else {
                            let send = async {
                                write.write_all(&data).await.unwrap();
                                write.shutdown().await.unwrap();
                            };
                            tokio::join!(send, receive);
                        }
                    });
                }
                let mut udp = session.open(&target, false).await.unwrap();
                for payload in [b"first".as_slice(), b"second", b""] {
                    udp.write_u16(payload.len() as u16).await.unwrap();
                    udp.write_all(payload).await.unwrap();
                    udp.flush().await.unwrap();
                    assert_eq!(udp.read_u16().await.unwrap() as usize, payload.len());
                    let mut result = vec![0; payload.len()];
                    udp.read_exact(&mut result).await.unwrap();
                    assert_eq!(result, payload);
                }
                drop(udp);
                while let Some(result) = jobs.join_next().await {
                    result.unwrap();
                }
            }
        }
        child.kill().await.unwrap();
        child.wait().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn stalled_route_does_not_block_other_routes_and_cancel_releases_capacity() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let handler = H2MuxClientHandler::new(
            Arc::new(Plain),
            H2MuxOptions {
                max_connections: 1,
                max_streams: 1,
                ..Default::default()
            },
        );
        let a = Arc::new(Route {
            key: RouteKey(vec![201]),
            opens: AtomicUsize::new(0),
        });
        let b = Arc::new(Route {
            key: RouteKey(vec![202]),
            opens: AtomicUsize::new(0),
        });
        let stalled = handler.connect_client_tcp(
            ClientTransport {
                reopen: None,
                route: a.clone(),
                open: Box::pin(std::future::pending()),
            },
            NetLocation::from_str("example.org:80", None)
                .unwrap()
                .into(),
        );
        let mut stalled = Box::pin(stalled);
        assert!(futures::poll!(&mut stalled).is_pending());
        let other = pooled(&handler, b.clone()).await;
        assert_eq!(b.opens.load(Ordering::Relaxed), 1);
        let mut waiter = Box::pin(pooled(&handler, a.clone()));
        assert!(futures::poll!(&mut waiter).is_pending());
        drop(stalled);
        let resumed = waiter.await;
        assert_eq!(a.opens.load(Ordering::Relaxed), 1);
        drop((other, resumed));
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn pooled_inner_reconnect_preserves_outer_wrappers_and_reuses_successful_session() {
    use crate::tcp::tcp_handler::ReopenTransport;

    #[derive(Debug)]
    struct RetryInner(AtomicUsize);
    #[async_trait]
    impl TcpClientHandler for RetryInner {
        async fn connect_client_tcp(
            &self,
            transport: ClientTransport<'_>,
            target: ResolvedLocation,
        ) -> io::Result<TcpClientSetupResult> {
            self.0.fetch_add(1, Ordering::SeqCst);
            assert_eq!(target.location().to_string(), "sp.mux.sing-box.arpa:444");
            let first = transport.open.await?;
            // Models an authenticated ECH rejection before application bytes.
            drop(first);
            let reopen = transport
                .reopen
                .expect("mux discarded reconnect capability");
            Ok(TcpClientSetupResult {
                client_stream: reopen().await?,
                early_data: None,
            })
        }
        async fn setup_client_tcp_stream(
            &self,
            _: Box<dyn AsyncStream>,
            _: ResolvedLocation,
        ) -> io::Result<TcpClientSetupResult> {
            panic!("pooled setup must retain ClientTransport for authenticated retries")
        }
    }

    #[derive(Debug)]
    struct ReopeningRoute {
        key: RouteKey,
        opens: AtomicUsize,
        wrappers: Arc<AtomicUsize>,
    }
    #[async_trait]
    impl CarrierDialer for ReopeningRoute {
        fn route_key(&self) -> &RouteKey {
            &self.key
        }
        async fn open_stream(&self) -> io::Result<Box<dyn AsyncStream>> {
            let attempt = self.opens.fetch_add(1, Ordering::SeqCst);
            let (stream, mut peer) = tokio::io::duplex(16384);
            let wrappers = self.wrappers.clone();
            tokio::spawn(async move {
                let mut prefix = [0; 7];
                peer.read_exact(&mut prefix).await.unwrap();
                assert_eq!(&prefix, b"wrapper");
                wrappers.fetch_add(1, Ordering::SeqCst);
                if attempt == 0 {
                    let mut rejected_data = Vec::new();
                    peer.read_to_end(&mut rejected_data).await.unwrap();
                    assert!(
                        rejected_data.is_empty(),
                        "mux bytes leaked before inner acceptance"
                    );
                    return;
                }
                let mut server = H2MuxServerSession::new(peer).await.unwrap();
                while let Some(inbound) = server.accept().await {
                    tokio::spawn(async move {
                        let (mut read, mut write) = tokio::io::split(inbound.stream);
                        let _ = tokio::io::copy(&mut read, &mut write).await;
                        let _ = write.shutdown().await;
                    });
                }
            });
            Ok(Box::new(stream))
        }
    }

    tokio::time::timeout(Duration::from_secs(5), async {
        let inner = Arc::new(RetryInner(AtomicUsize::new(0)));
        let handler = H2MuxClientHandler::new(
            inner.clone(),
            H2MuxOptions {
                max_connections: 1,
                max_streams: 4,
                ..Default::default()
            },
        );
        let route = Arc::new(ReopeningRoute {
            key: RouteKey(vec![1234]),
            opens: AtomicUsize::new(0),
            wrappers: Arc::new(AtomicUsize::new(0)),
        });
        let open = || {
            let route = route.clone();
            let carrier = route.clone();
            let reopen: ReopenTransport<'static> = Arc::new(move || {
                let route = carrier.clone();
                Box::pin(async move { route.open_stream().await })
            });
            ClientTransport {
                route: route.clone(),
                open: reopen(),
                reopen: Some(reopen),
            }
            .wrap(|mut stream| async move {
                stream.write_all(b"wrapper").await?;
                Ok(stream)
            })
        };
        let target: ResolvedLocation = NetLocation::from_str("echo.example:80", None)
            .unwrap()
            .into();
        for payload in [b"first".as_slice(), b"second"] {
            let mut stream = handler
                .connect_client_tcp(open(), target.clone())
                .await
                .unwrap()
                .client_stream;
            stream.write_all(payload).await.unwrap();
            stream.flush().await.unwrap();
            let mut response = vec![0; payload.len()];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(response, payload);
        }
        assert_eq!(route.opens.load(Ordering::SeqCst), 2);
        while route.wrappers.load(Ordering::SeqCst) < 2 {
            tokio::task::yield_now().await;
        }
        assert_eq!(route.wrappers.load(Ordering::SeqCst), 2);
        assert_eq!(inner.0.load(Ordering::SeqCst), 1);
    })
    .await
    .unwrap();
}
