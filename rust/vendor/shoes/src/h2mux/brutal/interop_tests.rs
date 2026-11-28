use super::*;
use crate::{
    address::ResolvedLocation,
    async_stream::AsyncStream,
    h2mux::{H2MuxClientHandler, H2MuxOptions, MuxProtocol},
    tcp::{
        carrier_dialer::{CarrierDialer, RouteKey},
        tcp_handler::{ClientTransport, TcpClientHandler, TcpClientSetupResult},
    },
};
use async_trait::async_trait;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

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
#[derive(Debug)]
struct Route {
    port: u16,
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
        Ok(Box::new(
            tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, self.port)).await?,
        ))
    }
}
fn transport(route: Arc<Route>) -> ClientTransport<'static> {
    ClientTransport {
        route: route.clone(),
        reopen: None,
        open: Box::pin(async move { route.open_stream().await }),
    }
}
async fn peer(mode: &str, path: &std::path::Path) -> (tokio::process::Child, u16) {
    let binary =
        std::env::var_os("AEROBOX_MUX_PEER").expect("set AEROBOX_MUX_PEER, built with -tags debug");
    let mut child = tokio::process::Command::new(binary)
        .arg(mode)
        .env("AEROBOX_MUX_EVENTS", path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .await
        .unwrap();
    (child, line.trim().parse().unwrap())
}

#[tokio::test]
#[ignore = "requires AEROBOX_MUX_PEER with -tags debug"]
async fn tcp_brutal_all_mux_padding_rates_pool_and_remote_rejection_with_go() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let dir = tempfile::tempdir().unwrap();
        let events = dir.path().join("accept.txt");
        let (mut child, port) = peer("brutal", &events).await;
        for protocol in [MuxProtocol::H2Mux, MuxProtocol::Smux, MuxProtocol::Yamux] {
            for padding in [false, true] {
                eprintln!("TCP Brutal {:?}, padding={padding}", protocol);
                let handler = H2MuxClientHandler::new(
                    Arc::new(Plain),
                    H2MuxOptions {
                        protocol,
                        padding,
                        max_connections: 4,
                        min_streams: 1,
                        max_streams: 4,
                        brutal: Some(BrutalConfig {
                            enabled: true,
                            up_mbps: 8,
                            down_mbps: 16,
                        }),
                    },
                );
                let route = Arc::new(Route {
                    port,
                    key: RouteKey(vec![port as usize]),
                    opens: AtomicUsize::new(0),
                });
                let target: ResolvedLocation =
                    NetLocation::new(Address::Hostname("brutal-echo.example".into()), 4321).into();
                let mut held = Vec::new();
                for data in [vec![1; 3], vec![2; 65537]] {
                    let mut stream = handler
                        .connect_client_tcp(transport(route.clone()), target.clone())
                        .await
                        .unwrap()
                        .client_stream;
                    stream.write_all(&data).await.unwrap();
                    stream.flush().await.unwrap();
                    let mut actual = vec![0; data.len()];
                    stream.read_exact(&mut actual).await.unwrap();
                    assert_eq!(actual, data);
                    assert!(stream.tcp_socket_control().unwrap().is_none());
                    held.push(stream);
                }
                let mut udp = handler
                    .connect_client_udp(transport(route.clone()), target)
                    .await
                    .unwrap();
                for length in [0, 3, 16384, 65535] {
                    let data = vec![0x5a; length];
                    std::future::poll_fn(|cx| {
                        std::pin::Pin::new(&mut *udp).poll_write_message(cx, &data)
                    })
                    .await
                    .unwrap();
                    std::future::poll_fn(|cx| std::pin::Pin::new(&mut *udp).poll_flush_message(cx))
                        .await
                        .unwrap();
                    let mut actual = vec![0; 65535];
                    let mut buffer = tokio::io::ReadBuf::new(&mut actual);
                    std::future::poll_fn(|cx| {
                        std::pin::Pin::new(&mut *udp).poll_read_message(cx, &mut buffer)
                    })
                    .await
                    .unwrap();
                    assert_eq!(buffer.filled().len(), length);
                    assert_eq!(buffer.filled(), data);
                }
                assert_eq!(
                    route.opens.load(Ordering::SeqCst),
                    1,
                    "Brutal must reuse the first carrier despite min_streams=1"
                );
                drop((udp, held, handler));
            }
        }
        let records = std::fs::read_to_string(&events).unwrap();
        assert_eq!(
            records
                .lines()
                .filter(|l| l.starts_with("carrier "))
                .count(),
            6
        );
        assert_eq!(records.lines().filter(|l| *l == "tcp").count(), 12);
        assert_eq!(records.lines().filter(|l| *l == "udp").count(), 6);
        child.kill().await.unwrap();

        let events = dir.path().join("reject.txt");
        let (mut child, port) = peer("reject", &events).await;
        let handler = H2MuxClientHandler::new(
            Arc::new(Plain),
            H2MuxOptions {
                brutal: Some(BrutalConfig {
                    enabled: true,
                    up_mbps: 1,
                    down_mbps: 1,
                }),
                ..Default::default()
            },
        );
        let route = Arc::new(Route {
            port,
            key: RouteKey(vec![port as usize]),
            opens: AtomicUsize::new(0),
        });
        for _ in 0..2 {
            let result = handler
                .connect_client_tcp(
                    transport(route.clone()),
                    NetLocation::new(Address::Hostname("never-open.example".into()), 443).into(),
                )
                .await;
            assert_eq!(
                result.err().unwrap().kind(),
                io::ErrorKind::ConnectionRefused
            );
        }
        assert_eq!(route.opens.load(Ordering::SeqCst), 2);
        let records = std::fs::read_to_string(events).unwrap();
        assert!(!records.lines().any(|line| matches!(line, "tcp" | "udp")));
        child.kill().await.unwrap();
    })
    .await
    .unwrap();
}
