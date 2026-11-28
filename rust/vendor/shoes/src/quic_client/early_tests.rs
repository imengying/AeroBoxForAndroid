use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadBuf};
use tokio_util::task::AbortOnDropHandle;

use super::Client;
use crate::{
    address::{NetLocation, ResolvedLocation},
    async_stream::{AsyncMessageStream, AsyncStream},
    config::ResolvedClientConfig,
    resolver::{NativeResolver, Resolver},
    tcp::{
        carrier_dialer::{
            CarrierDialer, EarlyDataOutcome, PendingQuicCarrier, QuicCarrier, RouteKey,
        },
        proxy_connector::ProxyConnector,
        socket_connector::SocketConnector,
        socket_connector_impl::SocketConnectorImpl,
    },
};

const UUID: &str = "d9ad4eab-f118-492b-a99b-e0e27332b4b2";

#[derive(Debug)]
struct Dialer {
    connector: SocketConnectorImpl,
    resolver: Arc<dyn Resolver>,
    address: ResolvedLocation,
    key: RouteKey,
    connections: parking_lot::Mutex<Vec<quinn::Connection>>,
    outcomes: Arc<parking_lot::Mutex<Vec<EarlyDataOutcome>>>,
    early: AtomicUsize,
    gate_next: AtomicBool,
    fail_next: AtomicBool,
    short_deadline_ms: AtomicU64,
    gate: Arc<tokio::sync::Semaphore>,
}
#[async_trait::async_trait]
impl CarrierDialer for Dialer {
    fn route_key(&self) -> &RouteKey {
        &self.key
    }
    async fn open_stream(&self) -> io::Result<Box<dyn AsyncStream>> {
        unreachable!()
    }
    async fn open_quic(&self) -> io::Result<QuicCarrier> {
        let carrier = self
            .connector
            .connect_quic(&self.resolver, &self.address)
            .await?;
        self.connections.lock().push(carrier.connection.clone());
        self.outcomes.lock().push(EarlyDataOutcome::NotAttempted);
        Ok(carrier)
    }
    async fn open_quic_early(&self) -> io::Result<PendingQuicCarrier> {
        let mut pending = self
            .connector
            .connect_quic_early(&self.resolver, &self.address)
            .await?;
        if let Some(carrier) = &pending.early {
            self.early.fetch_add(1, Ordering::SeqCst);
            self.connections.lock().push(carrier.connection.clone());
        }
        let gated = self.gate_next.swap(false, Ordering::SeqCst);
        let fail = self.fail_next.swap(false, Ordering::SeqCst);
        let milliseconds = self.short_deadline_ms.swap(0, Ordering::SeqCst);
        if milliseconds != 0 {
            pending.deadline = pending
                .deadline
                .min(tokio::time::Instant::now() + Duration::from_millis(milliseconds));
        }
        let gate = self.gate.clone();
        let outcomes = self.outcomes.clone();
        let completion = pending.completion;
        pending.completion = Box::pin(async move {
            if gated {
                gate.acquire().await.map_err(io::Error::other)?.forget();
            }
            if fail {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "test handshake identity rejected",
                ));
            }
            let result = completion.await?;
            outcomes.lock().push(result.early_data);
            Ok(result)
        });
        Ok(pending)
    }
}

fn configuration(
    address: SocketAddr,
    root: String,
    early: bool,
    mode: &str,
) -> ResolvedClientConfig {
    let mut value = json!({
        "address":address.to_string(),"transport":"quic",
        "quic_settings":{"verify":true,"sni_hostname":"localhost","alpn_protocols":["h3"],"options":{"root_certificates":[root]}},
        "protocol":{"type":"tuic","uuid":UUID,"password":"test-password","zero_rtt_handshake":early}
    });
    if mode == "uot" {
        value["protocol"]["udp_over_stream"] = true.into();
    } else {
        value["protocol"]["udp_relay_mode"] = mode.into();
    }
    crate::config::test_support::from_json(value).unwrap()
}

fn client(config: ResolvedClientConfig) -> (Client, Arc<Dialer>) {
    let connector = SocketConnectorImpl::from_config(&config, Some(&config.address)).unwrap();
    let address = config.address.clone().into();
    let client = Client::new(config).unwrap();
    let dialer = Arc::new(Dialer {
        connector,
        resolver: Arc::new(NativeResolver::new()),
        address,
        key: RouteKey(vec![199]),
        connections: Default::default(),
        outcomes: Default::default(),
        early: AtomicUsize::new(0),
        gate_next: AtomicBool::new(false),
        fail_next: AtomicBool::new(false),
        short_deadline_ms: AtomicU64::new(0),
        gate: Arc::new(tokio::sync::Semaphore::new(0)),
    });
    (client, dialer)
}

fn target(name: &str) -> ResolvedLocation {
    NetLocation::from_str(name, None).unwrap().into()
}

async fn tcp_echo(stream: Box<dyn AsyncStream>, size: usize) {
    let (mut read, mut write) = tokio::io::split(stream);
    let data: Vec<_> = (0..size).map(|n| (n % 251) as u8).collect();
    let mut received = vec![0; size];
    let (sent, echoed) = tokio::join!(
        async {
            write.write_all(&data).await?;
            write.flush().await?;
            write.shutdown().await
        },
        read.read_exact(&mut received),
    );
    sent.unwrap();
    echoed.unwrap();
    assert_eq!(received, data);
    let mut tail = Vec::new();
    read.read_to_end(&mut tail).await.unwrap();
    assert!(
        tail.is_empty(),
        "early replay duplicated bytes after expected payload"
    );
}

async fn warm(client: &Client, dialer: &Arc<Dialer>) {
    let stream = client
        .connect_tcp_with_dialer(dialer.clone(), &target("warm.test:443"))
        .await
        .unwrap();
    tcp_echo(stream.client_stream, 4).await;
    let generation = client
        .sessions
        .get(dialer.clone(), &client.protocol, false)
        .await
        .unwrap();
    generation.ready().await.unwrap();
    generation
        .connection()
        .close(0u32.into(), b"test ticket reconnect");
    generation.connection().closed().await;
}

fn local() -> (ResolvedClientConfig, AbortOnDropHandle<()>) {
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(aerobox_crypto::provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.signing_key.serialize_der())
                .into(),
        )
        .unwrap();
    tls.max_early_data_size = u32::MAX;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let server = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap(),
        )),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let config = configuration(
        server.local_addr().unwrap(),
        certificate.cert.pem(),
        true,
        "native",
    );
    let task = AbortOnDropHandle::new(tokio::spawn(async move {
        let mut sessions = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                incoming = server.accept() => {
                    let Some(incoming) = incoming else { break };
                    sessions.spawn(async move {
                        let Ok(connection) = incoming.await else { return };
                        let Ok(mut auth) = connection.accept_uni().await else { return };
                        let Ok(bytes) = auth.read_to_end(50).await else { return };
                        if bytes.len() != 50 { return; }
                        let mut token = [0;32];
                        connection.export_keying_material(&mut token, &bytes[2..18], b"test-password").unwrap();
                        assert_eq!(&bytes[18..], &token);
                        let mut streams = tokio::task::JoinSet::new();
                        loop {
                            tokio::select! {
                                pair = connection.accept_bi() => {
                                    let Ok((mut send, mut recv)) = pair else { break };
                                    streams.spawn(async move {
                                        let mut prefix = [0;4];
                                        if recv.read_exact(&mut prefix).await.is_err() { return; }
                                        assert_eq!(&prefix[..3], &[5,1,0]);
                                        let mut address = vec![0;prefix[3] as usize + 2];
                                        if recv.read_exact(&mut address).await.is_err() { return; }
                                        if tokio::io::copy(&mut recv, &mut send).await.is_ok() { let _ = send.finish(); }
                                    });
                                }
                                Some(result) = streams.join_next(), if !streams.is_empty() => { result.unwrap(); }
                            }
                        }
                    });
                }
                Some(result) = sessions.join_next(), if !sessions.is_empty() => { result.unwrap(); }
            }
        }
    }));
    (config, task)
}

#[tokio::test]
async fn tuic_early_backpressure_gates_read_flush_fin_and_native_udp_until_authentication() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (config, _server) = local();
        let (client, dialer) = client(config);
        warm(&client, &dialer).await;
        dialer.gate_next.store(true, Ordering::SeqCst);
        let mut stream = client
            .connect_tcp_with_dialer(dialer.clone(), &target("early.test:443"))
            .await
            .unwrap()
            .client_stream;
        assert_eq!(
            dialer.early.load(Ordering::SeqCst),
            1,
            "test must use a real resumption ticket"
        );
        let prefix = vec![7; 65536];
        stream.write_all(&prefix).await.unwrap();
        assert!(futures::poll!(Box::pin(stream.write(&[9]))).is_pending());
        assert!(futures::poll!(Box::pin(stream.flush())).is_pending());
        assert!(futures::poll!(Box::pin(stream.shutdown())).is_pending());
        let mut byte = [0; 1];
        assert!(futures::poll!(Box::pin(stream.read(&mut byte))).is_pending());
        let mut udp =
            Box::pin(client.connect_udp_with_dialer(dialer.clone(), target("packet.test:53")));
        assert!(futures::poll!(&mut udp).is_pending());
        dialer.gate.add_permits(1);
        let mut udp = udp.await.unwrap();
        let (mut read, mut write) = tokio::io::split(stream);
        let mut received = vec![0; 65539];
        let (a, b) = tokio::join!(
            async {
                write.write_all(&[9, 8, 7]).await?;
                write.shutdown().await
            },
            read.read_exact(&mut received)
        );
        a.unwrap();
        b.unwrap();
        assert_eq!(&received[..65536], prefix);
        assert_eq!(&received[65536..], &[9, 8, 7]);
        std::future::poll_fn(|cx| Pin::new(&mut *udp).poll_shutdown_message(cx))
            .await
            .unwrap();
        assert_eq!(
            dialer.outcomes.lock().as_slice(),
            &[EarlyDataOutcome::NotAttempted, EarlyDataOutcome::Accepted]
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn tuic_early_pool_retirement_and_handshake_error_poison_retained_streams() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for mode in ["retire", "identity", "deadline"] {
            let (config, _server) = local();
            let (client, dialer) = client(config);
            warm(&client, &dialer).await;
            dialer.gate_next.store(true, Ordering::SeqCst);
            if mode == "deadline" {
                dialer.short_deadline_ms.store(50, Ordering::SeqCst);
            }
            if mode == "identity" {
                dialer.fail_next.store(true, Ordering::SeqCst);
            }
            let mut stream = client
                .connect_tcp_with_dialer(dialer.clone(), &target("early.test:443"))
                .await
                .unwrap()
                .client_stream;
            stream.write_all(b"unconfirmed data").await.unwrap();
            assert_eq!(dialer.early.load(Ordering::SeqCst), 1);
            let expected = match mode {
                "retire" => {
                    drop(client);
                    io::ErrorKind::ConnectionAborted
                }
                "identity" => {
                    dialer.gate.add_permits(1);
                    io::ErrorKind::PermissionDenied
                }
                _ => io::ErrorKind::TimedOut,
            };
            assert_eq!(stream.flush().await.unwrap_err().kind(), expected, "{mode}");
            let mut bytes = [0; 64];
            assert_eq!(
                stream.read(&mut bytes).await.unwrap_err().kind(),
                expected,
                "{mode}"
            );
            assert_eq!(bytes, [0; 64]);
            assert_eq!(
                stream.write(b"must not replay").await.unwrap_err().kind(),
                expected,
                "{mode}"
            );
            assert_eq!(
                stream.shutdown().await.unwrap_err().kind(),
                expected,
                "{mode}"
            );
        }
    })
    .await
    .unwrap();
}

#[test]
fn tuic_early_rejects_strict_hybrid_before_native_or_resolved_socket_creation() {
    for early in [false, true] {
        let value = json!({"address":"localhost:443","transport":"quic",
            "quic_settings":{"key_exchange_groups":["X25519MLKEM768"]},
            "protocol":{"type":"tuic","uuid":UUID,"password":"test-password","zero_rtt_handshake":early}});
        let native: crate::config::ClientConfig = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(native.validate_quic_key_exchange(true).is_err(), early);
        let resolved: ResolvedClientConfig = crate::config::test_support::from_json(value).unwrap();
        assert_eq!(resolved.validate_quic_key_exchange(true).is_err(), early);
    }
}

async fn udp_echo(stream: &mut dyn AsyncMessageStream, data: &[u8]) {
    std::future::poll_fn(|cx| Pin::new(&mut *stream).poll_write_message(cx, data))
        .await
        .unwrap();
    std::future::poll_fn(|cx| Pin::new(&mut *stream).poll_flush_message(cx))
        .await
        .unwrap();
    let mut buffer = vec![0; 65535];
    let mut read = ReadBuf::new(&mut buffer);
    std::future::poll_fn(|cx| Pin::new(&mut *stream).poll_read_message(cx, &mut read))
        .await
        .unwrap();
    assert_eq!(read.filled(), data);
    assert!(!stream.read_message_eof_on_empty());
}
fn events(path: &std::path::Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[tokio::test]
#[ignore = "requires AEROBOX_TUIC_PEER built from the pinned independent Go fixture"]
async fn tuic_actual_early_accept_reject_and_udp_modes_with_go() {
    use std::process::Stdio;
    use tokio::io::{AsyncBufReadExt, BufReader};
    tokio::time::timeout(Duration::from_secs(40), async {
        for server_mode in ["accept", "reject-after-first", "disabled"] {
            for mode in ["native", "quic", "uot"] {
                let directory = tempfile::tempdir().unwrap();
                let mut process = tokio::process::Command::new(std::env::var_os("AEROBOX_TUIC_PEER").unwrap())
                    .arg(server_mode).env("AEROBOX_PEER_CERT_DIR", directory.path())
                    .env("AEROBOX_TUIC_HANDSHAKE_DELAY_MS", "50")
                    .stdout(Stdio::piped()).stderr(Stdio::inherit()).kill_on_drop(true).spawn().unwrap();
                let port: u16 = BufReader::new(process.stdout.take().unwrap()).lines().next_line().await.unwrap().unwrap().parse().unwrap();
                let root = std::fs::read_to_string(directory.path().join("ca.pem")).unwrap();
                let (client, dialer) = client(configuration(([127,0,0,1],port).into(), root, true, mode));
                warm(&client, &dialer).await;
                let stream = client.connect_tcp_with_dialer(dialer.clone(), &target("early.test:443")).await.unwrap();
                tcp_echo(stream.client_stream, 200_003).await;
                let mut packets = client.connect_udp_with_dialer(dialer.clone(), target("packet.test:5353")).await.unwrap();
                for size in [0usize,3,16384,65535] {
                    let data: Vec<_> = (0..size).map(|n| (n%251) as u8).collect();
                    udp_echo(&mut *packets, &data).await;
                }
                let expected = match server_mode {
                    "accept" => EarlyDataOutcome::Accepted,
                    "reject-after-first" => EarlyDataOutcome::Rejected,
                    _ => EarlyDataOutcome::NotAttempted,
                };
                assert_eq!(dialer.outcomes.lock().as_slice(), &[EarlyDataOutcome::NotAttempted, expected], "{server_mode}/{mode}");
                assert_eq!(dialer.early.load(Ordering::SeqCst), usize::from(server_mode != "disabled"));
                let rows = events(&directory.path().join("events.jsonl"));
                let handshakes: Vec<_> = rows.iter().filter(|r| r["event"] == "handshake").collect();
                assert_eq!(handshakes.len(),2,"{server_mode}/{mode}: {rows:?}");
                assert_eq!(handshakes[1]["used_0rtt"], server_mode=="accept", "{rows:?}");
                if server_mode != "disabled" { assert_eq!(handshakes[1]["resumed"], true, "{rows:?}"); }
                assert_eq!(rows.iter().filter(|r| r["event"] == "tcp_open" && r["destination"] == "early.test:443").count(),1,"replay duplicated CONNECT: {rows:?}");
                let closed: Vec<_> = rows.iter().filter(|r| r["event"] == "tcp_closed" && r["destination"] == "early.test:443").collect();
                assert_eq!(closed.len(),1); assert_eq!(closed[0]["bytes"],200_003);
                assert_eq!(rows.iter().filter(|r| r["event"] == "offer").count(),2,"TCP and UDP must share generation");
                drop((packets,client,dialer));
                process.kill().await.unwrap(); process.wait().await.unwrap();
            }
        }
    }).await.unwrap();
}
