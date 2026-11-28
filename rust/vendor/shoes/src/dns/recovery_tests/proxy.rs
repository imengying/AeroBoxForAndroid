use super::*;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Relay {
    address: SocketAddr,
    blackhole: Arc<AtomicBool>,
    opens: Arc<AtomicUsize>,
    live: Arc<AtomicUsize>,
    _task: AbortOnDropHandle<()>,
}

impl Relay {
    async fn start(target: SocketAddr) -> Self {
        let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
        let address = SocketAddr::from(([127, 0, 0, 1], listener.local_addr().unwrap().port()));
        let blackhole = Arc::new(AtomicBool::new(false));
        let opens = Arc::new(AtomicUsize::new(0));
        let live = Arc::new(AtomicUsize::new(0));
        let state = (blackhole.clone(), opens.clone(), live.clone());
        let task = AbortOnDropHandle::new(tokio::spawn(async move {
            let (blackhole, opens, live) = state;
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (downstream, _) = accepted.unwrap();
                        opens.fetch_add(1, Ordering::SeqCst);
                        let blackhole = blackhole.clone();
                        let live = live.clone();
                        connections.spawn(async move {
                            struct Active(Arc<AtomicUsize>);
                            impl Drop for Active {
                                fn drop(&mut self) { self.0.fetch_sub(1, Ordering::SeqCst); }
                            }
                            live.fetch_add(1, Ordering::SeqCst);
                            let _active = Active(live);
                            let upstream = tokio::net::TcpStream::connect(target).await.unwrap();
                            let (down_read, down_write) = downstream.into_split();
                            let (up_read, up_write) = upstream.into_split();
                            let forward = |mut read: tokio::net::tcp::OwnedReadHalf, mut write: tokio::net::tcp::OwnedWriteHalf| {
                                let blackhole = blackhole.clone();
                                async move {
                                    let mut bytes = [0; 16384];
                                    loop {
                                        let length = read.read(&mut bytes).await?;
                                        if length == 0 { return Ok::<_, std::io::Error>(()); }
                                        if !blackhole.load(Ordering::SeqCst) {
                                            write.write_all(&bytes[..length]).await?;
                                        }
                                    }
                                }
                            };
                            tokio::select! {
                                _ = forward(down_read, up_write) => {},
                                _ = forward(up_read, down_write) => {},
                            }
                        });
                    }
                    _ = connections.join_next(), if !connections.is_empty() => {},
                }
            }
        }));
        Self {
            address,
            blackhole,
            opens,
            live,
            _task: task,
        }
    }
}

struct Proxy {
    relay: Relay,
    client: serde_json::Value,
    network: crate::network_tasks::NetworkLifetime,
    handles: Vec<tokio::task::JoinHandle<()>>,
}

impl Proxy {
    async fn start() -> Self {
        let reservation = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
        let address = SocketAddr::from(([127, 0, 0, 1], reservation.local_addr().unwrap().port()));
        let protocol = json!({"type":"vless", "user_id":"550e8400-e29b-41d4-a716-446655440000"});
        let (server, client) = {
            let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let digest =
                aerobox_primitives::digest::digest(&aerobox_primitives::digest::SHA256, certificate.cert.der());
            let fingerprint: String = digest
                .as_ref()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            (
                json!({"type":"tls", "default_target":{"cert":certificate.cert.pem(), "key":certificate.signing_key.serialize_pem(), "protocol":protocol}}),
                json!({"type":"tls", "verify":false, "server_fingerprints":[fingerprint], "sni_hostname":"localhost", "protocol":protocol}),
            )
        };
        let config = crate::config::create_server_configs(
            serde_json::from_value(json!([
                {"address":address.to_string(), "protocol":server}
            ]))
            .unwrap(),
        )
        .unwrap()
        .configs
        .remove(0);
        let network = crate::network_tasks::NetworkLifetime::default();
        drop(reservation);
        let handles = network
            .scope(crate::tcp::tcp_server::start_servers(
                config,
                Arc::new(NativeResolver::new()),
            ))
            .await
            .unwrap();
        let relay = Relay::start(address).await;
        let client = json!({"name":"tls", "address":relay.address.to_string(), "protocol":client});
        Self {
            relay,
            client,
            network,
            handles,
        }
    }

    async fn stop(self) {
        self.network.cancel();
        self.network.wait().await;
        for handle in self.handles {
            let _ = handle.await;
        }
    }
}





#[tokio::test]
async fn doh_pool_fails_over_after_proxy_setup_other_error() {
    let failed = DohFixture::start().await;
    let healthy = DohFixture::start().await;
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
    let address = SocketAddr::from(([127, 0, 0, 1], listener.local_addr().unwrap().port()));
    let failed_address = failed.address;
    let healthy_address = healthy.address;
    let rejected = Arc::new(AtomicUsize::new(0));
    let count = rejected.clone();
    let proxy = AbortOnDropHandle::new(tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (tcp, _) = accepted.unwrap();
                    let count = count.clone();
                    tasks.spawn(async move {
                        let mut h2 = h2::server::handshake(tcp).await.unwrap();
                        let mut tunnels = tokio::task::JoinSet::new();
                        while let Some(Ok((request, mut respond))) = h2.accept().await {
                            assert_eq!(request.method(), http::Method::CONNECT);
                            let target = request.uri().authority().unwrap().as_str().parse::<SocketAddr>().unwrap();
                            if target == failed_address {
                                count.fetch_add(1, Ordering::SeqCst);
                                respond.send_response(http::Response::builder().status(503).body(()).unwrap(), true).unwrap();
                            } else {
                                assert_eq!(target, healthy_address);
                                tunnels.spawn(async move {
                                    // Ensure the setup error arrives before the healthy parallel answer.
                                    tokio::time::sleep(Duration::from_millis(30)).await;
                                    let mut upstream = tokio::net::TcpStream::connect(target).await.unwrap();
                                    let send = respond.send_response(http::Response::new(()), false).unwrap();
                                    let mut stream = crate::http2::stream::H2MultiStream::new(send, request.into_body());
                                    let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
                                });
                            }
                        }
                    });
                }
                _ = tasks.join_next(), if !tasks.is_empty() => {},
            }
        }
    }));
    let chain = crate::config::test_support::from_json(json!([{
        "address":address.to_string(), "protocol":{"type":"http", "http_version":"h2"}
    }]))
    .unwrap();
    let bootstrap: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let group = Arc::new(
        crate::tcp::chain_builder::try_build_client_chain_group(
            crate::option_util::NoneOrSome::One(chain),
            bootstrap.clone(),
        )
        .unwrap(),
    );
    let servers = [failed.address, healthy.address]
        .into_iter()
        .map(|address| {
            let mut connection = hickory_resolver::config::ConnectionConfig::https(
                "localhost".into(),
                Some("/dns-query".into()),
            );
            connection.port = address.port();
            (address.ip(), connection)
        })
        .collect();
    let resolver = crate::rustls_config_util::with_test_roots(healthy.roots.clone(), || {
        HickoryResolver::build_pooled(
            servers,
            group,
            bootstrap,
            HickoryResolverOptions {
                ip_strategy: super::super::IpStrategy::Ipv4Only,
                request_timeout: Some(Duration::from_millis(150)),
                attempts: 1,
                ..Default::default()
            },
            "proxy setup failover".into(),
        )
        .unwrap()
    });
    resolver
        .resolve_location(&NetLocation::from_str("pooled.example:80", None).unwrap())
        .await
        .unwrap();
    assert_eq!(rejected.load(Ordering::SeqCst), 1);
    assert_eq!(failed.requests.load(Ordering::SeqCst), 0);
    assert_eq!(healthy.requests.load(Ordering::SeqCst), 1);
    resolver.retire();
    drop(proxy);
    healthy.wait_closed().await;
}

#[tokio::test]
async fn rejected_proxy_pin_is_not_retried_or_bypassed() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let fixture = DohFixture::start().await;
        let mut proxy = Proxy::start().await;
        proxy.client["protocol"]["server_fingerprints"] = json!(["00".repeat(32)]);
        let chain = crate::config::test_support::from_json(json!([proxy.client.clone()])).unwrap();
        let bootstrap: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let group = Arc::new(
            crate::tcp::chain_builder::try_build_client_chain_group(
                crate::option_util::NoneOrSome::One(chain),
                bootstrap.clone(),
            )
            .unwrap(),
        );
        let resolver = fixture.refreshing_via(group, bootstrap).await;
        let error = resolver.exchange(query(0)).await.unwrap_err();
        assert!(error.to_string().contains("fingerprint"), "{error:?}");
        assert!(!crate::resolver::RefreshingResolver::should_refresh_for_error(&error));
        assert_eq!(proxy.relay.opens.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.connections.load(Ordering::SeqCst), 0);
        drop(resolver);
        proxy.stop().await;
    })
    .await
    .unwrap();
}
