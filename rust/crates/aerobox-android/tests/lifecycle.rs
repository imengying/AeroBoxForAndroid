use shoes::embedding::{EmbeddedCore, Platform};
use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

static LIFECYCLE_GATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct MultiNetworkPlatform {
    snapshot: std::sync::Mutex<shoes::embedding::PhysicalNetworkSnapshot>,
    bindings: std::sync::Mutex<Vec<(u64, u64)>>,
}
impl MultiNetworkPlatform {
    fn new() -> Self {
        use shoes::embedding::{PhysicalNetwork, PhysicalNetworkKind, PhysicalNetworkSnapshot};
        Self {
            snapshot: std::sync::Mutex::new(PhysicalNetworkSnapshot {
                generation: 1,
                default_handle: Some(1),
                networks: vec![
                    PhysicalNetwork {
                        handle: 1,
                        kind: PhysicalNetworkKind::Wifi,
                        interface: "wlan0".into(),
                        dns: vec![],
                    },
                    PhysicalNetwork {
                        handle: 2,
                        kind: PhysicalNetworkKind::Cellular,
                        interface: "rmnet0".into(),
                        dns: vec![],
                    },
                ],
            }),
            bindings: Default::default(),
        }
    }
}
impl Platform for MultiNetworkPlatform {
    fn protect(&self, _: i32) -> io::Result<()> {
        Ok(())
    }
    fn dns_servers(&self) -> io::Result<Vec<SocketAddr>> {
        Ok(vec!["127.0.0.1:9".parse().unwrap()])
    }
    fn physical_networks(&self) -> io::Result<shoes::embedding::PhysicalNetworkSnapshot> {
        Ok(self.snapshot.lock().unwrap().clone())
    }
    fn protect_on_network(&self, _: i32, generation: u64, handle: u64) -> io::Result<()> {
        self.bindings.lock().unwrap().push((generation, handle));
        let snapshot = self.snapshot.lock().unwrap();
        if generation != snapshot.generation
            || !snapshot
                .networks
                .iter()
                .any(|network| network.handle == handle)
        {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "expired physical network",
            ));
        }
        if handle == 1 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Wi-Fi bind failed",
            ));
        }
        Ok(())
    }
}

#[tokio::test(flavor = "current_thread")]
async fn physical_network_switch_and_service_restart_replace_bindings_and_pooled_flows() {
    let _gate = LIFECYCLE_GATE.lock().await;
    tokio::time::timeout(Duration::from_secs(15), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                tasks.spawn(async move {
                    let (mut read, mut write) = stream.split();
                    let _ = tokio::io::copy(&mut read, &mut write).await;
                });
            }
        });
        let proxy = vacant_address();
        let document = serde_json::json!({
            "inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":proxy.port()}],
            "outbounds":[{"type":"direct","tag":"direct","network_strategy":"fallback"}],
            "route":{"final":"direct","auto_detect_interface":true}
        });
        let config = aerobox_config::normalize_json(&document.to_string(), None).unwrap();
        let platform = Arc::new(MultiNetworkPlatform::new());
        EmbeddedCore::check_json(&config).await.unwrap();
        let core = EmbeddedCore::start_json(&config, Some(platform.clone()))
            .await
            .unwrap();
        let mut old = socks(proxy, target).await;
        echo(&mut old).await;
        assert_eq!(*platform.bindings.lock().unwrap(), [(1, 1), (1, 2)]);
        {
            let mut snapshot = platform.snapshot.lock().unwrap();
            snapshot.generation = 2;
            snapshot.default_handle = Some(2);
            snapshot.networks.retain(|network| network.handle == 2);
        }
        core.network_changed().await.unwrap();
        closed(&mut old).await;
        let mut fresh = socks(proxy, target).await;
        echo(&mut fresh).await;
        assert_eq!(platform.bindings.lock().unwrap().last(), Some(&(2, 2)));
        core.shutdown().await.unwrap();
        closed(&mut fresh).await;
        let old_count = platform.bindings.lock().unwrap().len();
        let replacement = Arc::new(MultiNetworkPlatform::new());
        let core = EmbeddedCore::start_json(&config, Some(replacement.clone()))
            .await
            .unwrap();
        let mut restarted = socks(proxy, target).await;
        echo(&mut restarted).await;
        assert_eq!(*replacement.bindings.lock().unwrap(), [(1, 1), (1, 2)]);
        assert_eq!(platform.bindings.lock().unwrap().len(), old_count);
        core.shutdown().await.unwrap();
        closed(&mut restarted).await;
        echo_task.abort();
        let _ = echo_task.await;
    })
    .await
    .unwrap();
}

struct TestPlatform(AtomicUsize);
impl Platform for TestPlatform {
    fn protect(&self, _: i32) -> io::Result<()> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    fn dns_servers(&self) -> io::Result<Vec<SocketAddr>> {
        Ok(vec!["127.0.0.1:9".parse().unwrap()])
    }
}

fn config(address: SocketAddr) -> String {
    serde_json::json!([{ "address": address.to_string(), "protocol": {"type": "socks"}, "name": "local-socks" }]).to_string()
}

fn app_config(address: SocketAddr) -> String {
    serde_json::json!({
        "outbounds":[{"type":"direct","tag":"direct"}],
        "route":{"final":"direct"},
        "inbounds":[{"type":"socks","tag":"local-socks","listen":address.ip().to_string(),"listen_port":address.port()}]
    }).to_string()
}

fn vacant_address() -> SocketAddr {
    let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    reserved.local_addr().unwrap()
}

async fn socks(proxy: SocketAddr, target: SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut response = [0; 2];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [5, 0]);
    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let mut response = [0; 4];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(response[1], 0);
    let length = if response[3] == 1 { 6 } else { 18 };
    stream.read_exact(&mut vec![0; length]).await.unwrap();
    stream
}

async fn echo(stream: &mut TcpStream) {
    stream.write_all(b"lifecycle-bytes").await.unwrap();
    let mut response = [0; 15];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"lifecycle-bytes");
}

async fn closed(stream: &mut TcpStream) {
    match tokio::time::timeout(Duration::from_secs(3), stream.read(&mut [0; 1]))
        .await
        .unwrap()
    {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
            ) => {}
        other => panic!("connection did not close: {other:?}"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn app_connections_report_actual_outbounds_rules_and_close_independently() {
    let _gate = LIFECYCLE_GATE.lock().await;
    tokio::time::timeout(Duration::from_secs(10), async {
        let direct = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let direct_address = direct.local_addr().unwrap();
        let remote = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let remote_address = remote.local_addr().unwrap();
        let direct_task = tokio::spawn(async move {
            let (mut stream, _) = direct.accept().await.unwrap();
            let (mut read, mut write) = stream.split();
            tokio::io::copy(&mut read, &mut write).await.unwrap();
        });
        let proxy_task = tokio::spawn(async move {
            let (mut stream, _) = remote.accept().await.unwrap();
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                assert!(header.len() < 8192);
                header.push(stream.read_u8().await.unwrap());
            }
            assert!(header.starts_with(b"CONNECT 127.0.0.1:18080 HTTP/1.1\r\n"));
            stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await.unwrap();
            let (mut read, mut write) = stream.split();
            tokio::io::copy(&mut read, &mut write).await.unwrap();
        });
        let inbound = vacant_address();
        let document = serde_json::json!({
            "inbounds":[{"type":"socks","tag":"socks-in","listen":"127.0.0.1","listen_port":inbound.port()}],
            "outbounds":[
                {"type":"http","tag":"proxy","server":"127.0.0.1","server_port":remote_address.port()},
                {"type":"direct","tag":"direct"}
            ],
            "route":{"final":"proxy","rules":[{"port":[direct_address.port()],"outbound":"direct"}]}
        });
        let config = aerobox_config::normalize_json(&document.to_string(), None).unwrap();
        let core = EmbeddedCore::start_json(&config, None).await.unwrap();
        let mut direct = socks(inbound, direct_address).await;
        echo(&mut direct).await;
        let mut proxy = socks(inbound, "127.0.0.1:18080".parse().unwrap()).await;
        echo(&mut proxy).await;
        let snapshot = core.connections().await.unwrap();
        let rows = snapshot["connections"].as_array().unwrap();
        assert_eq!(rows.len(), 2);
        let proxy_row = rows.iter().find(|row| row["metadata"]["destinationPort"] == "18080").unwrap();
        let direct_row = rows.iter().find(|row| row["id"] != proxy_row["id"]).unwrap();
        assert_eq!(proxy_row["chains"], serde_json::json!(["proxy"]));
        assert_eq!(direct_row["chains"], serde_json::json!(["__aerobox_direct"]));
        assert!(proxy_row["rulePayload"].as_str().unwrap().contains("any_destination"));
        let rule = direct_row["rulePayload"].as_str().unwrap();
        assert!(rule.contains("destination_port") && rule.contains(&direct_address.port().to_string()), "{rule}");
        assert_eq!(rows[0]["id"], proxy_row["id"], "newest connection first");
        let totals = core.stats().await.unwrap();
        assert_eq!(totals.active_connections, 2);
        assert!(totals.upload_total >= 30 && totals.download_total >= 30);
        core.close_connection(proxy_row["id"].as_str().unwrap().to_owned()).await.unwrap();
        closed(&mut proxy).await;
        echo(&mut direct).await;
        core.shutdown().await.unwrap();
        closed(&mut direct).await;
        direct_task.await.unwrap();
        proxy_task.await.unwrap();
    }).await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn lifecycle_reload_recovery_and_shutdown_release_connections() {
    let _gate = LIFECYCLE_GATE.lock().await;
    tokio::time::timeout(Duration::from_secs(30), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                tasks.spawn(async move { let (mut reader, mut writer) = stream.split(); let _ = tokio::io::copy(&mut reader, &mut writer).await; });
            }
        });
        let proxy = vacant_address();
        let platform = Arc::new(TestPlatform(AtomicUsize::new(0)));
        EmbeddedCore::check_json(&config(proxy)).await.unwrap();
        let core = EmbeddedCore::start_json(&config(proxy), Some(platform.clone())).await.unwrap();
        assert!(core.is_running());
        assert!(matches!(EmbeddedCore::start_json(&config(vacant_address()), None).await, Err(error) if error.kind() == io::ErrorKind::AlreadyExists));
        let mut stream = socks(proxy, target).await;
        echo(&mut stream).await;
        let stats = core.stats().await.unwrap();
        assert_eq!(stats.active_connections, 1);
        assert!(stats.upload_total >= 15 && stats.download_total >= 15);
        assert!(platform.0.load(Ordering::Relaxed) > 0);
        let snapshot = core.connections().await.unwrap();
        let id = snapshot["connections"][0]["id"].as_str().unwrap().to_owned();
        core.close_connection(id).await.unwrap();
        closed(&mut stream).await;

        let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
        assert!(core.reload_json(&config(occupied.local_addr().unwrap())).await.is_err());
        let mut old = socks(proxy, target).await;
        echo(&mut old).await;
        let replacement = vacant_address();
        core.reload_json(&config(replacement)).await.unwrap();
        // Graceful config reload retains established streams; network reset
        // cancels both current-generation and draining connections.
        echo(&mut old).await;
        let mut current = socks(replacement, target).await;
        echo(&mut current).await;
        core.network_changed().await.unwrap();
        closed(&mut old).await;
        closed(&mut current).await;
        let mut final_stream = socks(replacement, target).await;
        echo(&mut final_stream).await;
        core.shutdown().await.unwrap();
        assert!(!core.is_running());
        closed(&mut final_stream).await;
        assert!(TcpListener::bind(replacement).await.is_ok());
        let second = EmbeddedCore::start_json(&config(proxy), None).await.unwrap();
        second.shutdown().await.unwrap();
        echo_task.abort();
        let _ = echo_task.await;
    }).await.expect("embedded lifecycle timed out");
}

#[test]
fn synchronous_facade_validates_without_starting_service() {
    let runtime = aerobox::AndroidRuntime::new().unwrap();
    assert!(runtime.check("{}").is_err());
    assert!(runtime.check(&config("127.0.0.1:19080".parse().unwrap())).is_err());
    runtime
        .check(&app_config("127.0.0.1:19080".parse().unwrap()))
        .unwrap();
    assert!(!runtime.is_running());
    assert!(runtime.stats().is_err());
    runtime.stop().unwrap();
}

#[test]
fn synchronous_android_lifecycle_fits_a_one_megabyte_caller_stack() {
    const CHILD: &str = "AEROBOX_ANDROID_SMALL_STACK_TEST";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "synchronous_android_lifecycle_fits_a_one_megabyte_caller_stack",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "small-stack Android lifecycle failed: {}\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    std::thread::Builder::new()
        .stack_size(1024 * 1024)
        .spawn(|| {
            eprintln!("small-stack lifecycle: construct");
            let runtime = aerobox::AndroidRuntime::new().unwrap();
            let source = app_config(vacant_address());
            eprintln!("small-stack lifecycle: check");
            runtime.check(&source).unwrap();
            eprintln!("small-stack lifecycle: start");
            runtime
                .start(
                    &source,
                    None,
                    Some(Arc::new(TestPlatform(AtomicUsize::new(0)))),
                )
                .unwrap();
            assert!(runtime.is_running());
            eprintln!("small-stack lifecycle: network_changed");
            runtime.network_changed().unwrap();
            eprintln!("small-stack lifecycle: stop");
            runtime.stop().unwrap();
            assert!(!runtime.is_running());
        })
        .unwrap()
        .join()
        .unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn a_pending_url_test_does_not_block_stats_or_shutdown() {
    let _gate = LIFECYCLE_GATE.lock().await;
    tokio::time::timeout(Duration::from_secs(10), async {
        let stalled_proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let json = serde_json::json!([
            {"client_group":"probe", "type":"selector", "client_chains":[{
                "name":"stall", "address":stalled_proxy.local_addr().unwrap().to_string(),
                "protocol":{"type":"socks"}
            }]},
            {"address":vacant_address().to_string(), "protocol":{"type":"socks"}}
        ])
        .to_string();
        let core = Arc::new(EmbeddedCore::start_json(&json, None).await.unwrap());
        let probe_core = core.clone();
        let probe = tokio::spawn(async move {
            probe_core
                .urltest("stall".into(), "http://192.0.2.1/".into(), 30_000)
                .await
        });
        let (mut stream, _) = stalled_proxy.accept().await.unwrap();
        // Wait for the actual SOCKS handshake to enter I/O, then keep it stalled.
        let mut byte = [0];
        stream.read_exact(&mut byte).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), core.stats())
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), core.shutdown())
            .await
            .unwrap()
            .unwrap();
        assert!(probe.await.unwrap().is_err());
        assert!(!core.is_running());
    })
    .await
    .expect("pending probe prevented shutdown");
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn failed_tun_start_keeps_the_callers_descriptor_open() {
    let _gate = LIFECYCLE_GATE.lock().await;
    use std::os::fd::{AsFd, AsRawFd};
    let file = std::fs::File::open("/dev/null").unwrap();
    let json = serde_json::json!([{ "device_fd": file.as_raw_fd(), "dns": {"servers": "udp://127.0.0.1:9"} }]).to_string();
    // A regular character device cannot start a TUN stack. Even this failure
    // must close only the runtime-owned duplicate.
    let result = EmbeddedCore::start_json(&json, None).await;
    if let Ok(core) = result {
        core.shutdown().await.unwrap();
    }
    assert!(file.as_fd().try_clone_to_owned().is_ok());
}

#[test]
fn application_check_reports_deferred_rules_and_tun_without_opening_them() {
    let runtime = aerobox::AndroidRuntime::new().unwrap();
    let config = serde_json::json!({
        "outbounds":[{"type":"direct","tag":"direct"}],
        "inbounds":[{"type":"tun","tag":"tun-in","address":["172.19.0.1/28"],"stack":"mixed","mtu":9000}],
        "dns":{"servers":[{"type":"udp","tag":"dns-direct","server":"192.0.2.53"}],"final":"dns-direct"},
        "route":{"final":"direct","rule_set":[{"type":"remote","tag":"cn","format":"binary","url":"https://rules.invalid/cn.srs","download_detour":"direct"}],"rules":[{"rule_set":["cn"],"outbound":"direct"}]}
    });
    let report = runtime.check_details(&config.to_string()).unwrap();
    assert_eq!(report["requiresTunDescriptor"], true);
    assert_eq!(report["deferredRemoteRules"].as_array().unwrap().len(), 1);
    assert!(!runtime.is_running());
    let mut invalid = config.clone();
    invalid["outbounds"][0]["unknown_option"] = true.into();
    assert!(runtime.check_details(&invalid.to_string()).is_err());
    invalid = config;
    invalid["route"]["rules"][0]["outbound"] = "missing".into();
    assert!(runtime.check_details(&invalid.to_string()).is_err());
}

#[test]
fn stop_cancels_first_download_while_start_is_blocked() {
    let _gate = LIFECYCLE_GATE.blocking_lock();
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (ready, started) = std::sync::mpsc::channel();
    let fixture = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut buffer = [0; 4096];
        let _ = socket.read(&mut buffer).unwrap();
        ready.send(()).unwrap();
        // Keep the HTTP response pending until cancellation closes the socket.
        assert_eq!(socket.read(&mut buffer).unwrap(), 0);
        let _ = socket.write_all(b"closed");
    });
    let runtime = aerobox::AndroidRuntime::new().unwrap();
    let proxy = vacant_address();
    let document = serde_json::json!({
        "outbounds":[{"type":"direct","tag":"direct"}],
        "inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":proxy.port()}],
        "route":{"final":"direct","rule_set":[{"type":"remote","tag":"remote","url":format!("http://{address}/rules.json"),"format":"source","download_detour":"direct"}],"rules":[{"rule_set":["remote"],"action":"reject"}]}
    }).to_string();
    std::thread::scope(|threads| {
        let startup = threads.spawn(|| runtime.start(&document, None, None));
        started.recv_timeout(Duration::from_secs(5)).unwrap();
        let stopped = std::time::Instant::now();
        runtime.stop().unwrap();
        assert!(stopped.elapsed() < Duration::from_secs(3));
        assert!(startup.join().unwrap().is_err());
    });
    fixture.join().unwrap();
    assert!(!runtime.is_running());
    runtime
        .start(&app_config(vacant_address()), None, None)
        .unwrap();
    runtime.stop().unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn temporary_outbound_probe_uses_its_document_during_active_service() {
    let _gate = LIFECYCLE_GATE.lock().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let fixture = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut greeting = [0; 3];
        stream.read_exact(&mut greeting).await.unwrap();
        stream.write_all(&[5, 0]).await.unwrap();
        let mut request = [0; 10];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(&request[4..8], &[192, 0, 2, 22]);
        stream
            .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            header.push(stream.read_u8().await.unwrap());
        }
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
    });
    let core = EmbeddedCore::start_json(&config(vacant_address()), None)
        .await
        .unwrap();
    let temporary = serde_json::from_value(serde_json::json!([
        {"client_group":"temporary","client_chain":{"address":address.to_string(),"protocol":{"type":"socks"}}}
    ])).unwrap();
    let delay = core
        .probe_document(
            temporary,
            "temporary".into(),
            "http://192.0.2.22/".into(),
            3000,
        )
        .await
        .unwrap();
    assert!(delay <= 3000);
    assert!(core.is_running());
    fixture.await.unwrap();
    core.shutdown().await.unwrap();
}

#[test]
fn app_document_can_probe_proxy_and_direct_with_and_without_active_service() {
    use std::io::{Read, Write};
    let _gate = LIFECYCLE_GATE.blocking_lock();
    let proxy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_address = proxy.local_addr().unwrap();
    // Direct probes reject literal loopback destinations. Discover this host's
    // routed local address without sending a datagram, then serve the fixture
    // there; all HTTP requests still terminate on this test process.
    let route = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    route.connect("192.0.2.1:9").unwrap();
    let direct = std::net::TcpListener::bind((route.local_addr().unwrap().ip(), 0)).unwrap();
    let direct_address = direct.local_addr().unwrap();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let calls = Arc::new(AtomicUsize::new(0));
    let mut fixtures = Vec::new();
    for (listener, is_proxy) in [(proxy, true), (direct, false)] {
        listener.set_nonblocking(true).unwrap();
        let stop = stop.clone();
        let calls = calls.clone();
        fixtures.push(std::thread::spawn(move || {
            let header = |stream: &mut std::net::TcpStream| {
                let mut bytes = Vec::new();
                while !bytes.ends_with(b"\r\n\r\n") {
                    assert!(bytes.len() < 8192);
                    let mut byte = [0];
                    stream.read_exact(&mut byte).unwrap();
                    bytes.push(byte[0]);
                }
                bytes
            };
            while !stop.load(Ordering::SeqCst) {
                let (mut stream, _) = match listener.accept() {
                    Ok(accepted) => accepted,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(error) => panic!("fixture accept: {error}"),
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                if is_proxy {
                    assert!(
                        header(&mut stream).starts_with(b"CONNECT 192.0.2.22:18080 HTTP/1.1\r\n")
                    );
                    stream
                        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                        .unwrap();
                }
                let request = header(&mut stream);
                assert!(
                    request.starts_with(b"HEAD / HTTP/1.1\r\n"),
                    "unexpected probe request: {}",
                    String::from_utf8_lossy(&request)
                );
                calls.fetch_add(1, Ordering::SeqCst);
                stream
                    .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                    .unwrap();
            }
        }));
    }
    let runtime = aerobox::AndroidRuntime::new().unwrap();
    // Match ConfigGenerator.generateUrlTestConfig's Android document, including
    // its proxy/direct tags. Handwritten native groups miss adapter collisions.
    let document = serde_json::json!({
        "log":{"level":"error","timestamp":false},
        "dns":{"servers":[
            {"type":"udp","tag":"dns-direct","server":"127.0.0.1","server_port":9,
             "domain_resolver":{"server":"dns-local","strategy":"prefer_ipv4"}},
            {"type":"local","tag":"dns-local"}
        ],"final":"dns-direct","strategy":"prefer_ipv4"},
        "inbounds":[],
        "outbounds":[
            {"type":"http","tag":"proxy","server":"127.0.0.1","server_port":proxy_address.port()},
            {"type":"direct","tag":"direct"}
        ],
        "route":{"auto_detect_interface":true,"final":"proxy"}
    })
    .to_string();
    let mut policy: serde_json::Value = serde_json::from_str(&document).unwrap();
    for outbound in policy["outbounds"].as_array_mut().unwrap() {
        outbound["network_strategy"] = "fallback".into();
        outbound["network_type"] = serde_json::json!(["wifi"]);
        outbound["fallback_network_type"] = serde_json::json!(["cellular"]);
        outbound["fallback_delay"] = "1ms".into();
    }
    let policy = policy.to_string();
    let result = (|| -> io::Result<()> {
        runtime.check(&document)?;
        // Editor validation is offline, even when network policies are present.
        runtime.check(&policy)?;
        for document in [&document, &policy] {
            for running in [false, true] {
                let platform = Arc::new(MultiNetworkPlatform::new());
                if running {
                    runtime.start(&app_config(vacant_address()), None, Some(platform.clone()))?;
                }
                runtime.urltest_config(
                    document,
                    "proxy",
                    "http://192.0.2.22:18080/",
                    3000,
                    Some(platform.clone()),
                )?;
                runtime.urltest_config(
                    document,
                    "direct",
                    &format!("http://{direct_address}/"),
                    3000,
                    Some(platform.clone()),
                )?;
                if document == &policy {
                    // This fixture rejects the Wi-Fi bind, so each successful
                    // HEAD must use the requested cellular fallback.
                    assert_eq!(
                        *platform.bindings.lock().unwrap(),
                        [(1, 1), (1, 2), (1, 1), (1, 2)]
                    );
                }
                assert_eq!(runtime.is_running(), running);
                if running {
                    runtime.stop()?;
                }
            }
        }
        Ok(())
    })();
    runtime.stop().unwrap();
    stop.store(true, Ordering::SeqCst);
    for fixture in fixtures {
        fixture.join().unwrap();
    }
    result.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 8);
}

#[test]
fn concurrent_standalone_probes_share_context_and_start_cancels_them() {
    use std::io::Read;
    let _gate = LIFECYCLE_GATE.blocking_lock();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (ready, received) = std::sync::mpsc::channel();
    let fixture = std::thread::spawn(move || {
        let mut sockets = Vec::new();
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).unwrap();
            ready.send(()).unwrap();
            sockets.push(stream);
        }
        for mut stream in sockets {
            assert_eq!(stream.read(&mut [0; 1]).unwrap(), 0);
        }
    });
    let runtime = aerobox::AndroidRuntime::new().unwrap();
    let document = serde_json::json!({
        "outbounds":[{"type":"socks","tag":"probe","server":"127.0.0.1","server_port":address.port()}],
        "route":{"final":"probe"},"inbounds":[]
    }).to_string();
    std::thread::scope(|threads| {
        let first = threads.spawn(|| {
            runtime.urltest_config(&document, "probe", "http://192.0.2.22/", 30000, None)
        });
        let second = threads.spawn(|| {
            runtime.urltest_config(&document, "probe", "http://192.0.2.22/", 30000, None)
        });
        received.recv_timeout(Duration::from_secs(5)).unwrap();
        received.recv_timeout(Duration::from_secs(5)).unwrap();
        let began = std::time::Instant::now();
        runtime
            .start(&app_config(vacant_address()), None, None)
            .unwrap();
        assert!(began.elapsed() < Duration::from_secs(3));
        assert!(first.join().unwrap().is_err());
        assert!(second.join().unwrap().is_err());
        let stop1 = threads.spawn(|| runtime.stop());
        let stop2 = threads.spawn(|| runtime.stop());
        stop1.join().unwrap().unwrap();
        stop2.join().unwrap().unwrap();
    });
    fixture.join().unwrap();
    assert!(!runtime.is_running());
    runtime
        .start(&app_config(vacant_address()), None, None)
        .unwrap();
    runtime.stop().unwrap();
}
