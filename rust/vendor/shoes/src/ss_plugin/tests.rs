use super::{Config, ObfsMode, simple_obfs::Stream};
use crate::async_stream::{AsyncPing, AsyncStream};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

/// Forces a genuine Pending between fragments, to cover state retained across
/// poll calls (including one-byte headers and partial record payloads).
struct Fragmented {
    bytes: std::io::Cursor<Vec<u8>>,
    fragment: usize,
    pending: bool,
}
impl AsyncRead for Fragmented {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.pending {
            self.pending = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        self.pending = true;
        let pos = self.bytes.position() as usize;
        let len = self
            .fragment
            .min(out.remaining())
            .min(self.bytes.get_ref().len() - pos);
        out.put_slice(&self.bytes.get_ref()[pos..pos + len]);
        self.bytes.set_position((pos + len) as u64);
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for Fragmented {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(data.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
impl AsyncPing for Fragmented {
    fn supports_ping(&self) -> bool {
        false
    }
    fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}
impl AsyncStream for Fragmented {}
fn from_wire(mode: ObfsMode, data: Vec<u8>, fragment: usize) -> Stream {
    Stream::new(
        Box::new(Fragmented {
            bytes: std::io::Cursor::new(data),
            fragment,
            pending: false,
        }),
        mode,
        "cdn.example".into(),
        443,
    )
}
fn response_tls(payload: &[u8]) -> Vec<u8> {
    let mut response = vec![22, 3, 1, 0, 91];
    response.extend_from_slice(&[0; 91]);
    response.extend_from_slice(&[20, 3, 3, 0, 1, 1, 22, 3, 3]);
    response.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    response.extend_from_slice(payload);
    response
}

#[tokio::test]
async fn fragmented_and_coalesced_response_headers_preserve_payloads() {
    for fragment in [1, 2, 4, 5, 7, 91, 102, 105, 4096] {
        for mode in [ObfsMode::Http, ObfsMode::Tls] {
            let mut wire = if mode == ObfsMode::Http {
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\nfirst".to_vec()
            } else {
                response_tls(b"first")
            };
            if mode == ObfsMode::Tls {
                wire.extend_from_slice(&[23, 3, 3, 0, 6]);
            }
            wire.extend_from_slice(b"second");
            let mut stream = from_wire(mode, wire, fragment);
            let mut result = Vec::new();
            stream.read_to_end(&mut result).await.unwrap();
            assert_eq!(result, b"firstsecond", "{mode:?}/{fragment}");
        }
    }
}

#[tokio::test]
async fn truncated_headers_and_payloads_fail_without_clean_eof() {
    let full = response_tls(b"first");
    for len in 0..full.len() {
        let mut stream = from_wire(ObfsMode::Tls, full[..len].to_vec(), 3);
        let err = stream.read_to_end(&mut Vec::new()).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof, "cut={len}");
    }
    let mut wire = full;
    wire.extend_from_slice(&[23, 3, 3, 0, 4, 1, 2, 3, 4]);
    for len in 1..9 {
        let mut stream = from_wire(ObfsMode::Tls, wire[..wire.len() - len].to_vec(), 7);
        assert_eq!(
            stream
                .read_to_end(&mut Vec::new())
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
    for wire in [
        b"HTTP/1.1 101 Switching Protocols\r\n".to_vec(),
        vec![b'X'; 16385],
        b"HTTP/1.1 403 Forbidden\r\n\r\n".to_vec(),
    ] {
        assert!(
            from_wire(ObfsMode::Http, wire, 13)
                .read_to_end(&mut Vec::new())
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn empty_tls_records_are_skipped_and_invalid_records_fail() {
    let mut wire = response_tls(b"");
    for _ in 0..400 {
        wire.extend_from_slice(&[23, 3, 3, 0, 0]);
    }
    wire.extend_from_slice(&[23, 3, 3, 0, 1, 42]);
    let mut output = Vec::new();
    from_wire(ObfsMode::Tls, wire, 5000)
        .read_to_end(&mut output)
        .await
        .unwrap();
    assert_eq!(output, [42]);
    for header in [[22, 3, 3, 0, 1], [23, 3, 1, 0, 1], [23, 3, 3, 64, 1]] {
        let mut wire = response_tls(b"hi");
        wire.extend_from_slice(&header);
        assert!(
            from_wire(ObfsMode::Tls, wire, 13)
                .read_to_end(&mut Vec::new())
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn writes_survive_backpressure_and_shutdown_drains_the_last_frame() {
    for mode in [ObfsMode::Http, ObfsMode::Tls] {
        let (local, mut remote) = tokio::io::duplex(11);
        let mut stream = Stream::new(Box::new(local), mode, "cdn.example".into(), 8443);
        let data: Vec<u8> = (0..70_000).map(|i| (i % 251) as u8).collect();
        let writer = async {
            assert_eq!(stream.write(&[]).await.unwrap(), 0);
            stream.write_all(&data).await.unwrap();
            stream.shutdown().await.unwrap();
            assert_eq!(
                stream.write(b"late").await.unwrap_err().kind(),
                io::ErrorKind::BrokenPipe
            );
        };
        let mut wire = Vec::new();
        let ((), read) = tokio::join!(writer, remote.read_to_end(&mut wire));
        read.unwrap();
        let mut payload = Vec::new();
        if mode == ObfsMode::Http {
            let head_end = wire.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
            let head = std::str::from_utf8(&wire[..head_end]).unwrap();
            assert!(head.starts_with("GET / HTTP/1.1\r\n"));
            assert!(head.contains("Host: cdn.example:8443\r\n"));
            assert!(head.contains("Content-Length: 16384\r\n"));
            payload.extend_from_slice(&wire[head_end..]);
        } else {
            assert_eq!(&wire[..3], &[22, 3, 1]);
            let hello_len = u16::from_be_bytes([wire[3], wire[4]]) as usize + 5;
            assert_eq!(hello_len, 217 + 16_384 + "cdn.example".len());
            // Parse ClientHello vectors independently of the encoder.
            let mut at = 43;
            at += 1 + wire[at] as usize;
            at += 2 + u16::from_be_bytes([wire[at], wire[at + 1]]) as usize;
            at += 1 + wire[at] as usize;
            assert_eq!(
                u16::from_be_bytes([wire[at], wire[at + 1]]) as usize,
                hello_len - at - 2
            );
            at += 2;
            assert_eq!(&wire[at..at + 2], &[0, 35]);
            let ticket_len = u16::from_be_bytes([wire[at + 2], wire[at + 3]]) as usize;
            payload.extend_from_slice(&wire[at + 4..at + 4 + ticket_len]);
            at = hello_len;
            while at < wire.len() {
                assert_eq!(&wire[at..at + 3], &[23, 3, 3]);
                let count = u16::from_be_bytes([wire[at + 3], wire[at + 4]]) as usize;
                assert!(count <= 16384);
                payload.extend_from_slice(&wire[at + 5..at + 5 + count]);
                at += 5 + count;
            }
        }
        assert_eq!(payload, data);
    }
}

#[test]
fn host_validation_prevents_header_injection_and_length_wrap() {
    for host in [
        "cdn.example\r\nInjected: true".to_owned(),
        "x".repeat(256),
        "a b".into(),
    ] {
        assert!(
            Config::ObfsLocal {
                mode: ObfsMode::Tls,
                host
            }
            .validate()
            .is_err()
        );
    }
    for host in ["", "cdn.example", "[::1]"] {
        Config::ObfsLocal {
            mode: ObfsMode::Http,
            host: host.into(),
        }
        .validate()
        .unwrap();
    }
}

#[tokio::test]
#[ignore = "requires AEROBOX_OBFS_PEER built from tests/fixtures/obfs-peer"]
async fn simple_obfs_and_shadowsocks_with_independent_go_peers() {
    use crate::{
        address::{NetLocation, ResolvedLocation},
        config::{ResolvedClientProxyConfig, ShadowsocksConfig},
        resolver::NativeResolver,
        tcp::tcp_client_handler_factory::create_tcp_client_handler,
    };
    use base64::{Engine, engine::general_purpose::STANDARD};
    use std::{process::Stdio, sync::Arc, time::Duration};
    use tokio::io::{AsyncBufReadExt, BufReader};
    let executable = std::env::var_os("AEROBOX_OBFS_PEER").expect("set AEROBOX_OBFS_PEER");
    for mode in [ObfsMode::Http, ObfsMode::Tls] {
        for method in [
            "",
            "aes-128-gcm",
            "aes-256-gcm",
            "chacha20-ietf-poly1305",
            "2022-blake3-aes-128-gcm",
            "2022-blake3-aes-256-gcm",
            "2022-blake3-chacha20-poly1305",
        ] {
            let mut command = tokio::process::Command::new(&executable);
            command.arg(if mode == ObfsMode::Http {
                "http"
            } else {
                "tls"
            });
            if !method.is_empty() {
                command.arg(method);
            }
            let mut child = command
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .kill_on_drop(true)
                .spawn()
                .unwrap();
            let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
            let port: u16 = tokio::time::timeout(Duration::from_secs(5), lines.next_line())
                .await
                .unwrap()
                .unwrap()
                .unwrap()
                .parse()
                .unwrap();
            tokio::time::timeout(Duration::from_secs(25), async {
                let socket = tokio::net::TcpStream::connect(("127.0.0.1", port))
                    .await
                    .unwrap();
                let mut stream: Box<dyn AsyncStream> = if method.is_empty() {
                    Box::new(Stream::new(
                        Box::new(socket),
                        mode,
                        "cdn.example".into(),
                        port,
                    ))
                } else {
                    let password = if method.starts_with("2022-") {
                        STANDARD.encode(vec![
                            42;
                            if method == "2022-blake3-aes-128-gcm" {
                                16
                            } else {
                                32
                            }
                        ])
                    } else {
                        "aerobox-reference".into()
                    };
                    let config = ResolvedClientProxyConfig::Shadowsocks {
                        config: ShadowsocksConfig::from_client_fields(method, &password).unwrap(),
                        udp_enabled: true,
                        plugin: Some(Config::ObfsLocal {
                            mode,
                            host: "cdn.example".into(),
                        }),
                    };
                    let proxy = NetLocation::from_str(&format!("127.0.0.1:{port}"), None).unwrap();
                    let handler =
                        create_tcp_client_handler(config, &proxy, Arc::new(NativeResolver::new()))
                            .unwrap();
                    handler
                        .setup_client_tcp_stream(
                            Box::new(socket),
                            ResolvedLocation::new(
                                NetLocation::from_str("destination.example:443", None).unwrap(),
                            ),
                        )
                        .await
                        .unwrap()
                        .client_stream
                };
                // Flush the first transport payload separately. GOST's HTTP
                // reader is allowed to consume a complete request body here.
                stream.write_all(b"hello").await.unwrap();
                stream.flush().await.unwrap();
                let mut hello = [0; 5];
                stream
                    .read_exact(&mut hello)
                    .await
                    .unwrap_or_else(|err| panic!("{mode:?}/{method}: {err}"));
                assert_eq!(&hello, b"hello");
                let data: Vec<u8> = (0..524_288).map(|i| (i % 251) as u8).collect();
                let (mut reader, mut writer) = tokio::io::split(stream);
                let mut output = vec![0; data.len()];
                let (written, read) = tokio::join!(
                    async {
                        writer.write_all(&data).await?;
                        writer.flush().await
                    },
                    reader.read_exact(&mut output)
                );
                written.unwrap();
                read.unwrap();
                assert_eq!(data, output, "{mode:?}/{method}");
                writer.shutdown().await.unwrap();
            })
            .await
            .unwrap_or_else(|err| panic!("{mode:?}/{method}: {err}"));
            child.kill().await.unwrap();
            child.wait().await.unwrap();
        }
    }
}

#[tokio::test]
async fn plugin_mux_fragmentation_end_and_errors_preserve_stream_semantics() {
    let frames = [
        0, 4, 0, 0, 4, 0, 0, 4, 0, 0, 2, 1, 0, 3, 1, 2, 3, 0, 4, 0, 0, 3, 0,
    ];
    for fragment in [1, 3, 16, 128] {
        let inner = Fragmented {
            bytes: std::io::Cursor::new(frames.to_vec()),
            fragment,
            pending: false,
        };
        let mut stream = super::xray_mux::Stream::new(Box::new(inner));
        let mut data = Vec::new();
        stream.read_to_end(&mut data).await.unwrap();
        assert_eq!(data, [1, 2, 3]);
    }
    for wire in [
        vec![0, 4, 0, 0, 3, 2],
        vec![0, 4, 0, 1, 2, 1],
        vec![0, 4, 0, 0, 2, 1, 0],
        vec![0, 4, 0, 0, 2, 1, 0, 3, 1, 2],
        vec![2, 1],
    ] {
        let mut stream = super::xray_mux::Stream::new(Box::new(Fragmented {
            bytes: std::io::Cursor::new(wire),
            fragment: 1,
            pending: false,
        }));
        assert!(stream.read_to_end(&mut Vec::new()).await.is_err());
    }
    let (local, mut remote) = tokio::io::duplex(7);
    let mut stream = super::xray_mux::Stream::new(Box::new(local));
    let data = vec![42; 65_536];
    let mut wire = Vec::new();
    let ((), read) = tokio::join!(
        async {
            stream.write_all(&data).await.unwrap();
            stream.shutdown().await.unwrap();
        },
        remote.read_to_end(&mut wire)
    );
    read.unwrap();
    let mut bytes = bytes::BytesMut::from(wire.as_slice());
    let mut output = Vec::new();
    let mut frames = 0;
    while !bytes.is_empty() {
        let frame = crate::xudp::frame::FrameMetadata::decode(&mut bytes)
            .unwrap()
            .unwrap();
        assert_eq!(frame.session_id, 0);
        if frames == 0 {
            assert_eq!(frame.status, crate::xudp::frame::SessionStatus::New);
            assert_eq!(frame.target.unwrap().to_string(), "v1.mux.cool:666");
            assert_eq!(frame.network, Some(crate::xudp::frame::TargetNetwork::Tcp));
        }
        if frame.status == crate::xudp::frame::SessionStatus::End {
            assert!(bytes.is_empty());
            break;
        }
        use bytes::Buf;
        let size = bytes.get_u16() as usize;
        assert!(size <= 8192 - 666);
        output.extend_from_slice(&bytes.split_to(size));
        frames += 1;
    }
    assert!(frames > 1);
    assert_eq!(output, data);
}

#[tokio::test]
#[ignore = "requires AEROBOX_OBFS_PEER built from tests/fixtures/obfs-peer"]
async fn v2ray_plugin_websocket_tls_and_mux_with_independent_go_peers() {
    use crate::{
        address::{NetLocation, ResolvedLocation},
        config::{ResolvedClientProxyConfig, ShadowsocksConfig},
        resolver::NativeResolver,
        tcp::tcp_client_handler_factory::create_tcp_client_handler,
    };
    use base64::{Engine, engine::general_purpose::STANDARD};
    use std::{process::Stdio, sync::Arc, time::Duration};
    use tokio::io::{AsyncBufReadExt, BufReader};
    for mux in [0, 1, 8] {
        for tls in [false, true] {
            for method in ["aes-128-gcm", "2022-blake3-chacha20-poly1305"] {
                let certificates = tempfile::tempdir().unwrap();
                let mut command = tokio::process::Command::new(
                    std::env::var_os("AEROBOX_OBFS_PEER").expect("set AEROBOX_OBFS_PEER"),
                );
                command
                    .arg(if mux > 0 { "wsmux" } else { "ws" })
                    .arg(method);
                if tls {
                    command
                        .env("AEROBOX_PEER_TLS", "1")
                        .env("AEROBOX_PEER_CERT_DIR", certificates.path());
                }
                let mut child = command
                    .stdout(Stdio::piped())
                    .stderr(Stdio::inherit())
                    .kill_on_drop(true)
                    .spawn()
                    .unwrap();
                let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
                let port: u16 = tokio::time::timeout(Duration::from_secs(5), lines.next_line())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap()
                    .parse()
                    .unwrap();
                let roots = if tls {
                    vec![std::fs::read_to_string(certificates.path().join("ca.pem")).unwrap()]
                } else {
                    vec![]
                };
                let proxy = NetLocation::from_str(&format!("127.0.0.1:{port}"), None).unwrap();
                let config = |sni: &str| ResolvedClientProxyConfig::Shadowsocks {
                    config: ShadowsocksConfig::from_client_fields(
                        method,
                        &if method.starts_with("2022") {
                            STANDARD.encode([42; 32])
                        } else {
                            "aerobox-reference".into()
                        },
                    )
                    .unwrap(),
                    udp_enabled: true,
                    plugin: Some(Config::V2rayPlugin {
                        mode: super::V2rayMode::Websocket,
                        host: "localhost".into(),
                        path: "/tunnel".into(),
                        mux,
                        tls,
                        sni_hostname: Some(sni.into()),
                        root_certificates: roots.clone(),
                    }),
                };
                tokio::time::timeout(Duration::from_secs(20), async {
                    let handler = create_tcp_client_handler(
                        config("localhost"),
                        &proxy,
                        Arc::new(NativeResolver::new()),
                    )
                    .unwrap();
                    let socket = tokio::net::TcpStream::connect(("127.0.0.1", port))
                        .await
                        .unwrap();
                    let target = || {
                        ResolvedLocation::new(
                            NetLocation::from_str("destination.example:443", None).unwrap(),
                        )
                    };
                    let stream = handler
                        .setup_client_tcp_stream(Box::new(socket), target())
                        .await
                        .unwrap()
                        .client_stream;
                    let (mut reader, mut writer) = tokio::io::split(stream);
                    let data: Vec<u8> = (0..524_288).map(|i| (i % 251) as u8).collect();
                    let mut output = vec![0; data.len()];
                    let (sent, received) = tokio::join!(
                        async {
                            writer.write_all(&data).await?;
                            writer.flush().await
                        },
                        reader.read_exact(&mut output)
                    );
                    sent.unwrap();
                    received.unwrap();
                    assert_eq!(output, data, "{method}/mux={mux}/tls={tls}");
                    writer.shutdown().await.unwrap();
                    if tls {
                        let handler = create_tcp_client_handler(
                            config("wrong.example"),
                            &proxy,
                            Arc::new(NativeResolver::new()),
                        )
                        .unwrap();
                        let socket = tokio::net::TcpStream::connect(("127.0.0.1", port))
                            .await
                            .unwrap();
                        assert!(
                            handler
                                .setup_client_tcp_stream(Box::new(socket), target())
                                .await
                                .is_err(),
                            "plugin TLS must verify SNI"
                        );
                    }
                })
                .await
                .unwrap_or_else(|err| panic!("{method}/mux={mux}/tls={tls}: {err}"));
                child.kill().await.unwrap();
                child.wait().await.unwrap();
            }
        }
    }
}
