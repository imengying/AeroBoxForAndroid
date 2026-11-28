use super::VmessTcpClientHandler;
use crate::address::{NetLocation, ResolvedLocation};
use crate::async_stream::{AsyncFlushMessage, AsyncReadMessage, AsyncWriteMessage};
use crate::tcp::tcp_handler::TcpClientHandler;
use futures::future::poll_fn;
use std::pin::Pin;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, ReadBuf};

#[tokio::test]
#[ignore = "requires AEROBOX_VMESS_PEER with configurable test user IDs"]
async fn arbitrary_user_ids_authenticate_with_independent_go_peer() {
    for kind in ["vmess", "vless"] {
        for user in [
            "",
            "test-user",
            "用户",
            "550e8400-e29b-11d4-a716-446655440000",
            "00000000-0000-0000-0000-000000000000",
        ] {
            for alter in [0, 1] {
                if kind == "vless" && alter != 0 {
                    continue;
                }
                tokio::time::timeout(Duration::from_secs(15), async {
                    let mut child = tokio::process::Command::new(
                        std::env::var_os("AEROBOX_VMESS_PEER").unwrap(),
                    )
                    .args([kind, &alter.to_string()])
                    .env("AEROBOX_INTEROP_USER_ID", user)
                    .stdout(Stdio::piped())
                    .stderr(Stdio::inherit())
                    .kill_on_drop(true)
                    .spawn()
                    .unwrap();
                    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
                    let port = lines
                        .next_line()
                        .await
                        .unwrap()
                        .unwrap()
                        .parse::<u16>()
                        .unwrap();
                    let handler: Box<dyn TcpClientHandler> = if kind == "vmess" {
                        Box::new(
                            VmessTcpClientHandler::with_options(
                                "aes-128-gcm",
                                user,
                                true,
                                false,
                                false,
                            )
                            .unwrap()
                            .with_alter_id(alter),
                        )
                    } else {
                        Box::new(
                            crate::vless::vless_client_handler::VlessTcpClientHandler::new(user, true, None, false)
                                .unwrap(),
                        )
                    };
                    let wire = tokio::net::TcpStream::connect(("127.0.0.1", port))
                        .await
                        .unwrap();
                    let setup = handler
                        .setup_client_tcp_stream(
                            Box::new(wire),
                            NetLocation::from_str("destination.test:443", None)
                                .unwrap()
                                .into(),
                        )
                        .await
                        .unwrap();
                    let (mut reader, mut writer) = tokio::io::split(setup.client_stream);
                    let payload: Vec<_> = (0..32769).map(|i| (i % 251) as u8).collect();
                    let mut received = vec![0; payload.len()];
                    let (sent, read) = tokio::join!(
                        async {
                            writer.write_all(&payload).await?;
                            writer.flush().await
                        },
                        reader.read_exact(&mut received)
                    );
                    sent.unwrap();
                    read.unwrap();
                    assert_eq!(received, payload);
                    writer.shutdown().await.unwrap();
                    child.kill().await.unwrap();
                    child.wait().await.unwrap();
                })
                .await
                .unwrap_or_else(|_| panic!("{kind} id={user:?} alter={alter}"));
            }
        }
    }
}

#[tokio::test]
#[ignore = "requires AEROBOX_VMESS_PEER built from tests/fixtures/vmess-peer"]
async fn legacy_authentication_cfb_and_zero_with_independent_go_peer() {
    use crate::packet_encoding::PacketEncoding;
    use std::sync::Arc;
    let resolver: Arc<dyn crate::resolver::Resolver> =
        Arc::new(crate::resolver::NativeResolver::new());
    for alter_id in [0u16, 1, 64] {
        let mut child = tokio::process::Command::new(
            std::env::var_os("AEROBOX_VMESS_PEER").expect("set AEROBOX_VMESS_PEER"),
        )
        .args(["vmess", &alter_id.to_string()])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
        let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
        let port = tokio::time::timeout(Duration::from_secs(5), lines.next_line())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .parse::<u16>()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(60), async {
            for cipher in [
                "aes-128-cfb",
                "aes-128-gcm",
                "chacha20-poly1305",
                "none",
                "zero",
            ] {
                eprintln!("VMess reference TCP alter_id={alter_id} cipher={cipher}");
                let handler = VmessTcpClientHandler::with_options(
                    cipher,
                    "d9ad4eab-f118-492b-a99b-e0e27332b4b2",
                    true,
                    true,
                    true,
                )
                .unwrap()
                .with_alter_id(alter_id);
                let wire = tokio::net::TcpStream::connect(("127.0.0.1", port))
                    .await
                    .unwrap();
                let setup = handler
                    .setup_client_tcp_stream(
                        Box::new(wire),
                        NetLocation::from_str("destination.example:443", None)
                            .unwrap()
                            .into(),
                    )
                    .await
                    .unwrap();
                let (mut reader, mut writer) = tokio::io::split(setup.client_stream);
                let payload: Vec<_> = (0..131_071).map(|i| (i % 251) as u8).collect();
                let mut received = vec![0; payload.len()];
                let (sent, read) = tokio::join!(
                    async {
                        writer.write_all(&payload).await?;
                        writer.flush().await
                    },
                    reader.read_exact(&mut received)
                );
                sent.unwrap();
                read.unwrap_or_else(|error| panic!("TCP alter_id={alter_id} {cipher}: {error}"));
                assert_eq!(received, payload, "TCP alter_id={alter_id} {cipher}");
                writer.shutdown().await.unwrap();
                drop(reader);
                drop(writer);
                for encoding in [
                    PacketEncoding::Native,
                    PacketEncoding::Xudp,
                    PacketEncoding::PacketAddr,
                ] {
                    let handler = VmessTcpClientHandler::with_options(
                        cipher,
                        "d9ad4eab-f118-492b-a99b-e0e27332b4b2",
                        true,
                        true,
                        true,
                    )
                    .unwrap()
                    .with_alter_id(alter_id)
                    .with_packet_encoding(Some(encoding), Some(resolver.clone()));
                    let wire = tokio::net::TcpStream::connect(("127.0.0.1", port))
                        .await
                        .unwrap();
                    let mut stream = handler
                        .setup_client_udp_bidirectional(
                            Box::new(wire),
                            NetLocation::from_str("192.0.2.1:53", None).unwrap().into(),
                        )
                        .await
                        .unwrap();
                    // sing-vmess's native UDP response writer splits above
                    // WriteChunkSize=15000, including packetaddr's IP header.
                    // XUDP reassembles its explicit length across those chunks.
                    let lengths: &[usize] = match encoding {
                        PacketEncoding::Native => &[0, 1, 1400, 15_000],
                        PacketEncoding::PacketAddr => &[0, 1, 1400, 14_993],
                        PacketEncoding::Xudp => &[0, 1, 1400, 15_000, 32_768],
                    };
                    for &length in lengths {
                        eprintln!("VMess reference UDP alter_id={alter_id} cipher={cipher} encoding={encoding:?} length={length}");
                        let payload: Vec<_> = (0..length).map(|i| (i % 251) as u8).collect();
                        let unrepresentable = (length == 0 && encoding == PacketEncoding::Native && matches!(cipher, "none" | "zero"))
                            || (encoding == PacketEncoding::Xudp && length == 0);
                        if unrepresentable {
                            assert_eq!(poll_fn(|cx| Pin::new(&mut stream).poll_write_message(cx, &payload)).await.unwrap_err().kind(),std::io::ErrorKind::InvalidInput);
                            continue;
                        }
                        poll_fn(|cx| Pin::new(&mut stream).poll_write_message(cx, &payload))
                            .await
                            .unwrap();
                        poll_fn(|cx| Pin::new(&mut stream).poll_flush_message(cx))
                            .await
                            .unwrap();
                        let mut bytes = vec![0; 65535];
                        let mut output = ReadBuf::new(&mut bytes);
                        poll_fn(|cx| Pin::new(&mut stream).poll_read_message(cx, &mut output))
                            .await
                            .unwrap_or_else(|error| {
                                panic!("UDP alter_id={alter_id} {cipher} {encoding:?}: {error}")
                            });
                        assert!(
                            output.filled() == payload,
                            "UDP alter_id={alter_id} {cipher} {encoding:?} expected={length} received={}",
                            output.filled().len(),
                        );
                    }
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("legacy matrix stalled for alter_id={alter_id}"));
        child.kill().await.unwrap();
        child.wait().await.unwrap();
    }
}

#[tokio::test]
#[ignore = "requires AEROBOX_VMESS_PEER built from tests/fixtures/vmess-peer"]
async fn authenticated_lengths_and_padding_with_independent_go_peer() {
    let mut child = tokio::process::Command::new(
        std::env::var_os("AEROBOX_VMESS_PEER").expect("set AEROBOX_VMESS_PEER"),
    )
    .stdout(Stdio::piped())
    .stderr(Stdio::inherit())
    .kill_on_drop(true)
    .spawn()
    .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let port = tokio::time::timeout(Duration::from_secs(5), lines.next_line())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .parse::<u16>()
        .unwrap();
    let target =
        || ResolvedLocation::new(NetLocation::from_str("destination.example:443", None).unwrap());
    tokio::time::timeout(Duration::from_secs(60), async {
        for cipher in ["aes-128-gcm", "chacha20-poly1305", "none"] {
            for padding in [false, true] {
                for auth in [false, true] {
                    let handler = VmessTcpClientHandler::with_options(
                        cipher,
                        "d9ad4eab-f118-492b-a99b-e0e27332b4b2",
                        true,
                        padding,
                        auth,
                    )
                    .unwrap();
                    let wire = tokio::net::TcpStream::connect(("127.0.0.1", port))
                        .await
                        .unwrap();
                    let setup = handler
                        .setup_client_tcp_stream(Box::new(wire), target())
                        .await
                        .unwrap();
                    let (mut reader, mut writer) = tokio::io::split(setup.client_stream);
                    let payload: Vec<u8> = (0..524_288).map(|i| (i % 251) as u8).collect();
                    let mut echoed = vec![0; payload.len()];
                    let (sent, received) = tokio::join!(
                        async {
                            writer.write_all(&payload).await?;
                            writer.flush().await
                        },
                        reader.read_exact(&mut echoed)
                    );
                    sent.unwrap();
                    received.unwrap_or_else(|err| {
                        panic!("{cipher}, padding={padding}, auth={auth}: {err}")
                    });
                    assert_eq!(echoed, payload, "{cipher}, padding={padding}, auth={auth}");
                    writer.shutdown().await.unwrap();
                    drop(reader);
                    drop(writer);
                    let wire = tokio::net::TcpStream::connect(("127.0.0.1", port))
                        .await
                        .unwrap();
                    let mut udp = handler
                        .setup_client_udp_bidirectional(Box::new(wire), target())
                        .await
                        .unwrap();
                    for len in [1, 1400, 15_000] {
                        let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
                        poll_fn(|cx| Pin::new(&mut udp).poll_write_message(cx, &payload))
                            .await
                            .unwrap();
                        poll_fn(|cx| Pin::new(&mut udp).poll_flush_message(cx))
                            .await
                            .unwrap();
                        let mut bytes = vec![0; 65535];
                        let mut buffer = ReadBuf::new(&mut bytes);
                        poll_fn(|cx| Pin::new(&mut udp).poll_read_message(cx, &mut buffer))
                            .await
                            .unwrap();
                        assert!(buffer.filled() == payload, "UDP {cipher}, padding={padding}, auth={auth}, expected={len}, received={}", buffer.filled().len());
                    }
                }
            }
        }
    })
    .await
    .expect("VMess reference peer stalled");
    child.kill().await.unwrap();
    child.wait().await.unwrap();
}

#[tokio::test]
#[ignore = "requires AEROBOX_VMESS_PEER built from tests/fixtures/vmess-peer"]
async fn vmess_and_vless_udp_encodings_with_independent_go_peer() {
    use crate::packet_encoding::PacketEncoding;
    use crate::vless::vless_client_handler::VlessTcpClientHandler;
    use std::sync::Arc;
    let resolver: Arc<dyn crate::resolver::Resolver> =
        Arc::new(crate::resolver::NativeResolver::new());
    for protocol in ["vmess", "vless"] {
        let mut child = tokio::process::Command::new(
            std::env::var_os("AEROBOX_VMESS_PEER").expect("set AEROBOX_VMESS_PEER"),
        )
        .arg(protocol)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
        let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
        let port = tokio::time::timeout(Duration::from_secs(5), lines.next_line())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .parse::<u16>()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(30), async {
            for encoding in [
                PacketEncoding::Native,
                PacketEncoding::Xudp,
                PacketEncoding::PacketAddr,
            ] {
                let handler: Box<dyn TcpClientHandler> = if protocol == "vmess" {
                    Box::new(
                        VmessTcpClientHandler::with_options(
                            "chacha20-poly1305",
                            "d9ad4eab-f118-492b-a99b-e0e27332b4b2",
                            true,
                            true,
                            true,
                        )
                        .unwrap()
                        .with_packet_encoding(Some(encoding), Some(resolver.clone())),
                    )
                } else {
                    Box::new(
                        VlessTcpClientHandler::new(
                            "d9ad4eab-f118-492b-a99b-e0e27332b4b2",
                            true,
                            None,
                            false,
                        )
                        .unwrap()
                        .with_packet_encoding(Some(encoding), resolver.clone())
                        .unwrap(),
                    )
                };
                for destination in ["192.0.2.1:53", "[2001:db8::1]:53"] {
                    let wire = tokio::net::TcpStream::connect(("127.0.0.1", port))
                        .await
                        .unwrap();
                    let target =
                        ResolvedLocation::new(NetLocation::from_str(destination, None).unwrap());
                    let mut stream = handler
                        .setup_client_udp_bidirectional(Box::new(wire), target)
                        .await
                        .unwrap();
                    for len in [1, 1400, 7000] {
                        let bytes: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
                        poll_fn(|cx| Pin::new(&mut stream).poll_write_message(cx, &bytes))
                            .await
                            .unwrap();
                        poll_fn(|cx| Pin::new(&mut stream).poll_flush_message(cx))
                            .await
                            .unwrap();
                        let mut packet = vec![0; 65535];
                        let mut output = ReadBuf::new(&mut packet);
                        poll_fn(|cx| Pin::new(&mut stream).poll_read_message(cx, &mut output))
                            .await
                            .unwrap_or_else(|e| {
                                panic!("{protocol} {encoding:?} {destination}: {e}")
                            });
                        assert!(
                            output.filled() == bytes,
                            "{protocol} {encoding:?}: expected {len}, got {}",
                            output.filled().len()
                        );
                    }
                }
            }
        })
        .await
        .expect("UDP encoding peer stalled");
        child.kill().await.unwrap();
        child.wait().await.unwrap();
    }
}
