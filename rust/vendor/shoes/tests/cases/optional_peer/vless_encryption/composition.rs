use super::*;
use shoes_test_support::{
    socks5::Socks5UdpAssociation, test_servers::start_udp_echo_server_with_suffix,
};



async fn wrapped_case(
    peer: Kind,
    peer_client: bool,
    transport: Transport,
    encrypted: bool,
    vision: bool,
) {
    eprintln!(
        "composition: {peer:?} client={peer_client} {transport:?} encrypted={encrypted} vision={vision}"
    );
    let (encryption, decryption) = if encrypted {
        let (encryption, decryption, _) = credentials("random", &["mlkem768"]);
        (encryption, decryption)
    } else {
        ("none".into(), "none".into())
    };
    let (server_kind, client_kind) = peer_roles(peer, peer_client);
    let (cover, connector, mut cover_task) = tls_echo(false).await;
    let (target, _, mut target_task) = echo().await;
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let (cert, key) = (cert.cert.pem(), cert.signing_key.serialize_pem());
    let server_port = free_port().await;
    let mut server_settings = server_config(server_kind, server_port, &decryption, vision);
    if server_kind == Kind::Mihomo && !encrypted {
        server_settings["listeners"][0]["allow-insecure"] = json!(true);
    }
    let server = start(
        server_kind,
        server_port,
        wrap(
            server_kind,
            server_settings,
            true,
            transport,
            &cert,
            &key,
            cover,
        ),
    )
    .await;
    let client_port = free_port().await;
    let mut client_settings =
        client_config(client_kind, client_port, server_port, &encryption, vision);
    if client_kind == Kind::Mihomo {
        client_settings["proxies"][0]["packet-encoding"] = json!("xudp");
    }
    let client = start(
        client_kind,
        client_port,
        wrap(
            client_kind,
            client_settings,
            false,
            transport,
            &cert,
            &key,
            cover,
        ),
    )
    .await;
    let data: Vec<_> = (0..32769).map(|n| (n % 251) as u8).collect();
    for _ in 0..2 {
        if vision {
            let result = timeout(LIMIT, async {
                let socket = socks_connect(client_port, cover).await?;
                let mut stream = connector
                    .connect("localhost".try_into().unwrap(), socket)
                    .await?;
                for payload in [&[42; 64][..], &[43; 64], &data] {
                    let (mut r, mut w) = tokio::io::split(&mut stream);
                    let mut reply = vec![0; payload.len()];
                    tokio::try_join!(w.write_all(payload), r.read_exact(&mut reply))?;
                    assert_eq!(reply, payload);
                }
                // Close inner TLS without requiring WebSocket to support a TCP half-close.
                stream.get_mut().1.send_close_notify();
                stream.flush().await?;
                assert_eq!(stream.read(&mut [0]).await?, 0, "data after TLS close");
                Ok::<_, io::Error>(())
            })
            .await;
            assert!(
                matches!(result, Ok(Ok(()))),
                "{result:?}\n{}",
                pair_logs(&client, &server)
            );
        } else {
            exchange(client_port, target, &data)
                .await
                .unwrap_or_else(|e| panic!("{e}\n{}", pair_logs(&client, &server)));
        }
    }
    let shoes = if peer_client { &server } else { &client };
    if encrypted {
        shoes.assert_handshakes(&["fresh", "resumed"]);
    }
    if vision {
        for direction in ["READ", "WRITE"] {
            assert_eq!(
                shoes
                    .logs()
                    .matches(&format!(
                        "VISION {direction}: Switching to direct copy mode"
                    ))
                    .count(),
                2,
                "{}",
                shoes.logs()
            );
        }
    }
    // Force UDP frames across HTTP POST and native-record boundaries.
    let udp = start_udp_echo_server_with_suffix("0.0.0.0", 0, b"reply")
        .await
        .unwrap();
    let destination = (std::net::Ipv4Addr::LOCALHOST, udp.local_addr().port()).into();
    for _ in 0..2 {
        let association = timeout(
            LIMIT,
            Socks5UdpAssociation::connect("127.0.0.1", client_port),
        )
        .await
        .unwrap_or_else(|e| panic!("{e}\n{}", pair_logs(&client, &server)))
        .unwrap_or_else(|e| panic!("{e}\n{}", pair_logs(&client, &server)));
        let payload = vec![37; 4096];
        let reply = association
            .send_to(destination, &payload)
            .await
            .unwrap_or_else(|e| panic!("{e}\n{}", pair_logs(&client, &server)));
        assert_eq!(reply, [payload, b"reply".to_vec()].concat());
    }
    drop((client, server));
    cover_task.stop().await;
    target_task.stop().await;
}











#[tokio::test]
async fn encrypted_non_vision_and_wss_resume_through_wrappers() {
    for peer in [Kind::Xray, Kind::Mihomo] {
        for client in [false, true] {
            for transport in [
                Transport::Tls,
                Transport::Websocket,
                Transport::Wss,
                Transport::Reality,
            ] {
                wrapped_case(peer, client, transport, true, false).await;
            }
            wrapped_case(peer, client, Transport::Wss, true, true).await;
        }
    }
    for vision in [false, true] {
        wrapped_case(Kind::Shoes, false, Transport::Quic, true, vision).await;
    }
}

#[tokio::test]
async fn legacy_vless_websocket_and_mihomo_transports_carry_tcp_and_udp() {
    for peer in [Kind::Xray, Kind::Mihomo] {
        for client in [false, true] {
            for transport in [Transport::Websocket, Transport::Wss] {
                wrapped_case(peer, client, transport, false, false).await;
            }
        }
    }
    for client in [false, true] {
        for transport in [Transport::Raw, Transport::Tls, Transport::Reality] {
            wrapped_case(Kind::Mihomo, client, transport, false, false).await;
        }
    }
}
