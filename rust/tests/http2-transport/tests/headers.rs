use aerobox_http2_transport_check::{validate_websocket_headers, wrap_transport};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn config(kind: &str) -> Value {
    json!({"kind":kind, "host":["one.example", "two.example:8443"], "path":"/tunnel", "headers":{"X-Route":["one", "two"]}, "protocol":null})
}

#[tokio::test]
async fn http1_and_upgrade_write_repeated_headers_and_one_selected_host() {
    for kind in ["http1", "http_upgrade"] {
        let (io, mut peer) = tokio::io::duplex(1024);
        let server = tokio::spawn(async move {
            let mut bytes = Vec::new();
            while !bytes.ends_with(b"\r\n\r\n") {
                bytes.push(peer.read_u8().await.unwrap());
            }
            let request = String::from_utf8(bytes).unwrap();
            assert_eq!(request.matches("Host: ").count(), 1);
            assert!(
                request.contains("Host: one.example\r\n")
                    || request.contains("Host: two.example:8443\r\n")
            );
            assert!(request.contains("X-Route: one\r\nX-Route: two\r\n"));
            let response = if kind == "http1" {
                "HTTP/1.1 200 OK\r\n\r\nreply"
            } else {
                "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nreply"
            };
            peer.write_all(response.as_bytes()).await.unwrap();
        });
        let mut stream = wrap_transport(config(kind), io).await.unwrap();
        let mut result = Vec::new();
        stream.read_to_end(&mut result).await.unwrap();
        assert_eq!(result, b"reply");
        server.await.unwrap();
    }
}

#[tokio::test]
async fn http2_preserves_repeated_header_values_in_the_hpack_request() {
    let (io, peer) = tokio::io::duplex(8192);
    let server = tokio::spawn(async move {
        let mut connection = h2::server::handshake(peer).await.unwrap();
        let (request, mut reply) = connection.accept().await.unwrap().unwrap();
        assert!(matches!(
            request.uri().authority().map(|a| a.as_str()),
            Some("one.example" | "two.example:8443")
        ));
        assert_eq!(
            request
                .headers()
                .get_all("x-route")
                .iter()
                .map(|v| v.to_str().unwrap())
                .collect::<Vec<_>>(),
            ["one", "two"]
        );
        let mut send = reply.send_response(http::Response::new(()), false).unwrap();
        send.send_data(bytes::Bytes::from_static(b"reply"), true)
            .unwrap();
        let _request = request;
        let _send = send;
        while connection.accept().await.is_some() {}
    });
    let mut stream = wrap_transport(config("http2"), io).await.unwrap();
    let mut reply = [0; 5];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"reply");
    drop(stream);
    server.abort();
}

#[test]
fn websocket_headers_accept_repeats_without_weakening_handshake_validation() {
    for early in [false, true] {
        validate_websocket_headers(
            json!({"Host":"edge.example", "X-Route":["one", "two"]}),
            early,
        )
        .unwrap();
        for bad in [
            json!({"Host":["one.example", "two.example"]}),
            json!({"Host":"one.example", "host":"two.example"}),
            json!({"Host":"one.example", "X-Route":["good", "bad\r\nInjected: yes"]}),
            json!({"Host":"one.example", "Connection":"Upgrade"}),
            json!({"Host":"one.example", "X-Route":vec!["value"; 40]}),
        ] {
            assert!(
                validate_websocket_headers(bad.clone(), early).is_err(),
                "{bad}"
            );
        }
    }
    assert!(
        validate_websocket_headers(
            json!({"Host":"one.example", "sec-websocket-protocol":["one","two"]}),
            true
        )
        .is_err()
    );
}
