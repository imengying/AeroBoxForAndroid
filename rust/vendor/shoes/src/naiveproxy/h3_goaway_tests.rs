use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use bytes::{Buf, Bytes};
use h3::ConnectionState;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::task::AbortOnDropHandle;

use crate::{
    address::NetLocation,
    async_stream::AsyncStream,
    quic_endpoint::QuicEndpoint,
    tcp::{
        carrier_dialer::{CarrierDialer, QuicCarrier, RouteKey},
        proxy_connector::ProxyConnector,
    },
};

use super::Client;

#[derive(Debug)]
struct Dialer {
    endpoint: Arc<QuicEndpoint>,
    address: std::net::SocketAddr,
    opens: AtomicUsize,
    key: RouteKey,
}

#[async_trait]
impl CarrierDialer for Dialer {
    fn route_key(&self) -> &RouteKey {
        &self.key
    }
    async fn open_stream(&self) -> io::Result<Box<dyn AsyncStream>> {
        unreachable!()
    }
    async fn open_quic(&self) -> io::Result<QuicCarrier> {
        self.opens.fetch_add(1, Ordering::Relaxed);
        Ok(QuicCarrier {
            connection: self
                .endpoint
                .connect(self.address, "localhost")?
                .await
                .map_err(io::Error::other)?,
            _endpoint: self.endpoint.clone(),
        })
    }
}

fn endpoints(max_streams: u32) -> (quinn::Endpoint, Arc<Dialer>) {
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
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap(),
    ));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(max_streams.into());
    server_config.transport_config(Arc::new(transport));
    let server = quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let tls = crate::rustls_config_util::naive::create_config(
        &crate::config::tls::TlsClientOptions {
            root_certificates: vec![certificate.cert.pem()],
            ..Default::default()
        },
        true,
    )
    .unwrap();
    let mut endpoint =
        QuicEndpoint::new(None, std::net::UdpSocket::bind("127.0.0.1:0").unwrap(), 1).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap(),
    )));
    let route = Arc::new(Dialer {
        endpoint: Arc::new(endpoint),
        address: server.local_addr().unwrap(),
        opens: AtomicUsize::new(0),
        key: RouteKey(vec![95]),
    });
    (server, route)
}

async fn serve(server: quinn::Endpoint, mut trigger: Option<tokio::sync::oneshot::Receiver<()>>) {
    let mut sessions = tokio::task::JoinSet::new();
    let mut generation = 0u8;
    while let Some(incoming) = server.accept().await {
        generation += 1;
        let trigger = if generation == 1 {
            trigger.take()
        } else {
            None
        };
        sessions.spawn(async move {
            let connection = incoming.await.unwrap();
            let mut driver = h3::server::builder().send_grease(false)
                .build(h3_quinn::Connection::new(connection)).await.unwrap();
            let mut streams = tokio::task::JoinSet::new();
            let mut trigger = trigger;
            loop {
                tokio::select! {
                    next = driver.accept() => {
                        let Ok(Some(resolver)) = next else { break; };
                        let (request, mut stream) = resolver.resolve_request().await.unwrap();
                        assert_eq!(request.method(), http::Method::CONNECT);
                        assert_eq!(request.headers()["proxy-authorization"], "Basic dXNlcjpwYXNz");
                        streams.spawn(async move {
                            stream.send_response(http::Response::builder().status(200).body(()).unwrap()).await.unwrap();
                            stream.send_data(Bytes::from(vec![generation])).await.unwrap();
                            while let Some(mut data) = stream.recv_data().await.unwrap() {
                                let data = data.copy_to_bytes(data.remaining());
                                stream.send_data(data).await.unwrap();
                            }
                            stream.finish().await.unwrap();
                        });
                        if generation == 1 {
                            if let Some(trigger) = trigger.take() { trigger.await.unwrap(); }
                            driver.shutdown(0).await.unwrap();
                        }
                    }
                    result = streams.join_next(), if !streams.is_empty() => { result.unwrap().unwrap(); }
                }
            }
            while let Some(result) = streams.join_next().await { result.unwrap(); }
        });
    }
}

#[tokio::test]
async fn http3_goaway_replaces_cached_session_and_preserves_active_tunnel() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let (server, route) = endpoints(100);
        let _peer = AbortOnDropHandle::new(tokio::spawn(serve(server, None)));
        let client = Client::new(
            crate::config::test_support::from_json(serde_json::json!({
                "address":"localhost:443", "transport":"quic", "protocol":{
                    "type":"naiveproxy", "username":"user", "password":"pass", "padding":false,
                    "settings":{"quic":true}
                }
            }))
            .unwrap(),
        )
        .unwrap();
        let target = NetLocation::from_str("echo.test:443", None).unwrap().into();
        let mut old = client
            .connect_tcp_with_dialer(route.clone(), &target)
            .await
            .unwrap()
            .client_stream;
        assert_eq!(old.read_u8().await.unwrap(), 1);

        // Wait for the real driver to process GOAWAY, without keeping an extra
        // Session Arc alive that could conceal a tunnel ownership regression.
        let slot = client.slots.lock()[0].clone();
        loop {
            {
                let stored = slot.session.lock().await;
                let session = stored.as_ref().unwrap();
                assert!(!session._driver.is_finished());
                assert!(session.carrier.connection.close_reason().is_none());
                if session.sender.is_closing() {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        let mut replacement = client
            .connect_tcp_with_dialer(route.clone(), &target)
            .await
            .unwrap()
            .client_stream;
        assert_eq!(replacement.read_u8().await.unwrap(), 2);
        let mut reused = client
            .connect_tcp_with_dialer(route.clone(), &target)
            .await
            .unwrap()
            .client_stream;
        assert_eq!(reused.read_u8().await.unwrap(), 2);
        assert_eq!(route.opens.load(Ordering::Relaxed), 2);

        for (index, stream) in [&mut old, &mut replacement, &mut reused]
            .into_iter()
            .enumerate()
        {
            let payload: Vec<u8> = (0..16385)
                .map(|offset| ((offset + index) % 251) as u8)
                .collect();
            stream.write_all(&payload).await.unwrap();
            stream.shutdown().await.unwrap();
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, payload);
        }
        assert_eq!(route.opens.load(Ordering::Relaxed), 2);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn http3_goaway_during_credit_wait_redials_without_replaying_the_old_tunnel() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let (server, route) = endpoints(1);
        let (goaway, trigger) = tokio::sync::oneshot::channel();
        let _peer = AbortOnDropHandle::new(tokio::spawn(serve(server, Some(trigger))));
        let client = Arc::new(
            Client::new(
                crate::config::test_support::from_json(serde_json::json!({
                    "address":"localhost:443", "transport":"quic", "protocol":{
                        "type":"naiveproxy", "username":"user", "password":"pass", "padding":false,
                        "settings":{"quic":true}
                    }
                }))
                .unwrap(),
            )
            .unwrap(),
        );
        let target = NetLocation::from_str("echo.test:443", None).unwrap().into();
        let mut old = client
            .connect_tcp_with_dialer(route.clone(), &target)
            .await
            .unwrap()
            .client_stream;
        assert_eq!(old.read_u8().await.unwrap(), 1);

        let (started, waiting) = tokio::sync::oneshot::channel();
        let pending = {
            let client = client.clone();
            let route = route.clone();
            let target = target.clone();
            tokio::spawn(async move {
                let mut request = Box::pin(client.connect_tcp_with_dialer(route, &target));
                assert!(futures::poll!(&mut request).is_pending());
                started.send(()).unwrap();
                request.await.unwrap().client_stream
            })
        };
        waiting.await.unwrap();
        assert_eq!(route.opens.load(Ordering::Relaxed), 1);
        // The sole stream credit is held by `old`. The peer sends GOAWAY and
        // never grants another credit on that connection.
        goaway.send(()).unwrap();
        let mut replacement = pending.await.unwrap();
        assert_eq!(replacement.read_u8().await.unwrap(), 2);
        assert_eq!(route.opens.load(Ordering::Relaxed), 2);

        for stream in [&mut old, &mut replacement] {
            stream.write_all(b"still alive after GOAWAY").await.unwrap();
            stream.shutdown().await.unwrap();
            let mut echo = Vec::new();
            stream.read_to_end(&mut echo).await.unwrap();
            assert_eq!(echo, b"still alive after GOAWAY");
        }
        let mut reused = client
            .connect_tcp_with_dialer(route.clone(), &target)
            .await
            .unwrap()
            .client_stream;
        assert_eq!(reused.read_u8().await.unwrap(), 2);
        reused.write_all(b"reuse").await.unwrap();
        reused.shutdown().await.unwrap();
        let mut echo = Vec::new();
        reused.read_to_end(&mut echo).await.unwrap();
        assert_eq!(echo, b"reuse");
        assert_eq!(route.opens.load(Ordering::Relaxed), 2);
    })
    .await
    .unwrap();
}
