use super::*;
use bytes::Bytes;
use hickory_resolver::TlsConfig;
use rustls::{
    RootCertStore,
    pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
};
use tokio_rustls::TlsAcceptor;

#[derive(Clone, Copy, Debug)]
enum DohReply {
    Valid,
    HttpError,
    WrongContentType,
    MalformedDns,
    WrongQuestion,
}

async fn doh_server(
    mode: DohReply,
    endpoint: &'static str,
) -> (
    Upstream,
    TlsConfig,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let cert = rcgen::generate_simple_self_signed(vec!["dns.test".into()]).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let mut tls = TlsConfig::new().unwrap();
    tls.config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let private = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
    let mut server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert.der().clone()], private)
        .unwrap();
    server.alpn_protocols = vec![b"h2".to_vec()];
    let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let acceptor = TlsAcceptor::from(Arc::new(server));
    let (shutdown, mut stop) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let mut workers = tokio::task::JoinSet::new();
        loop {
            let (socket, _) = tokio::select! {
                _ = &mut stop => break,
                Some(result) = workers.join_next(), if !workers.is_empty() => { result.unwrap(); continue; }
                socket = listener.accept() => socket.unwrap(),
            };
            let acceptor = acceptor.clone();
            workers.spawn(async move {
                let Ok(stream) = acceptor.accept(socket).await else {
                    return;
                };
                let mut connection = h2::server::handshake(stream).await.unwrap();
                while let Some(request) = connection.accept().await {
                    let Ok((request, mut sender)) = request else {
                        return;
                    };
                    assert_eq!(request.method(), "POST");
                    assert_eq!(request.uri().path_and_query().unwrap().as_str(), endpoint);
                    assert_eq!(request.headers()["content-type"], "application/dns-message");
                    let mut body = request.into_body();
                    let mut bytes = Vec::new();
                    while let Some(chunk) = body.data().await {
                        let chunk = chunk.unwrap();
                        body.flow_control().release_capacity(chunk.len()).unwrap();
                        bytes.extend_from_slice(&chunk);
                    }
                    let query = Message::from_vec(&bytes).unwrap();
                    let mut answer = response(&query);
                    answer.answers.push(Record::from_rdata(
                        query.queries[0].name().clone(),
                        60,
                        RData::A(A("192.0.2.99".parse().unwrap())),
                    ));
                    if matches!(mode, DohReply::WrongQuestion) {
                        answer.queries[0].set_name(canonical_name("different.test").unwrap());
                    }
                    let reply = http::Response::builder()
                        .status(if matches!(mode, DohReply::HttpError) {
                            503
                        } else {
                            200
                        })
                        .header(
                            "content-type",
                            if matches!(mode, DohReply::WrongContentType) {
                                "application/json"
                            } else {
                                "application/dns-message"
                            },
                        )
                        .body(())
                        .unwrap();
                    let mut body = sender.send_response(reply, false).unwrap();
                    let bytes = if matches!(mode, DohReply::MalformedDns) {
                        vec![0, 1, 2]
                    } else {
                        answer.to_vec().unwrap()
                    };
                    body.send_data(Bytes::from(bytes), true).unwrap();
                }
            });
        }
        workers.abort_all();
        while let Some(result) = workers.join_next().await {
            if let Err(error) = result {
                assert!(error.is_cancelled(), "DoH fixture worker failed: {error}");
            }
        }
    });
    (
        Upstream::Doh {
            url: format!("https://dns.test:{port}{endpoint}")
                .parse()
                .unwrap(),
            bootstrap: vec![Ipv4Addr::LOCALHOST.into()],
        },
        tls,
        shutdown,
        task,
    )
}

#[tokio::test]
async fn doh_uses_bootstrap_with_certificate_and_hostname_validation() {
    let (upstream, tls, shutdown, task) = doh_server(DohReply::Valid, "/dns-query").await;
    let forwarder =
        Forwarder::with_tls(std::slice::from_ref(&upstream), Duration::from_secs(2), tls).unwrap();
    for _ in 0..2 {
        let answer = forwarder
            .exchange(query("external.example", RecordType::A))
            .await
            .unwrap();
        assert_eq!(
            answer.answers[0].data,
            RData::A(A("192.0.2.99".parse().unwrap()))
        );
        assert_eq!(answer.metadata.id, 4242);
    }
    // The same self-signed server must fail with the normal public trust roots.
    let untrusted =
        Forwarder::new(std::slice::from_ref(&upstream), Duration::from_secs(2)).unwrap();
    assert!(
        untrusted
            .exchange(query("external.example", RecordType::A))
            .await
            .is_err()
    );
    let _ = shutdown.send(());
    tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap();
    let (mut upstream, tls, shutdown, task) = doh_server(DohReply::Valid, "/dns-query").await;
    if let Upstream::Doh { url, .. } = &mut upstream {
        url.set_host(Some("wrong.test")).unwrap();
    }
    let wrong_host = Forwarder::with_tls(&[upstream], Duration::from_secs(2), tls).unwrap();
    assert!(
        wrong_host
            .exchange(query("external.example", RecordType::A))
            .await
            .is_err()
    );
    let _ = shutdown.send(());
    tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn doh_rejects_http_and_dns_protocol_failures() {
    for mode in [
        DohReply::HttpError,
        DohReply::WrongContentType,
        DohReply::MalformedDns,
        DohReply::WrongQuestion,
    ] {
        let (upstream, tls, shutdown, task) = doh_server(mode, "/dns-query").await;
        let forwarder = Forwarder::with_tls(&[upstream], Duration::from_secs(1), tls).unwrap();
        assert!(
            forwarder
                .exchange(query("external.example", RecordType::A))
                .await
                .is_err(),
            "{mode:?}"
        );
        let _ = shutdown.send(());
        tokio::time::timeout(Duration::from_secs(3), task)
            .await
            .unwrap()
            .unwrap();
    }
}

#[tokio::test]
async fn doh_preserves_custom_path_and_query() {
    let (upstream, tls, shutdown, task) =
        doh_server(DohReply::Valid, "/resolve/custom?profile=test").await;
    let forwarder = Forwarder::with_tls(&[upstream], Duration::from_secs(1), tls).unwrap();
    assert_eq!(
        forwarder
            .exchange(query("external.example", RecordType::A))
            .await
            .unwrap()
            .answers
            .len(),
        1
    );
    let _ = shutdown.send(());
    tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap();
}
