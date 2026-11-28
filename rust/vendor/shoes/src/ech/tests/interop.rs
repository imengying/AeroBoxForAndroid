use super::*;
use crate::{
    address::NetLocation,
    async_stream::AsyncStream,
    config::{ResolvedClientConfig, ResolvedClientHop},
    option_util::OneOrSome,
};
use rustls::pki_types::pem::PemObject;
use serde_json::{Value, json};
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

#[derive(Debug)]
struct Named(Arc<Dns>);
impl Resolver for Named {
    fn named(&self, name: &str) -> Option<Arc<dyn Resolver>> {
        (name == "ech-dns").then(|| self.0.clone() as Arc<dyn Resolver>)
    }
    fn resolve_location(&self, location: &NetLocation) -> crate::resolver::ResolveFuture {
        self.0.resolve_location(location)
    }
    fn exchange(&self, request: Vec<u8>) -> crate::resolver::DnsExchangeFuture {
        self.0.exchange(request)
    }
}

fn pin(dir: &std::path::Path) -> String {
    let pem = std::fs::read(dir.join("secret.pem")).unwrap();
    let cert = rustls::pki_types::CertificateDer::from_pem_slice(&pem).unwrap();
    let (_, cert) = x509_parser::parse_x509_certificate(cert.as_ref()).unwrap();
    STANDARD.encode(aerobox_primitives::digest::digest(
        &aerobox_primitives::digest::SHA256,
        cert.public_key().raw,
    ))
}
fn configuration(
    port: u16,
    quic: bool,
    verify: bool,
    dir: &std::path::Path,
    dynamic: bool,
    fragments: bool,
) -> Value {
    let mut ech = json!({"config_path":dir.join("initial-config.pem").to_str().unwrap()});
    if dynamic {
        ech = json!({"query_server_name":"config.test"});
    }
    let mut tls = json!({"verify":verify,"sni_hostname":"secret.test","alpn_protocols":["h3"],"options":{
        "ech":ech,"root_certificates":[std::fs::read_to_string(dir.join("ca.pem")).unwrap()],
        // The public certificate deliberately has another key. Rejection uses
        // the public CA/name; accepted connections still enforce this inner pin.
        "certificate_public_key_sha256":[pin(dir)]
    }});
    if quic {
        json!({"address":format!("127.0.0.1:{port}"),"transport":"quic","quic_settings":tls,"protocol":{"type":"noop"}})
    } else {
        tls["type"] = "tls".into();
        tls["protocol"] = json!({"type":"noop"});
        if fragments {
            tls["fragmentation"] =
                json!({"fragment":true,"record_fragment":true,"fragment_fallback_delay":"1ms"});
        }
        json!({"address":format!("127.0.0.1:{port}"),"protocol":tls})
    }
}
fn chain(value: Value, resolver: Arc<dyn Resolver>) -> crate::client_proxy_chain::ClientProxyChain {
    let config: ResolvedClientConfig = crate::config::test_support::from_json(value).unwrap();
    crate::tcp::chain_builder::try_build_client_proxy_chain(
        OneOrSome::One(ResolvedClientHop::Single(config)),
        resolver,
    )
    .unwrap()
}
async fn echo(stream: Box<dyn AsyncStream>) {
    let (mut read, mut write) = tokio::io::split(stream);
    let data: Vec<_> = (0..65537).map(|n| (n % 251) as u8).collect();
    let mut output = vec![0; data.len()];
    let (a, b) = tokio::join!(
        async {
            write.write_all(&data).await?;
            write.flush().await
        },
        read.read_exact(&mut output)
    );
    a.unwrap();
    b.unwrap();
    assert_eq!(data, output);
    write.shutdown().await.unwrap();
}
fn stats(dir: &std::path::Path) -> Value {
    serde_json::from_slice(&std::fs::read(dir.join("stats.json")).unwrap()).unwrap()
}

#[tokio::test]
#[ignore = "requires AEROBOX_ECH_PEER built from tests/fixtures/ech-peer"]
async fn tcp_and_quic_ech_accept_rotation_rejection_and_public_auth_with_go() {
    tokio::time::timeout(Duration::from_secs(80), async {
        for quic in [false, true] {
            for mode in ["accept", "rotate", "reject", "badpublic"] {
                for verify in [true, false] {
                    let dir = tempfile::tempdir().unwrap();
                    let mut child =
                        tokio::process::Command::new(std::env::var_os("AEROBOX_ECH_PEER").unwrap())
                            .arg(if quic { "quic" } else { "tcp" })
                            .arg(mode)
                            .env("AEROBOX_PEER_CERT_DIR", dir.path())
                            .stdout(Stdio::piped())
                            .stderr(Stdio::inherit())
                            .kill_on_drop(true)
                            .spawn()
                            .unwrap();
                    let port: u16 = BufReader::new(child.stdout.take().unwrap())
                        .lines()
                        .next_line()
                        .await
                        .unwrap()
                        .unwrap()
                        .parse()
                        .unwrap();
                    let initial =
                        std::fs::read_to_string(dir.path().join("initial-config.pem")).unwrap();
                    let payload = initial
                        .trim()
                        .strip_prefix("-----BEGIN ECH CONFIGS-----")
                        .unwrap()
                        .strip_suffix("-----END ECH CONFIGS-----")
                        .unwrap();
                    let bytes = STANDARD
                        .decode(
                            payload
                                .chars()
                                .filter(|c| !c.is_ascii_whitespace())
                                .collect::<String>(),
                        )
                        .unwrap();
                    // Dynamic lookup and inline/file input traverse the same handshake path.
                    let dynamic = !verify;
                    let dns = Arc::new(Dns {
                        calls: AtomicUsize::new(0),
                        mode: AtomicUsize::new(0),
                        blocked: AtomicBool::new(false),
                        bytes,
                        ttl: 60,
                    });
                    let resolver: Arc<dyn Resolver> = Arc::new(Named(dns.clone()));
                    let mut input = configuration(port, quic, verify, dir.path(), dynamic, !quic);
                    if dynamic && quic {
                        input["domain_resolver"] =
                            json!({"server":"ech-dns","ip_strategy":"ipv4_only"});
                    }
                    let client = chain(input, resolver.clone());
                    let target = NetLocation::from_str("destination.test:443", None)
                        .unwrap()
                        .into();
                    let result = client.connect_tcp(target, &resolver).await;
                    if matches!(mode, "accept" | "rotate") {
                        let result = result.unwrap_or_else(|error| {
                            panic!("{quic} {mode} verify={verify}: {error}")
                        });
                        echo(result.client_stream).await;
                        let report = stats(dir.path());
                        assert_eq!(report["ech_accepted"], 1, "{report}");
                        assert_eq!(
                            report["attempts"],
                            if mode == "rotate" { 2 } else { 1 },
                            "{report}"
                        );
                        assert_eq!(dns.calls.load(Ordering::SeqCst), usize::from(dynamic));
                        let target = NetLocation::from_str("destination.test:443", None)
                            .unwrap()
                            .into();
                        echo(
                            client
                                .connect_tcp(target, &resolver)
                                .await
                                .unwrap()
                                .client_stream,
                        )
                        .await;
                        let report = stats(dir.path());
                        assert_eq!(report["ech_accepted"], 2, "{report}");
                        assert_eq!(
                            report["attempts"],
                            if mode == "rotate" { 3 } else { 2 },
                            "cached retry must avoid another rejected connection: {report}"
                        );
                        assert_eq!(dns.calls.load(Ordering::SeqCst), usize::from(dynamic));
                    } else {
                        assert!(result.is_err(), "{quic} {mode} verify={verify}");
                        let report = stats(dir.path());
                        assert_eq!(report["connections"], 0, "{report}");
                        assert_eq!(
                            report["attempts"], 1,
                            "unauthenticated retries forbidden: {report}"
                        );
                    }
                    child.kill().await.unwrap();
                    child.wait().await.unwrap();
                }
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn reopening_transport_replays_every_outer_wrapper_in_order() {
    use crate::tcp::{
        carrier_dialer::{CarrierDialer, RouteKey},
        tcp_handler::{ClientTransport, ReopenTransport},
    };
    #[derive(Debug)]
    struct Dialer {
        key: RouteKey,
    }
    #[async_trait::async_trait]
    impl CarrierDialer for Dialer {
        fn route_key(&self) -> &RouteKey {
            &self.key
        }
        async fn open_stream(&self) -> io::Result<Box<dyn AsyncStream>> {
            unreachable!()
        }
    }
    let (send, mut receive) = tokio::sync::mpsc::unbounded_channel();
    let reopen: ReopenTransport<'static> = Arc::new(move || {
        let (stream, peer) = tokio::io::duplex(16);
        send.send(peer).unwrap();
        Box::pin(async move { Ok(Box::new(stream) as Box<dyn AsyncStream>) })
    });
    let t = ClientTransport {
        route: Arc::new(Dialer {
            key: RouteKey(vec![1]),
        }),
        open: reopen(),
        reopen: Some(reopen),
    };
    let t = t
        .wrap(|mut s| async move {
            s.write_all(b"outer").await?;
            Ok(s)
        })
        .wrap(|mut s| async move {
            s.write_all(b"inner").await?;
            Ok(s)
        });
    let first = t.open.await.unwrap();
    let second = t.reopen.unwrap()().await.unwrap();
    for _ in 0..2 {
        let mut peer = receive.recv().await.unwrap();
        let mut bytes = [0; 10];
        peer.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"outerinner");
    }
    drop((first, second));
}
