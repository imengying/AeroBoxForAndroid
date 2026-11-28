use super::quic::Client;
use std::{io,pin::Pin,sync::{Arc,atomic::{AtomicUsize,Ordering}},time::Duration};
use async_trait::async_trait;
use bytes::{Buf,Bytes};
use tokio::io::ReadBuf;
use tokio_util::task::AbortOnDropHandle;
use crate::{address::NetLocation,async_stream::AsyncStream,tcp::{carrier_dialer::{CarrierDialer,QuicCarrier},proxy_connector::ProxyConnector}};
use crate::{quic_endpoint::QuicEndpoint, tcp::carrier_dialer::RouteKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug)]
struct Dialer {endpoint:Arc<QuicEndpoint>,address:std::net::SocketAddr,opens:AtomicUsize,key:RouteKey}
#[async_trait]
impl CarrierDialer for Dialer {
    fn route_key(&self)->&RouteKey {&self.key}
    async fn open_stream(&self)->io::Result<Box<dyn AsyncStream>> {unreachable!()}
    async fn open_quic(&self)->io::Result<QuicCarrier> {
        self.opens.fetch_add(1,Ordering::Relaxed);
        Ok(QuicCarrier{connection:self.endpoint.connect(self.address,"localhost")?.await.map_err(io::Error::other)?,_endpoint:self.endpoint.clone()})
    }
}
fn endpoints()->(quinn::Endpoint,Arc<Dialer>) {
    let certificate=rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let provider=Arc::new(aerobox_crypto::provider());
    let mut tls=rustls::ServerConfig::builder_with_provider(provider.clone()).with_protocol_versions(&[&rustls::version::TLS13]).unwrap().with_no_client_auth().with_single_cert(vec![certificate.cert.der().clone()],rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.signing_key.serialize_der()).into()).unwrap();
    tls.alpn_protocols=vec![b"h3".to_vec()];
    let server=quinn::Endpoint::server(quinn::ServerConfig::with_crypto(Arc::new(quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap())),"127.0.0.1:0".parse().unwrap()).unwrap();
    let mut roots=rustls::RootCertStore::empty();roots.add(certificate.cert.der().clone()).unwrap();
    let mut tls=rustls::ClientConfig::builder_with_provider(provider).with_protocol_versions(&[&rustls::version::TLS13]).unwrap().with_root_certificates(roots).with_no_client_auth();
    tls.alpn_protocols=vec![b"h3".to_vec()];
    let mut endpoint=QuicEndpoint::new(None,std::net::UdpSocket::bind("127.0.0.1:0").unwrap(),1).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap())));
    let route=Arc::new(Dialer{endpoint:Arc::new(endpoint),address:server.local_addr().unwrap(),opens:AtomicUsize::new(0),key:RouteKey(vec![51])});
    (server,route)
}

async fn serve(server:quinn::Endpoint) {
    let mut sessions=tokio::task::JoinSet::new();
    while let Some(incoming)=server.accept().await {
        sessions.spawn(async move {
            let Ok(connection)=incoming.await else {return;};
            let mut h3=h3::server::builder().send_grease(false).build(h3_quinn::Connection::new(connection)).await.unwrap();
            let mut streams=tokio::task::JoinSet::new();
            while let Ok(Some(resolver))=h3.accept().await {
                streams.spawn(async move {
                    let (request,mut stream)=resolver.resolve_request().await.unwrap();
                    assert_eq!(request.method(),http::Method::CONNECT);
                    let authorized=request.headers().get("proxy-authorization").is_some_and(|v|v=="Basic dXNlcjpwYXNz");
                    if !authorized {stream.send_response(http::Response::builder().status(407).body(()).unwrap()).await.unwrap();stream.finish().await.unwrap();return;}
                    assert_eq!(request.headers().get_all("x-test").iter().count(),2);
                    let padding=request.headers().contains_key("padding");
                    let mut response=http::Response::builder().status(200);
                    if padding {response=response.header("padding-type-reply","1");}
                    stream.send_response(response.body(()).unwrap()).await.unwrap();
                    // Independent peer: decode the 3-byte Naive frames, echo
                    // application bytes with zero padding. Exercise UoT v2 too.
                    let mut wire=bytes::BytesMut::new();let mut received=0;let mut sent=0;
                    let mut skip=if request.uri().authority().unwrap().as_str()=="sp.v2.udp-over-tcp.arpa:0" {8} else {0};
                    while let Ok(Some(mut data))=stream.recv_data().await {
                        wire.extend_from_slice(&data.copy_to_bytes(data.remaining()));
                        loop {
                            let mut application=if padding && received<8 {
                                if wire.len()<3 {break;}
                                let size=u16::from_be_bytes([wire[0],wire[1]]) as usize;let extra=wire[2] as usize;
                                if wire.len()<3+size+extra {break;}
                                wire.advance(3);let value=wire.split_to(size).freeze();wire.advance(extra);received+=1;value
                            } else {if wire.is_empty(){break;}wire.split().freeze()};
                            let discard=skip.min(application.len());skip-=discard;application.advance(discard);
                            if application.is_empty(){continue;}
                            for part in application.chunks(65535) {
                                let data=if padding && sent<8 {sent+=1;let mut frame=Vec::with_capacity(part.len()+3);frame.extend_from_slice(&(part.len() as u16).to_be_bytes());frame.push(0);frame.extend_from_slice(part);Bytes::from(frame)} else {Bytes::copy_from_slice(part)};
                                if stream.send_data(data).await.is_err(){return;}
                            }
                        }
                    }
                    let _=stream.finish().await;
                });
            }
        });
    }
}

fn client(padding:bool,udp:Option<u8>,concurrency:usize,password:&str)->Client {
    let config=crate::config::test_support::from_json(serde_json::json!({"address":"localhost:443","transport":"quic","protocol":{"type":"naiveproxy","username":"user","password":password,"padding":padding,"settings":{"quic":true,"insecure_concurrency":concurrency,"extra_headers":{"x-test":["one","two"]},"udp_over_tcp":udp}}})).unwrap();
    Client::new(config).unwrap()
}

#[tokio::test]
async fn http3_padding_reuse_concurrency_and_uot_preserve_data_and_fin() {
    tokio::time::timeout(Duration::from_secs(20),async {
        let (server,route)=endpoints();let peer=AbortOnDropHandle::new(tokio::spawn(serve(server)));
        for padding in [false,true] {
            let client=Arc::new(client(padding,Some(2),2,"pass"));
            let before=route.opens.load(Ordering::Relaxed);let mut jobs=tokio::task::JoinSet::new();
            for index in 0..6 {
                let client=client.clone();let route=route.clone();
                jobs.spawn(async move {
                    let stream=client.connect_tcp_with_dialer(route,&NetLocation::from_str("echo.test:443",None).unwrap().into()).await.unwrap().client_stream;
                    let data=vec![index as u8;512*1024];let expected=data.clone();
                    let (mut read,mut write)=tokio::io::split(stream);
                    let send=async {write.write_all(&data).await.unwrap();write.flush().await.unwrap();write.shutdown().await.unwrap();};
                    let receive=async {let mut bytes=Vec::new();read.read_to_end(&mut bytes).await.unwrap();assert_eq!(bytes,expected);};
                    tokio::join!(send,receive);
                });
            }
            while let Some(result)=jobs.join_next().await {result.unwrap();}
            assert_eq!(route.opens.load(Ordering::Relaxed)-before,2);
            let mut udp=client.connect_udp_with_dialer(route.clone(),NetLocation::from_str("127.0.0.1:53",None).unwrap().into()).await.unwrap();
            for payload in [b"hello".as_slice(),b"",b"after empty"] {
                std::future::poll_fn(|cx|Pin::new(&mut *udp).poll_write_message(cx,payload)).await.unwrap();
                std::future::poll_fn(|cx|Pin::new(&mut *udp).poll_flush_message(cx)).await.unwrap();
                let mut storage=[0;64];let mut out=ReadBuf::new(&mut storage);
                std::future::poll_fn(|cx|Pin::new(&mut *udp).poll_read_message(cx,&mut out)).await.unwrap();
                assert_eq!(out.filled(),payload);assert!(!udp.read_message_eof_on_empty());
            }
        }
        let denied=client(false,None,1,"incorrect").connect_tcp_with_dialer(route,&NetLocation::from_str("echo.test:80",None).unwrap().into()).await;
        assert!(matches!(denied,Err(e) if e.kind()==io::ErrorKind::PermissionDenied));
        drop(peer);
    }).await.unwrap();
}

#[tokio::test]
async fn http3_concurrency_above_sixteen_reuses_sessions_and_large_config_is_lazy() {
    tokio::time::timeout(Duration::from_secs(30),async {
        let (server,route)=endpoints();
        let _peer=AbortOnDropHandle::new(tokio::spawn(serve(server)));
        for concurrency in [17,33,usize::MAX] {
            let client=client(false,None,concurrency,"pass");
            let before=route.opens.load(Ordering::Relaxed);
            let expected_sessions=if concurrency==usize::MAX {1} else {concurrency};
            let requests=if concurrency==usize::MAX {1} else {concurrency*2};
            for _ in 0..requests {
                let mut stream=client.connect_tcp_with_dialer(route.clone(),&NetLocation::from_str("echo.test:443",None).unwrap().into()).await.unwrap().client_stream;
                stream.write_all(b"reuse").await.unwrap();
                stream.shutdown().await.unwrap();
                let mut received=Vec::new();
                stream.take(6).read_to_end(&mut received).await.unwrap();
                assert_eq!(received,b"reuse");
            }
            assert_eq!(route.opens.load(Ordering::Relaxed)-before,expected_sessions);
        }
    }).await.unwrap();
}

#[tokio::test]
#[ignore = "requires AEROBOX_NAIVE_PEER built from tests/fixtures/naive-peer"]
async fn naive_http2_and_http3_with_independent_go_peer() {
    use base64::Engine;
    use tokio::io::{AsyncBufReadExt,BufReader};
    use crate::tcp::tcp_handler::TcpClientHandler;
    tokio::time::timeout(Duration::from_secs(30),async {
        let mut child=tokio::process::Command::new(std::env::var_os("AEROBOX_NAIVE_PEER").expect("set AEROBOX_NAIVE_PEER"))
            .stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::inherit()).kill_on_drop(true).spawn().unwrap();
        let mut line=String::new();BufReader::new(child.stdout.take().unwrap()).read_line(&mut line).await.unwrap();
        let settings:serde_json::Value=serde_json::from_str(&line).unwrap();
        let der=base64::engine::general_purpose::STANDARD.decode(settings["certificate"].as_str().unwrap()).unwrap();
        let tls_options=crate::config::tls::TlsClientOptions {
            root_certificates:vec![format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",base64::engine::general_purpose::STANDARD.encode(der))],
            ..Default::default()
        };
        let config=crate::rustls_config_util::naive::create_config(&tls_options,false).unwrap();
        let h3_config=crate::rustls_config_util::naive::create_config(&tls_options,true).unwrap();
        let mut endpoint=QuicEndpoint::new(None,std::net::UdpSocket::bind("127.0.0.1:0").unwrap(),1).unwrap();
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(h3_config).unwrap())));
        let dialer=Arc::new(Dialer{endpoint:Arc::new(endpoint),address:([127,0,0,1],settings["h3"].as_u64().unwrap() as u16).into(),opens:AtomicUsize::new(0),key:RouteKey(vec![72])});
        for padding in [false,true] {
            let h3=client(padding,None,1,"pass");
            for http3 in [false,true] {
                let target=NetLocation::from_str("echo.test:443",None).unwrap().into();
                let stream=if http3 {h3.connect_tcp_with_dialer(dialer.clone(),&target).await.unwrap().client_stream} else {
                    let socket=tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST,settings["h2"].as_u64().unwrap() as u16)).await.unwrap();
                    let config=config.clone();
                    let tls=crate::crypto::CryptoTlsStream::handshake(socket,crate::crypto::TlsConnection::new(rustls::ClientConnection::new(Arc::new(config),"localhost".try_into().unwrap()).unwrap()),crate::crypto::TlsReadMode::Stream,&[]).await.unwrap();
                    super::NaiveProxyTcpClientHandler::new("user","pass",padding).setup_client_tcp_stream(Box::new(tls),target).await.unwrap().client_stream
                };
                let data:Vec<u8>=(0..512*1024).map(|i|(i%251) as u8).collect();let expected=data.clone();
                let (mut read,mut write)=tokio::io::split(stream);
                let upload=async {write.write_all(&data).await.unwrap();write.flush().await.unwrap();write.shutdown().await.unwrap();};
                let download=async {let mut bytes=Vec::new();read.read_to_end(&mut bytes).await.unwrap();assert_eq!(bytes,expected,"HTTP/3={http3}, padding={padding}");};
                tokio::join!(upload,download);
            }
        }
        child.kill().await.unwrap();child.wait().await.unwrap();
    }).await.unwrap();
}
