#![cfg(feature = "cli")]

#[path = "transport/doh.rs"]
mod doh;

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use hickory_proto::{
    op::{Edns, Message, OpCode, Query, ResponseCode},
    rr::{
        RData, Record, RecordType,
        rdata::{A, SOA, TXT},
    },
};
use hickory_server::Server;
use tendns::{
    config::{Config, Upstream},
    names::canonical_name,
    protocol::{Entry, Publication, Value, encrypt},
    resolver::{Clock, Resolver, SystemClock},
    server::Handler,
    upstream::{Exchange, Forwarder},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
};

fn query(name: &str, kind: RecordType) -> Message {
    let mut query = Message::query();
    query.metadata.id = 4242;
    query.metadata.recursion_desired = true;
    query
        .queries
        .push(Query::query(canonical_name(name).unwrap(), kind));
    query
}

fn response(query: &Message) -> Message {
    let mut response = Message::response(query.metadata.id, OpCode::Query);
    response.metadata.recursion_desired = query.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    response.queries = query.queries.clone();
    response
}

fn localhost(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

async fn tcp_read(stream: &mut TcpStream) -> Message {
    tokio::time::timeout(Duration::from_secs(5), async {
        let length = stream.read_u16().await.unwrap() as usize;
        let mut bytes = vec![0; length];
        stream.read_exact(&mut bytes).await.unwrap();
        Message::from_vec(&bytes).unwrap()
    })
    .await
    .expect("DNS TCP response timed out")
}

async fn tcp_write(stream: &mut TcpStream, response: &Message) {
    tokio::time::timeout(Duration::from_secs(5), async {
        let bytes = response.to_vec().unwrap();
        stream.write_u16(bytes.len() as u16).await.unwrap();
        stream.write_all(&bytes).await.unwrap();
    })
    .await
    .expect("DNS TCP write timed out");
}

#[tokio::test]
async fn plain_upstream_retries_truncated_udp_and_reconnects_closed_tcp() {
    let tcp = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let address = localhost(tcp.local_addr().unwrap().port());
    let udp = UdpSocket::bind(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        address.port(),
    ))
    .await
    .unwrap();
    let udp_task = tokio::spawn(async move {
        let mut bytes = [0; 4096];
        for _ in 0..2 {
            let (length, peer) = udp.recv_from(&mut bytes).await.unwrap();
            let query = Message::from_vec(&bytes[..length]).unwrap();
            let mut reply = response(&query);
            reply.metadata.truncation = true;
            udp.send_to(&reply.to_vec().unwrap(), peer).await.unwrap();
        }
    });
    let tcp_task = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut stream, _) = tcp.accept().await.unwrap();
            let query = tcp_read(&mut stream).await;
            let mut reply = response(&query);
            reply.metadata.authentic_data = true;
            reply.answers.push(Record::from_rdata(
                query.queries[0].name().clone(),
                123,
                RData::A(A("192.0.2.42".parse().unwrap())),
            ));
            tcp_write(&mut stream, &reply).await;
        }
    });
    let upstream = Forwarder::new(&[Upstream::Plain(address)], Duration::from_secs(2)).unwrap();
    for _ in 0..2 {
        let result = upstream
            .exchange(query("external.example", RecordType::A))
            .await
            .unwrap();
        assert_eq!(result.metadata.id, 4242);
        assert!(!result.metadata.truncation);
        assert!(result.metadata.authentic_data);
        assert_eq!(
            result.answers[0].data,
            RData::A(A("192.0.2.42".parse().unwrap()))
        );
    }
    tokio::time::timeout(Duration::from_secs(5), udp_task)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), tcp_task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn negative_response_preserves_soa_and_does_not_trigger_tcp() {
    let udp = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    let address = localhost(udp.local_addr().unwrap().port());
    let task = tokio::spawn(async move {
        let mut bytes = [0; 4096];
        let (length, peer) = udp.recv_from(&mut bytes).await.unwrap();
        let query = Message::from_vec(&bytes[..length]).unwrap();
        let mut reply = response(&query);
        reply.metadata.response_code = ResponseCode::NXDomain;
        reply.authorities.push(Record::from_rdata(
            canonical_name("example").unwrap(),
            30,
            RData::SOA(SOA::new(
                canonical_name("ns.example").unwrap(),
                canonical_name("admin.example").unwrap(),
                1,
                30,
                30,
                30,
                30,
            )),
        ));
        udp.send_to(&reply.to_vec().unwrap(), peer).await.unwrap();
    });
    let upstream = Forwarder::new(&[Upstream::Plain(address)], Duration::from_secs(2)).unwrap();
    let result = upstream
        .exchange(query("missing.example", RecordType::A))
        .await
        .unwrap();
    assert_eq!(result.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(result.authorities.len(), 1);
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn upstream_failover_uses_the_next_configured_resolver() {
    let mut upstreams = Vec::new();
    let mut tasks = Vec::new();
    for failure in [true, false] {
        let udp = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        upstreams.push(Upstream::Plain(localhost(udp.local_addr().unwrap().port())));
        tasks.push(tokio::spawn(async move {
            let mut bytes = [0; 4096];
            let (len, peer) = udp.recv_from(&mut bytes).await.unwrap();
            let question = Message::from_vec(&bytes[..len]).unwrap();
            let mut answer = response(&question);
            if failure {
                answer.metadata.response_code = ResponseCode::ServFail;
            } else {
                answer.answers.push(Record::from_rdata(
                    question.queries[0].name().clone(),
                    60,
                    RData::A(A("192.0.2.11".parse().unwrap())),
                ));
            }
            udp.send_to(&answer.to_vec().unwrap(), peer).await.unwrap();
        }));
    }
    let forwarder = Forwarder::new(&upstreams, Duration::from_secs(2)).unwrap();
    let answer = forwarder
        .exchange(query("external.net", RecordType::A))
        .await
        .unwrap();
    assert_eq!(
        answer.answers[0].data,
        RData::A(A("192.0.2.11".parse().unwrap()))
    );
    for task in tasks {
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
    }
}

struct LargeAnswer;
#[async_trait::async_trait]
impl Exchange for LargeAnswer {
    async fn exchange(&self, query: Message) -> anyhow::Result<Message> {
        let mut response = response(&query);
        for i in 0..20 {
            response.answers.push(Record::from_rdata(
                query.queries[0].name().clone(),
                60,
                RData::TXT(TXT::new(vec![format!("{i:03}{}", "x".repeat(197))])),
            ));
        }
        Ok(response)
    }
}

#[tokio::test]
async fn listeners_support_udp_tcp_edns_truncation_and_shutdown() {
    let config = Config::parse("hex_zones = ['hex.test']").unwrap();
    let resolver = Arc::new(Resolver::new(config.policy, Arc::new(LargeAnswer)));
    let mut server = Server::new(Handler::new(resolver, 8, Duration::from_secs(2)));
    let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let address = localhost(listener.local_addr().unwrap().port());
    let udp = UdpSocket::bind(SocketAddr::new(
        Ipv4Addr::UNSPECIFIED.into(),
        address.port(),
    ))
    .await
    .unwrap();
    server.register_socket(udp);
    server.register_listener(listener, Duration::from_secs(2), 8);
    let cancellation = server.shutdown_token().clone();
    let task = tokio::spawn(async move {
        server.block_until_done().await.unwrap();
    });
    let client = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    let mut bytes = [0; 65535];
    for max_size in [512, 1232] {
        let mut question = query("large.external", RecordType::TXT);
        if max_size > 512 {
            question.edns = Some(Edns::new());
            question.edns.as_mut().unwrap().set_max_payload(max_size);
        }
        client
            .send_to(&question.to_vec().unwrap(), address)
            .await
            .unwrap();
        let (length, _) =
            tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut bytes))
                .await
                .unwrap()
                .unwrap();
        assert!(length <= max_size as usize);
        let result = Message::from_vec(&bytes[..length]).unwrap();
        assert!(result.metadata.truncation);
        assert_eq!(result.edns.is_some(), max_size > 512);
    }
    let mut stream = TcpStream::connect(address).await.unwrap();
    tcp_write(&mut stream, &query("large.external", RecordType::TXT)).await;
    let result = tcp_read(&mut stream).await;
    assert!(!result.metadata.truncation);
    assert_eq!(result.answers.len(), 20);
    tcp_write(&mut stream, &query("c0000201.hex.test", RecordType::A)).await;
    let result = tcp_read(&mut stream).await;
    assert_eq!(
        result.answers[0].data,
        RData::A(A("192.0.2.1".parse().unwrap()))
    );
    let mut invalid = query("example.com", RecordType::A);
    invalid.metadata.op_code = OpCode::Update;
    tcp_write(&mut stream, &invalid).await;
    assert_eq!(
        tcp_read(&mut stream).await.metadata.response_code,
        ResponseCode::NotImp
    );
    let mut invalid = query("example.com", RecordType::A);
    invalid.queries.push(invalid.queries[0].clone());
    tcp_write(&mut stream, &invalid).await;
    assert_eq!(
        tcp_read(&mut stream).await.metadata.response_code,
        ResponseCode::FormErr
    );
    let mut invalid = query("example.com", RecordType::A);
    invalid.queries[0].set_query_class(hickory_proto::rr::DNSClass::CH);
    tcp_write(&mut stream, &invalid).await;
    assert_eq!(
        tcp_read(&mut stream).await.metadata.response_code,
        ResponseCode::Refused
    );
    let mut invalid = query("example.com", RecordType::A);
    let mut edns = Edns::new();
    edns.set_version(1);
    invalid.edns = Some(edns);
    tcp_write(&mut stream, &invalid).await;
    let bad_version = tcp_read(&mut stream).await;
    // BADVERS and BADSIG share wire code 16; Hickory decodes it as BADSIG.
    assert_eq!(u16::from(bad_version.metadata.response_code), 16);
    assert_eq!(bad_version.edns.unwrap().version(), 0);
    drop(stream);
    cancellation.cancel();
    tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn encrypted_txt_resolves_through_real_dns_listeners() {
    let upstream_socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    let upstream_address = localhost(upstream_socket.local_addr().unwrap().port());
    let config = Config::parse(&format!(
        "[[upstreams]]\ntype='plain'\naddress='{upstream_address}'\n[[discovery]]\ndomain='example.com'\nkey='BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc'"
    )).unwrap();
    let now = SystemClock.now().unwrap();
    let value = encrypt(
        &Publication {
            issued_at: now,
            expires_at: now + 3600,
            entries: vec![Entry {
                subdomain: "nas".into(),
                value: Value::A("192.0.2.10".parse().unwrap()),
            }],
        },
        &config.policy.discovery()[0].key,
        &canonical_name("example.com").unwrap(),
    )
    .unwrap();
    let publisher = tokio::spawn(async move {
        let mut bytes = [0; 4096];
        let (len, peer) = upstream_socket.recv_from(&mut bytes).await.unwrap();
        let question = Message::from_vec(&bytes[..len]).unwrap();
        assert_eq!(
            question.queries,
            vec![Query::query(
                canonical_name("example.com").unwrap(),
                RecordType::TXT
            )]
        );
        let mut answer = response(&question);
        answer.answers.push(Record::from_rdata(
            canonical_name("example.com").unwrap(),
            60,
            RData::TXT(TXT::from_bytes(value.as_bytes().chunks(20).collect())),
        ));
        upstream_socket
            .send_to(&answer.to_vec().unwrap(), peer)
            .await
            .unwrap();
    });
    let forwarder = Arc::new(Forwarder::new(&config.upstreams, Duration::from_secs(2)).unwrap());
    let resolver = Arc::new(Resolver::new(config.policy, forwarder));
    let mut server = Server::new(Handler::new(resolver, 8, Duration::from_secs(3)));
    let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let address = localhost(listener.local_addr().unwrap().port());
    server.register_socket(
        UdpSocket::bind(SocketAddr::new(
            Ipv4Addr::UNSPECIFIED.into(),
            address.port(),
        ))
        .await
        .unwrap(),
    );
    server.register_listener(listener, Duration::from_secs(2), 8);
    let cancellation = server.shutdown_token().clone();
    let task = tokio::spawn(async move {
        server.block_until_done().await.unwrap();
    });
    let client = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    let question = query("nas.example.com", RecordType::A);
    client
        .send_to(&question.to_vec().unwrap(), address)
        .await
        .unwrap();
    let mut bytes = [0; 4096];
    let (len, _) = tokio::time::timeout(Duration::from_secs(4), client.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    let answer = Message::from_vec(&bytes[..len]).unwrap();
    assert_eq!(answer.metadata.response_code, ResponseCode::NoError);
    assert_eq!(
        answer.answers[0].data,
        RData::A(A("192.0.2.10".parse().unwrap()))
    );
    tokio::time::timeout(Duration::from_secs(5), publisher)
        .await
        .unwrap()
        .unwrap();
    let mut stream = TcpStream::connect(address).await.unwrap();
    tcp_write(&mut stream, &question).await;
    let cached = tcp_read(&mut stream).await;
    assert_eq!(cached.answers[0].data, answer.answers[0].data);
    assert!(!cached.metadata.authentic_data);
    drop(stream);
    cancellation.cancel();
    tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap();
}

struct BlockedUpstream {
    entered: tokio::sync::mpsc::UnboundedSender<String>,
    release: tokio::sync::Semaphore,
}

#[async_trait::async_trait]
impl Exchange for BlockedUpstream {
    async fn exchange(&self, query: Message) -> anyhow::Result<Message> {
        self.entered
            .send(query.queries[0].name().to_ascii())
            .unwrap();
        self.release.acquire().await.unwrap().forget();
        let mut answer = response(&query);
        answer.answers.push(Record::from_rdata(
            query.queries[0].name().clone(),
            60,
            RData::A(A("192.0.2.1".parse().unwrap())),
        ));
        Ok(answer)
    }
}

async fn guarded_listener(
    upstream: Arc<dyn Exchange>,
    request_timeout: Duration,
) -> (Server<Handler>, SocketAddr) {
    let config = Config::parse("").unwrap();
    let resolver = Arc::new(Resolver::new(config.policy, upstream));
    let mut server = Server::new(Handler::new(resolver, 1, request_timeout));
    let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let address = localhost(listener.local_addr().unwrap().port());
    server.register_listener(listener, Duration::from_secs(5), 8);
    (server, address)
}

#[tokio::test]
async fn unrepresentable_handler_deadline_does_not_panic() {
    let request_timeout = Duration::from_secs(u64::MAX);
    assert!(
        tokio::time::Instant::now()
            .checked_add(request_timeout)
            .is_none()
    );
    let (mut server, address) = guarded_listener(Arc::new(LargeAnswer), request_timeout).await;
    let mut stream = TcpStream::connect(address).await.unwrap();
    tcp_write(&mut stream, &query("large.test", RecordType::TXT)).await;
    let result = tcp_read(&mut stream).await;
    assert_eq!(result.metadata.response_code, ResponseCode::NoError);
    assert!(!result.answers.is_empty());
    drop(stream);
    tokio::time::timeout(Duration::from_secs(3), server.shutdown_gracefully())
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn overloaded_handler_rejects_only_excess_requests_and_recovers() {
    let (entered, mut calls) = tokio::sync::mpsc::unbounded_channel();
    let upstream = Arc::new(BlockedUpstream {
        entered,
        release: tokio::sync::Semaphore::new(0),
    });
    let (mut server, address) = guarded_listener(upstream.clone(), Duration::from_secs(5)).await;
    let mut first = TcpStream::connect(address).await.unwrap();
    tcp_write(&mut first, &query("first.test", RecordType::A)).await;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), calls.recv())
            .await
            .unwrap()
            .unwrap(),
        "first.test."
    );
    let mut second = TcpStream::connect(address).await.unwrap();
    tcp_write(&mut second, &query("second.test", RecordType::A)).await;
    assert_eq!(
        tcp_read(&mut second).await.metadata.response_code,
        ResponseCode::ServFail
    );
    assert!(
        calls.try_recv().is_err(),
        "overloaded request reached upstream"
    );
    upstream.release.add_permits(1);
    assert_eq!(
        tcp_read(&mut first).await.metadata.response_code,
        ResponseCode::NoError
    );
    upstream.release.add_permits(1);
    tcp_write(&mut second, &query("recovered.test", RecordType::A)).await;
    assert_eq!(tcp_read(&mut second).await.answers.len(), 1);
    drop(first);
    drop(second);
    tokio::time::timeout(Duration::from_secs(3), server.shutdown_gracefully())
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn handler_deadline_returns_servfail_and_releases_its_permit() {
    let (entered, mut calls) = tokio::sync::mpsc::unbounded_channel();
    let upstream = Arc::new(BlockedUpstream {
        entered,
        release: tokio::sync::Semaphore::new(0),
    });
    let (mut server, address) =
        guarded_listener(upstream.clone(), Duration::from_millis(100)).await;
    let mut stream = TcpStream::connect(address).await.unwrap();
    tcp_write(&mut stream, &query("slow.test", RecordType::A)).await;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), calls.recv())
            .await
            .unwrap()
            .unwrap(),
        "slow.test."
    );
    let failed = tcp_read(&mut stream).await;
    assert_eq!(failed.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(failed.metadata.id, 4242);
    assert!(failed.answers.is_empty());
    upstream.release.add_permits(1);
    tcp_write(&mut stream, &query("recovered.test", RecordType::A)).await;
    assert_eq!(tcp_read(&mut stream).await.answers.len(), 1);
    drop(stream);
    tokio::time::timeout(Duration::from_secs(3), server.shutdown_gracefully())
        .await
        .unwrap()
        .unwrap();
}
