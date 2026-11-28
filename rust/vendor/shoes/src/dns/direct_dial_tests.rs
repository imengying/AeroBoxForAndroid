use super::*;
use crate::{address::NetLocation, config};
use ::hickory_resolver::proto::{
    op::ResponseCode,
    rr::{RData, Record, RecordType, rdata::A},
};
use serde_json::json;
use std::{pin::Pin, sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadBuf};

#[tokio::test]
async fn outbound_connect_timeout_includes_proxy_handshake_and_releases_socket() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let resolver: Arc<dyn crate::resolver::Resolver> =
            Arc::new(crate::resolver::NativeResolver::new());
        let chain = crate::config::test_support::from_json::<config::ResolvedClientChain>(json!([{
            "address":endpoint.to_string(),
            "protocol":{"type":"socks"},
            "dial_options":{"connect_timeout":"50ms"}
        }]))
        .unwrap();
        let chain =
            crate::tcp::chain_builder::try_build_client_proxy_chain(chain.hops, resolver.clone())
                .unwrap();
        let target = NetLocation::from_str("192.0.2.1:443", None).unwrap();
        let connecting = chain.connect_tcp(target.into(), &resolver);
        let peer = async {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut hello = [0; 3];
            stream.read_exact(&mut hello).await.unwrap();
            assert_eq!(hello, [5, 1, 0]);
            assert_eq!(
                stream.read(&mut [0; 1]).await.unwrap(),
                0,
                "timed out handshake must close the carrier"
            );
        };
        let (result, ()) = tokio::join!(connecting, peer);
        assert_eq!(result.err().unwrap().kind(), std::io::ErrorKind::TimedOut);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn direct_outbound_uses_named_dns_for_tcp_and_udp_destinations() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let chosen = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let other = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let chosen_address = chosen.local_addr().unwrap();
        let other_address = other.local_addr().unwrap();
        let observed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let unexpected = observed.clone();
        let mut fixtures = tokio::task::JoinSet::new();
        fixtures.spawn(async move {
            let mut packet = [0; 4096];
            loop {
                let (length, peer) = chosen.recv_from(&mut packet).await.unwrap();
                let request = message::decode(&packet[..length]).unwrap();
                assert_eq!(request.queries[0].query_type, RecordType::A);
                assert!(matches!(request.queries[0].name.to_ascii().as_str(), "tcp-target.aerobox-test.example." | "udp-target.aerobox-test.example."));
                let mut reply = fake_ip::responder::response(&request, ResponseCode::NoError);
                reply.add_answer(Record::from_rdata(request.queries[0].name.clone(), 60, RData::A(A("127.0.0.1".parse().unwrap()))));
                chosen.send_to(&reply.to_vec().unwrap(), peer).await.unwrap();
            }
        });
        fixtures.spawn(async move {
            let mut packet = [0; 4096];
            loop {
                let (length, peer) = other.recv_from(&mut packet).await.unwrap();
                unexpected.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let request = message::decode(&packet[..length]).unwrap();
                let reply = fake_ip::responder::response(&request, ResponseCode::Refused);
                other.send_to(&reply.to_vec().unwrap(), peer).await.unwrap();
            }
        });
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tcp_port = tcp.local_addr().unwrap().port();
        let udp_port = udp.local_addr().unwrap().port();
        fixtures.spawn(async move {
            let (mut stream, _) = tcp.accept().await.unwrap();
            let request = stream.read_u8().await.unwrap();
            assert_eq!(request, 71);
            stream.write_u8(72).await.unwrap();
        });
        fixtures.spawn(async move {
            let mut packet = [0; 1];
            let (length, peer) = udp.recv_from(&mut packet).await.unwrap();
            assert_eq!((&packet[..length], length), (&[81][..], 1));
            udp.send_to(&[82], peer).await.unwrap();
        });
        let document = json!([
            {"dns_group":"chosen","dns_servers":[{"url":format!("udp://{chosen_address}"),"ip_strategy":"ipv4_only"}]},
            {"dns_group":"other","dns_servers":[{"url":format!("udp://{other_address}"),"ip_strategy":"ipv4_only"}]},
            {"client_group":"out","client_chain":{"protocol":{"type":"direct"},"domain_resolver":{"server":"chosen","ip_strategy":"ipv4_only"}}},
            {"address":"127.0.0.1:0","protocol":{"type":"socks"},"dns":{"servers":"other"},"rules":[{"conditions":{"any_destination":true},"client_chain":"out"}]}
        ]);
        let validated = config::create_server_configs(serde_json::from_value(document).unwrap()).unwrap();
        let mut registry = build_dns_registry(validated.dns_groups).await.unwrap();
        let config::ResolvedConfig::Server(server) = &validated.configs[0] else { panic!() };
        let resolver = registry.get_for_server(server.dns.as_ref());
        let config::ResolvedRuleActionConfig::Allow { client_chains, .. } = &server.rules.iter().next().unwrap().action else { panic!() };
        let chain = crate::tcp::chain_builder::try_build_client_proxy_chain(client_chains.iter().next().unwrap().hops.clone(), resolver.clone()).unwrap();
        let mut stream = chain.connect_tcp(NetLocation::from_str(&format!("tcp-target.aerobox-test.example:{tcp_port}"),None).unwrap().into(), &resolver).await.unwrap().client_stream;
        stream.write_u8(71).await.unwrap();
        assert_eq!(stream.read_u8().await.unwrap(),72);
        let mut datagrams = chain.connect_udp_bidirectional(&resolver, NetLocation::from_str(&format!("udp-target.aerobox-test.example:{udp_port}"),None).unwrap().into()).await.unwrap();
        futures::future::poll_fn(|cx| Pin::new(&mut *datagrams).poll_write_message(cx,&[81])).await.unwrap();
        let mut packet = [0; 16];
        let mut read = ReadBuf::new(&mut packet);
        futures::future::poll_fn(|cx| Pin::new(&mut *datagrams).poll_read_message(cx,&mut read)).await.unwrap();
        assert_eq!(read.filled(), &[82]);
        assert_eq!(observed.load(std::sync::atomic::Ordering::Relaxed),0,"the inbound resolver must not receive direct outbound questions");
        registry.retire_network();
        fixtures.abort_all();
        while fixtures.join_next().await.is_some() {}
    }).await.unwrap();
}
