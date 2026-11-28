use super::*;
use crate::{address::NetLocation, config, resolver::Resolver};
use ::hickory_resolver::proto::{
    op::{Message, Query},
    rr::{Name, RecordType},
};
use serde_json::json;

fn request(name: &str, kind: RecordType) -> Vec<u8> {
    let mut message = Message::query();
    message.metadata.id = 901;
    message.add_query(Query::query(Name::from_ascii(name).unwrap(), kind));
    message.to_vec().unwrap()
}
fn policy() -> serde_json::Value {
    json!([
        {"dns_group":"direct-dns","hosts":{"proxy.example":"192.0.2.10","www.local":"192.0.2.11","cn.example":"192.0.2.12"},"dns_servers":"system"},
        {"dns_group":"remote-dns","hosts":{"www.example":["192.0.2.20","2001:db8::20"]},"dns_servers":"system"},
        {"rule_source_group":"cn","rules":[{"domain":["cn.example"]}]},
        {"dns_group":"policy","fake_ip":{"ipv4_range":"198.18.0.0/15","missing_family":"nodata"},"routing":{"final_server":"remote-dns","ip_strategy":"ipv6_then_ipv4","rules":[
            {"conditions":{"domain":["proxy.example"]},"server":"direct-dns"},
            {"conditions":{"rule_source_group":"cn"},"server":"direct-dns"},
            {"conditions":{"domain_suffix":["local"]},"server":"direct-dns"},
            {"conditions":{"any_destination":true},"query_types":[1,28],"fake_ip":true},
            {"conditions":{"any_destination":true},"query_types":[64,65],"rcode":0}
        ]}},
        {"address":"127.0.0.1:1080","protocol":{"type":"socks"},"dns":{"servers":"policy"}}
    ])
}
#[tokio::test]
async fn ordered_dns_rules_reuse_rule_sources_keep_fake_answers_out_of_real_resolution() {
    let validated =
        config::create_server_configs(serde_json::from_value(policy()).unwrap()).unwrap();
    let mut registry = build_dns_registry(validated.dns_groups).await.unwrap();
    let resolver = registry.get_by_name("policy").unwrap();
    let context = resolver.fake_dns_context().unwrap();
    for (name, expected) in [
        ("proxy.example", "192.0.2.10"),
        ("cn.example", "192.0.2.12"),
        ("www.local", "192.0.2.11"),
    ] {
        let reply = context
            .exchange(request(name, RecordType::A), false)
            .await
            .unwrap()
            .unwrap();
        let answer = message::decode(&reply).unwrap();
        assert_eq!(
            message::addresses(&answer).next().unwrap().to_string(),
            expected
        );
    }
    let reply = context
        .exchange(request("www.example", RecordType::A), false)
        .await
        .unwrap()
        .unwrap();
    let answer = message::decode(&reply).unwrap();
    let fake = message::addresses(&answer).next().unwrap();
    assert!(context.contains(fake));
    assert_eq!(
        context.restore(fake).unwrap().as_deref(),
        Some("www.example")
    );
    let addresses = resolver
        .resolve_location(&NetLocation::from_str("www.example:443", None).unwrap())
        .await
        .unwrap();
    assert_eq!(addresses[0].ip().to_string(), "2001:db8::20");
    assert!(
        addresses
            .iter()
            .all(|address| !context.contains(address.ip()))
    );
    for kind in [RecordType::HTTPS, RecordType::SVCB] {
        let reply = context
            .exchange(request("www.example", kind), false)
            .await
            .unwrap()
            .unwrap();
        let answer = message::decode(&reply).unwrap();
        assert!(answer.answers.is_empty());
        assert_eq!(
            answer.metadata.response_code,
            ::hickory_resolver::proto::op::ResponseCode::NoError
        );
    }
    assert!(
        registry
            .get_or_create_default()
            .named("direct-dns")
            .is_some()
    );
}
#[test]
fn dns_dependency_cycles_include_proxy_entrance_resolvers() {
    for doc in [
        json!([{ "dns_group":"loop","routing":{"final_server":"loop"}}]),
        json!([
            {"client_group":"proxy","client_chain":{"address":"proxy.example:1080","domain_resolver":{"server":"remote"},"protocol":{"type":"socks"}}},
            {"dns_group":"remote","dns_servers":[{"url":"tcp://192.0.2.53","client_chain":"proxy"}]}
        ]),
        json!([{ "dns_group":"policy","routing":{"final_server":"unknown"}}]),
        json!([{ "dns_group":"real","dns_servers":"system"},{"dns_group":"bad","routing":{"final_server":"real","rules":[{"conditions":{"ip_cidr":["192.0.2.0/24"]},"server":"real"}]}}]),
    ] {
        assert!(config::create_server_configs(serde_json::from_value(doc).unwrap()).is_err());
    }
}
#[tokio::test]
async fn proxy_entrance_uses_named_resolver_without_resolving_destination() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let document = json!([
        {"dns_group":"entrance","hosts":{"proxy.invalid":"127.0.0.1"},"dns_servers":"system"},
        {"dns_group":"destination","hosts":{"proxy.invalid":"192.0.2.99"},"dns_servers":"system"},
        {"client_group":"out","client_chain":{"address":format!("proxy.invalid:{}",endpoint.port()),"domain_resolver":{"server":"entrance","ip_strategy":"ipv4_only"},"protocol":{"type":"socks"}}},
        {"address":"127.0.0.1:0","protocol":{"type":"socks"},"dns":{"servers":"destination"},"rules":[{"conditions":{"any_destination":true},"client_chain":"out"}]}
    ]);
    let validated =
        config::create_server_configs(serde_json::from_value(document).unwrap()).unwrap();
    let mut registry = build_dns_registry(validated.dns_groups).await.unwrap();
    let config::ResolvedConfig::Server(inbound) = &validated.configs[0] else {
        panic!()
    };
    let resolver = registry.get_for_server(inbound.dns.as_ref());
    let config::ResolvedRuleActionConfig::Allow { client_chains, .. } =
        &inbound.rules.iter().next().unwrap().action
    else {
        panic!()
    };
    let chain = crate::tcp::chain_builder::try_build_client_proxy_chain(
        client_chains.iter().next().unwrap().hops.clone(),
        resolver.clone(),
    )
    .unwrap();
    let server = async {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut hello = [0; 3];
        stream.read_exact(&mut hello).await.unwrap();
        stream.write_all(&[5, 0]).await.unwrap();
        let mut header = [0; 3];
        stream.read_exact(&mut header).await.unwrap();
        let target = crate::socks_handler::read_location_direct(&mut stream)
            .await
            .unwrap();
        assert_eq!(target.to_string(), "unresolved.destination.invalid:443");
        stream
            .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
    };
    let client = chain.connect_tcp(
        NetLocation::from_str("unresolved.destination.invalid:443", None)
            .unwrap()
            .into(),
        &resolver,
    );
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        let (client, _) = tokio::join!(client, server);
        client.unwrap();
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn udp_dns_detour_reaches_upstream_through_socks() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let socks = listener.local_addr().unwrap();
    drop(listener);
    let core = crate::embedding::EmbeddedCore::start_json(
        &json!([{"address":socks.to_string(),"protocol":{"type":"socks"}}]).to_string(),
        None,
    )
    .await
    .unwrap();
    let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = upstream.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut bytes = vec![0; 4096];
        let (length, peer) = upstream.recv_from(&mut bytes).await.unwrap();
        let query = message::decode(&bytes[..length]).unwrap();
        let mut reply = super::fake_ip::responder::response(
            &query,
            ::hickory_resolver::proto::op::ResponseCode::NoError,
        );
        reply.add_answer(::hickory_resolver::proto::rr::Record::from_rdata(
            query.queries[0].name.clone(),
            30,
            ::hickory_resolver::proto::rr::RData::A(::hickory_resolver::proto::rr::rdata::A(
                "192.0.2.99".parse().unwrap(),
            )),
        ));
        upstream
            .send_to(&reply.to_vec().unwrap(), peer)
            .await
            .unwrap();
    });
    let document = json!([
        {"client_group":"proxy","client_chain":{"address":socks.to_string(),"protocol":{"type":"socks"}}},
        {"dns_group":"remote","dns_servers":[{"url":format!("udp://{endpoint}"),"client_chain":"proxy"}]}
    ]);
    let validated =
        config::create_server_configs(serde_json::from_value(document).unwrap()).unwrap();
    let registry = build_dns_registry(validated.dns_groups).await.unwrap();
    let resolver = registry.get_by_name("remote").unwrap();
    let reply = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        resolver.exchange(request("dns.example", RecordType::A)),
    )
    .await
    .unwrap()
    .unwrap();
    let reply = message::decode(&reply).unwrap();
    assert_eq!(
        message::addresses(&reply).next().unwrap().to_string(),
        "192.0.2.99"
    );
    task.await.unwrap();
    resolver.retire();
    drop(resolver);
    drop(registry);
    core.shutdown().await.unwrap();
}

#[tokio::test]
async fn doq_validates_tls_and_exchanges_dns_direct_and_through_socks_udp() {
    use ::hickory_resolver::config::{
        ConnectionConfig, LookupIpStrategy, NameServerConfig, ResolverConfig,
    };
    use std::{sync::Arc, time::Duration};
    for proxied in [false, true] {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let mut tls =
            rustls::ServerConfig::builder_with_provider(Arc::new(aerobox_crypto::provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert.cert.der().clone()],
                    rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())
                        .into(),
                )
                .unwrap();
        tls.alpn_protocols = vec![b"doq".to_vec()];
        let server = quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(
                quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap(),
            )),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let endpoint = server.local_addr().unwrap();
        let socks = if proxied {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            drop(listener);
            let core = crate::embedding::EmbeddedCore::start_json(
                &json!([
                    {"address":address.to_string(),"protocol":{"type":"socks"}}
                ])
                .to_string(),
                None,
            )
            .await
            .unwrap();
            Some((address, core))
        } else {
            None
        };
        let bootstrap: Arc<dyn crate::resolver::Resolver> =
            Arc::new(crate::resolver::NativeResolver::new());
        let chain = match &socks {
            Some((address, _)) => crate::tcp::chain_builder::build_client_chain_group_with_limits(
                crate::option_util::NoneOrSome::One(
                    crate::config::test_support::from_json(
                        json!({"address":address.to_string(),"protocol":{"type":"socks"}}),
                    )
                    .unwrap(),
                ),
                bootstrap.clone(),
                Default::default(),
            )
            .unwrap(),
            None => crate::tcp::chain_builder::build_direct_chain_group(bootstrap.clone()),
        };
        let provider = super::proxy_runtime::ProxyRuntimeProvider::with_bootstrap(
            Arc::new(chain),
            bootstrap,
            Duration::from_secs(3),
        );
        let mut connection = ConnectionConfig::quic(Arc::from("localhost"));
        connection.port = endpoint.port();
        let config = ResolverConfig::from_parts(
            None,
            vec![],
            vec![NameServerConfig::new(endpoint.ip(), true, vec![connection])],
        );
        let mut builder =
            ::hickory_resolver::Resolver::builder_with_config(config, provider.clone());
        builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4Only;
        builder.options_mut().attempts = 1;
        builder.options_mut().timeout = Duration::from_secs(3);
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(aerobox_crypto::provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let resolver = builder.with_tls_config(tls).build().unwrap();
        let serve = async {
            let peer = server.accept().await.unwrap().await.unwrap();
            let (mut send, mut receive) = peer.accept_bi().await.unwrap();
            let mut length = [0; 2];
            receive.read_exact(&mut length).await.unwrap();
            let mut bytes = vec![0; u16::from_be_bytes(length).into()];
            receive.read_exact(&mut bytes).await.unwrap();
            let query = message::decode(&bytes).unwrap();
            assert_eq!(query.metadata.id, 0);
            assert_eq!(query.queries[0].name.to_ascii(), "dns.example.");
            let mut response = super::fake_ip::responder::response(
                &query,
                ::hickory_resolver::proto::op::ResponseCode::NoError,
            );
            response.add_answer(::hickory_resolver::proto::rr::Record::from_rdata(
                query.queries[0].name.clone(),
                30,
                ::hickory_resolver::proto::rr::RData::A(::hickory_resolver::proto::rr::rdata::A(
                    "192.0.2.77".parse().unwrap(),
                )),
            ));
            let bytes = response.to_vec().unwrap();
            send.write_all(&(bytes.len() as u16).to_be_bytes())
                .await
                .unwrap();
            send.write_all(&bytes).await.unwrap();
            send.finish().unwrap();
            let _ = send.stopped().await;
        };
        let lookup = async {
            let addresses = resolver.lookup_ip("dns.example.").await.unwrap();
            assert_eq!(addresses.iter().next().unwrap().to_string(), "192.0.2.77");
        };
        tokio::time::timeout(Duration::from_secs(8), async {
            tokio::join!(serve, lookup);
        })
        .await
        .unwrap();
        provider.retire();
        drop(resolver);
        server.close(0u32.into(), b"done");
        if let Some((_, core)) = socks {
            core.shutdown().await.unwrap();
        }
    }
}
