use super::*;
use crate::config::tls::TlsClientOptions;
use hickory_resolver::proto::rr::{
    Record,
    rdata::{
        CNAME, HTTPS, SVCB,
        svcb::{EchConfigList, SvcParamKey},
    },
};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

fn list() -> Vec<u8> {
    let (key, _) = aerobox_crypto::hpke::ALL_SUPPORTED_SUITES[0]
        .generate_key_pair()
        .unwrap();
    let mut contents = vec![42, 0, 32];
    contents.extend_from_slice(&(key.0.len() as u16).to_be_bytes());
    contents.extend_from_slice(&key.0);
    contents.extend_from_slice(&[0, 4, 0, 1, 0, 1, 0, 11]);
    contents.extend_from_slice(b"public.test");
    contents.extend_from_slice(&[0, 0]);
    let mut encoded = ((contents.len() + 4) as u16).to_be_bytes().to_vec();
    encoded.extend_from_slice(&[0xfe, 0x0d]);
    encoded.extend_from_slice(&(contents.len() as u16).to_be_bytes());
    encoded.extend_from_slice(&contents);
    encoded
}
fn pem(bytes: &[u8]) -> String {
    format!(
        "-----BEGIN ECH CONFIGS-----\n{}\n-----END ECH CONFIGS-----\n",
        STANDARD.encode(bytes)
    )
}
fn binding(name: &str, ttl: u32, bytes: Vec<u8>) -> Record {
    Record::from_rdata(
        Name::from_ascii(name).unwrap(),
        ttl,
        RData::HTTPS(HTTPS(SVCB::new(
            1,
            Name::root(),
            vec![(
                SvcParamKey::EchConfigList,
                SvcParamValue::EchConfigList(EchConfigList(bytes)),
            )],
        ))),
    )
}
#[derive(Debug)]
struct Dns {
    calls: AtomicUsize,
    mode: AtomicUsize,
    blocked: AtomicBool,
    bytes: Vec<u8>,
    ttl: u32,
}
impl Dns {
    fn new(ttl: u32) -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
            mode: AtomicUsize::new(0),
            blocked: AtomicBool::new(false),
            bytes: list(),
            ttl,
        })
    }
}
impl Resolver for Dns {
    fn request_timeout(&self) -> Option<Duration> {
        Some(Duration::from_millis(100))
    }
    fn resolve_location(&self, _: &crate::address::NetLocation) -> crate::resolver::ResolveFuture {
        Box::pin(async { unreachable!() })
    }
    fn exchange(&self, raw: Vec<u8>) -> crate::resolver::DnsExchangeFuture {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut response = crate::dns::message::decode(&raw).unwrap();
        let name = response.queries[0].name().to_ascii();
        response.metadata.message_type = MessageType::Response;
        let mode = self.mode.load(Ordering::SeqCst);
        if mode != 1 {
            response.add_answer(binding(&name, self.ttl, self.bytes.clone()));
        }
        match mode {
            2 => response.metadata.id ^= 1,
            3 => response.metadata.truncation = true,
            4 => {
                response.metadata.response_code = ResponseCode::NXDomain;
            }
            5 => {
                response.queries.clear();
            }
            6 => response.answers[0].name = Name::from_ascii("unrelated.test").unwrap(),
            7 => response.metadata.message_type = MessageType::Query,
            8 => {
                response.answers = vec![binding(&name, self.ttl, vec![0, 0])];
            }
            9 => {
                response.answers = vec![
                    Record::from_rdata(
                        Name::from_ascii(&name).unwrap(),
                        2,
                        RData::CNAME(CNAME(Name::from_ascii("alias.test").unwrap())),
                    ),
                    binding("alias.test", 100, self.bytes.clone()),
                ];
            }
            10 => {
                response.answers = vec![Record::from_rdata(
                    Name::from_ascii(&name).unwrap(),
                    2,
                    RData::CNAME(CNAME(Name::from_ascii(&name).unwrap())),
                )];
            }
            11 => {
                response.answers = if name.starts_with("secret.") {
                    vec![Record::from_rdata(
                        Name::from_ascii(&name).unwrap(),
                        2,
                        RData::HTTPS(HTTPS(SVCB::new(
                            0,
                            Name::from_ascii("alias.test").unwrap(),
                            vec![],
                        ))),
                    )]
                } else {
                    vec![binding(&name, 100, self.bytes.clone())]
                };
            }
            _ => {}
        }
        let block = self.blocked.load(Ordering::SeqCst);
        Box::pin(async move {
            if block {
                std::future::pending::<()>().await;
            }
            tokio::task::yield_now().await;
            response.to_vec().map_err(io::Error::other)
        })
    }
}
fn policy() -> Arc<Policy> {
    Policy::new(&EchOptions::default(), &"secret.test".try_into().unwrap()).unwrap()
}

#[test]
fn pem_files_and_list_bounds_are_validated_at_load() {
    let bytes = list();
    parse_list(&bytes).unwrap();
    parse_pem(&pem(&bytes)).unwrap();
    for bad in [
        "".to_owned(),
        "dGVzdA==".into(),
        pem(&bytes).replace("ECH CONFIGS", "CERTIFICATE"),
        format!("{}{}", pem(&bytes), pem(&bytes)),
        format!("{}trailing", pem(&bytes)),
        "a".repeat(MAX_PEM + 1),
    ] {
        assert!(parse_pem(&bad).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(parse_list(&trailing).is_err());
    for prefix in 0..bytes.len() {
        assert!(parse_list(&bytes[..prefix]).is_err());
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ech.pem");
    std::fs::write(&path, pem(&bytes)).unwrap();
    let mut opts = EchOptions {
        config_path: Some(path.to_str().unwrap().into()),
        ..Default::default()
    };
    opts.embed().unwrap();
    std::fs::remove_file(path).unwrap();
    opts.static_config().unwrap().unwrap();
    assert!(opts.config_path.is_none());
    let mut inline = EchOptions {
        config: Some(pem(&bytes)),
        config_path: Some("/does/not/exist".into()),
        ..Default::default()
    };
    inline.embed().unwrap();
}

#[test]
fn ech_requires_dns_identity_sni_and_tls13() {
    assert!(Policy::new(&Default::default(), &"127.0.0.1".try_into().unwrap()).is_err());
    for options in [
        TlsClientOptions {
            disable_sni: true,
            ech: Some(Default::default()),
            ..Default::default()
        },
        TlsClientOptions {
            max_version: Some(crate::config::tls::TlsVersion::V12),
            ech: Some(Default::default()),
            ..Default::default()
        },
    ] {
        assert!(
            crate::rustls_config_util::try_create_client_config_with_options(
                true,
                vec![],
                vec![],
                true,
                None,
                false,
                &Default::default(),
                &options
            )
            .is_err()
        );
    }
}

#[tokio::test(start_paused = true)]
async fn dns_singleflight_ttl_and_expired_failures_never_fall_back() {
    let dns = Dns::new(2);
    let resolver: Arc<dyn Resolver> = dns.clone();
    let p = policy();
    let results = futures::future::join_all((0..16).map(|_| p.mode(&resolver))).await;
    assert!(results.iter().all(Result::is_ok));
    assert_eq!(dns.calls.load(Ordering::SeqCst), 1);
    tokio::time::advance(Duration::from_secs(3)).await;
    dns.mode.store(1, Ordering::SeqCst);
    assert!(p.mode(&resolver).await.is_err());
    dns.mode.store(0, Ordering::SeqCst);
    p.mode(&resolver).await.unwrap();
    assert_eq!(dns.calls.load(Ordering::SeqCst), 3);
    let zero = Dns::new(0);
    let resolver: Arc<dyn Resolver> = zero.clone();
    let p = policy();
    p.mode(&resolver).await.unwrap();
    p.mode(&resolver).await.unwrap();
    assert_eq!(zero.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test(start_paused = true)]
async fn dns_aliases_bound_ttl_and_reject_mismatched_or_malformed_answers() {
    for mode in 1..=8 {
        let dns = Dns::new(10);
        dns.mode.store(mode, Ordering::SeqCst);
        let resolver: Arc<dyn Resolver> = dns;
        assert!(policy().mode(&resolver).await.is_err(), "mode {mode}");
    }
    for mode in [9, 11] {
        let dns = Dns::new(100);
        dns.mode.store(mode, Ordering::SeqCst);
        let resolver: Arc<dyn Resolver> = dns.clone();
        let p = policy();
        p.mode(&resolver).await.unwrap();
        let calls = dns.calls.load(Ordering::SeqCst);
        tokio::time::advance(Duration::from_secs(3)).await;
        p.mode(&resolver).await.unwrap();
        assert_eq!(dns.calls.load(Ordering::SeqCst), calls * 2);
    }
    let dns = Dns::new(10);
    dns.mode.store(10, Ordering::SeqCst);
    let resolver: Arc<dyn Resolver> = dns;
    assert!(policy().mode(&resolver).await.is_err());
}

#[tokio::test]
async fn cancelled_dns_releases_singleflight_and_allows_next_caller() {
    let dns = Dns::new(10);
    dns.blocked.store(true, Ordering::SeqCst);
    let resolver: Arc<dyn Resolver> = dns.clone();
    let p = policy();
    let task = tokio::spawn({
        let p = p.clone();
        let resolver = resolver.clone();
        async move { p.mode(&resolver).await }
    });
    while dns.calls.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    dns.blocked.store(false, Ordering::SeqCst);
    tokio::time::timeout(Duration::from_secs(1), p.mode(&resolver))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(dns.calls.load(Ordering::SeqCst), 2);
}

mod interop;
mod configuration;

#[tokio::test]
async fn ech_reconnect_does_not_add_udp_capability() {
    use crate::tcp::proxy_connector::ProxyConnector;
    use serde_json::json;
    for (inner, udp) in [
        (json!({"type":"noop"}), false),
        (json!({"type":"http"}), false),
        (
            json!({"type":"vless","user_id":"01010101-0101-4101-8101-010101010101"}),
            true,
        ),
    ] {
        let input = json!({"address":"secret.test:443","protocol":{"type":"tls","options":{"ech":{}},"protocol":inner}});
        let config = crate::config::test_support::from_json(input).unwrap();
        let client = crate::tcp::proxy_connector_impl::ProxyConnectorImpl::from_config(
            config,
            Arc::new(crate::resolver::NativeResolver::new()),
        )
        .unwrap()
        .unwrap();
        assert!(client.needs_carrier_dialer());
        assert_eq!(client.supports_udp(), udp);
    }
}

#[tokio::test(start_paused = true)]
async fn dns_deadline_includes_waiting_for_singleflight_lock() {
    let dns = Dns::new(60);
    let resolver: Arc<dyn Resolver> = dns.clone();
    let p = policy();
    let guard = p.cache.lock().await;
    let start = Instant::now();
    let error = p.mode(&resolver).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(Instant::now() - start, Duration::from_millis(100));
    assert_eq!(dns.calls.load(Ordering::SeqCst), 0);
    drop(guard);
    p.mode(&resolver).await.unwrap();
}
#[tokio::test(start_paused = true)]
async fn authenticated_retry_cache_preserves_ttl_and_cannot_overwrite_a_refresh() {
    let dns = Dns::new(2);
    let resolver: Arc<dyn Resolver> = dns.clone();
    let p = policy();
    let first = p.mode(&resolver).await.unwrap();
    let replacement = Arc::new(parse_list(&list()).unwrap());
    p.accepted_retry(&first, replacement.clone());
    assert!(Arc::ptr_eq(&replacement, &p.mode(&resolver).await.unwrap()));
    tokio::time::advance(Duration::from_secs(3)).await;
    let latest = p.mode(&resolver).await.unwrap();
    assert!(!Arc::ptr_eq(&replacement, &latest));
    p.accepted_retry(&replacement, first.clone());
    assert!(Arc::ptr_eq(&latest, &p.mode(&resolver).await.unwrap()));
    assert_eq!(dns.calls.load(Ordering::SeqCst), 2);
    let p = Policy::new(
        &EchOptions {
            config: Some(pem(&list())),
            ..Default::default()
        },
        &"secret.test".try_into().unwrap(),
    )
    .unwrap();
    let initial = p.mode(&resolver).await.unwrap();
    p.accepted_retry(&initial, replacement.clone());
    assert!(Arc::ptr_eq(&replacement, &p.mode(&resolver).await.unwrap()));
}
