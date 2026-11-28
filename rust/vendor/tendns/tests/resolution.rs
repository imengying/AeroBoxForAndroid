#[path = "resolution/cache.rs"]
mod cache;
#[path = "resolution/lookup.rs"]
mod lookup;

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use anyhow::{Context, Result};
use async_trait::async_trait;
use hickory_proto::{
    op::{Message, OpCode, Query, ResponseCode},
    rr::{
        Name, RData, Record, RecordType,
        rdata::{A, CNAME, SOA, TXT},
    },
};
use tendns::{
    names::canonical_name,
    policy::{Discovery, Policy},
    protocol::{Entry, Publication, Secret, Value, encrypt},
    resolver::{Clock, Resolver},
    upstream::Exchange,
};

const KEY: &str = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc";

#[derive(Default)]
struct Mock {
    replies: Mutex<HashMap<(Name, RecordType), Message>>,
    calls: Mutex<Vec<(Name, RecordType)>>,
    gate: Mutex<Option<Arc<tokio::sync::Semaphore>>>,
    deadlines: Mutex<Vec<tokio::time::Instant>>,
}

impl Mock {
    fn set(&self, owner: &str, kind: RecordType, message: Message) {
        self.replies
            .lock()
            .unwrap()
            .insert((canonical_name(owner).unwrap(), kind), message);
    }

    fn calls(&self) -> Vec<(String, RecordType)> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .map(|(name, kind)| (name.to_ascii(), *kind))
            .collect()
    }
}

#[async_trait]
impl Exchange for Mock {
    async fn exchange_with_deadline(
        &self,
        query: Message,
        deadline: tokio::time::Instant,
    ) -> Result<Message> {
        self.deadlines.lock().unwrap().push(deadline);
        self.exchange(query).await
    }

    async fn exchange(&self, query: Message) -> Result<Message> {
        let key = (
            query.queries[0].name().clone(),
            query.queries[0].query_type(),
        );
        self.calls.lock().unwrap().push(key.clone());
        let gate = self.gate.lock().unwrap().clone();
        if let Some(gate) = gate {
            gate.acquire_owned().await?.forget();
        }
        self.replies
            .lock()
            .unwrap()
            .get(&key)
            .cloned()
            .context("mock upstream failure")
    }
}

struct FakeClock(AtomicU64);
impl Clock for FakeClock {
    fn now(&self) -> Result<u64> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

fn discovery(domain: &str, key: &str) -> Discovery {
    Discovery {
        domain: canonical_name(domain).unwrap(),
        key: Arc::new(Secret::decode(key).unwrap()),
    }
}

fn config() -> Arc<Policy> {
    Arc::new(
        Policy::new(
            vec![discovery("example.com", KEY)],
            vec![canonical_name("hex.test").unwrap()],
            60,
            1024,
        )
        .unwrap(),
    )
}

fn query(name: &str, kind: RecordType) -> Message {
    let mut message = Message::query();
    message.metadata.id = 1234;
    message.metadata.recursion_desired = true;
    message
        .queries
        .push(Query::query(canonical_name(name).unwrap(), kind));
    message
}

fn reply() -> Message {
    Message::response(0, OpCode::Query)
}

fn entry(label: &str, ip: &str) -> Entry {
    Entry {
        subdomain: label.into(),
        value: Value::A(ip.parse().unwrap()),
    }
}

fn publication(entries: Vec<Entry>, issued_at: u64) -> Publication {
    Publication {
        issued_at,
        expires_at: issued_at + 100,
        entries,
    }
}

fn txt(config: &Policy, owner: &str, publication: &Publication, ttl: u32) -> Record {
    let name = canonical_name(owner).unwrap();
    let encoded = encrypt(
        publication,
        &config.discovery_for(&name).unwrap().key,
        &name,
    )
    .unwrap();
    // Providers may split at any character boundary, even inside the prefix.
    Record::from_rdata(
        name,
        ttl,
        RData::TXT(TXT::from_bytes(encoded.as_bytes().chunks(3).collect())),
    )
}

fn setup() -> (Arc<Policy>, Arc<Mock>, Arc<FakeClock>, Resolver) {
    let config = config();
    let mock = Arc::new(Mock::default());
    let clock = Arc::new(FakeClock(AtomicU64::new(100)));
    let resolver = Resolver::with_clock(config.clone(), mock.clone(), clock.clone());
    (config, mock, clock, resolver)
}

async fn assert_pending<F: std::future::Future>(mut future: std::pin::Pin<&mut F>) {
    std::future::poll_fn(|cx| {
        assert!(future.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
}

#[tokio::test]
async fn parent_first_hidden_names_and_type_precedence() {
    let (config, mock, _, resolver) = setup();
    let mut parent = reply();
    parent.answers.push(txt(
        &config,
        "example.com",
        &publication(vec![entry("nas", "192.0.2.1")], 100),
        60,
    ));
    parent.metadata.authentic_data = true;
    mock.set("example.com", RecordType::TXT, parent);
    let mut direct = reply();
    direct.answers.push(txt(
        &config,
        "nas.example.com",
        &publication(vec![entry("", "192.0.2.2")], 100),
        60,
    ));
    mock.set("nas.example.com", RecordType::TXT, direct);
    let mut question = query("nas.example.com", RecordType::A);
    question.queries[0].set_name(Name::from_ascii("NaS.Example.COM.").unwrap());
    let result = resolver.answer(question.clone()).await.unwrap();
    assert_eq!(
        result.queries[0].name().to_ascii(),
        question.queries[0].name().to_ascii()
    );
    assert_eq!(
        result.answers[0].data,
        RData::A(A("192.0.2.1".parse().unwrap()))
    );
    assert_eq!(result.answers[0].name.to_ascii(), "nas.example.com.");
    assert!(!result.metadata.authentic_data);
    assert!(!result.metadata.authoritative);
    assert!(result.metadata.recursion_available);
    let result = resolver
        .answer(query("nas.example.com", RecordType::AAAA))
        .await
        .unwrap();
    assert!(result.answers.is_empty());
    assert_eq!(result.metadata.response_code, ResponseCode::NoError);
    assert_eq!(mock.calls(), vec![("example.com.".into(), RecordType::TXT)]);
}

#[tokio::test]
async fn confirmed_miss_tries_direct_only_then_nxdomain() {
    let (config, mock, _, resolver) = setup();
    let mut parent = reply();
    parent.answers.push(txt(
        &config,
        "example.com",
        &publication(vec![entry("other", "192.0.2.1")], 100),
        60,
    ));
    mock.set("example.com", RecordType::TXT, parent);
    let mut direct = reply();
    direct.answers.push(txt(
        &config,
        "nas.example.com",
        &publication(vec![entry("", "192.0.2.2")], 100),
        60,
    ));
    mock.set("nas.example.com", RecordType::TXT, direct);
    let result = resolver
        .answer(query("nas.example.com", RecordType::A))
        .await
        .unwrap();
    assert_eq!(
        result.answers[0].data,
        RData::A(A("192.0.2.2".parse().unwrap()))
    );
    assert_eq!(
        mock.calls(),
        vec![
            ("example.com.".into(), RecordType::TXT),
            ("nas.example.com.".into(), RecordType::TXT)
        ]
    );
    mock.set("missing.example.com", RecordType::TXT, reply());
    let result = resolver
        .answer(query("missing.example.com", RecordType::A))
        .await
        .unwrap();
    assert_eq!(result.metadata.response_code, ResponseCode::NXDomain);
    assert!(
        mock.calls()
            .iter()
            .all(|(_, kind)| *kind == RecordType::TXT)
    );
}

#[tokio::test]
async fn parent_errors_never_leak_child_queries() {
    for invalid in [
        None,
        Some("td1.invalid"),
        Some("td2.unsupported"),
        Some("td10.unsupported"),
        Some("td1"),
    ] {
        let (_, mock, _, resolver) = setup();
        if let Some(value) = invalid {
            let mut parent = reply();
            parent.answers.push(Record::from_rdata(
                canonical_name("example.com").unwrap(),
                60,
                RData::TXT(TXT::new(vec![value.into()])),
            ));
            mock.set("example.com", RecordType::TXT, parent);
        }
        assert!(
            resolver
                .answer(query("secret.example.com", RecordType::A))
                .await
                .is_err()
        );
        assert_eq!(mock.calls(), vec![("example.com.".into(), RecordType::TXT)]);
    }
}

#[tokio::test]
async fn split_txt_values_combine_independent_entries_and_reject_alias_conflicts() {
    let (config, mock, _, resolver) = setup();
    let mut answer = reply();
    answer.answers.push(txt(
        &config,
        "example.com",
        &publication(vec![entry("", "192.0.2.1")], 90),
        60,
    ));
    answer.answers.push(txt(
        &config,
        "example.com",
        &publication(vec![entry("", "192.0.2.2")], 100),
        60,
    ));
    answer.answers.push(txt(
        &config,
        "example.com",
        &publication(
            vec![Entry {
                subdomain: String::new(),
                value: Value::Aaaa("2001:db8::1".parse().unwrap()),
            }],
            100,
        ),
        60,
    ));
    answer.answers.push(answer.answers[1].clone());
    mock.set("example.com", RecordType::TXT, answer.clone());
    let result = resolver
        .answer(query("example.com", RecordType::A))
        .await
        .unwrap();
    assert_eq!(result.answers.len(), 2);
    assert_eq!(
        result.answers[0].data,
        RData::A(A("192.0.2.1".parse().unwrap()))
    );
    assert_eq!(
        result.answers[1].data,
        RData::A(A("192.0.2.2".parse().unwrap()))
    );
    let ipv6 = resolver
        .answer(query("example.com", RecordType::AAAA))
        .await
        .unwrap();
    assert_eq!(ipv6.answers.len(), 1);
    assert!(matches!(ipv6.answers[0].data, RData::AAAA(_)));
    answer.answers.push(txt(
        &config,
        "example.com",
        &publication(
            vec![Entry {
                subdomain: String::new(),
                value: Value::Cname(canonical_name("target.net").unwrap()),
            }],
            100,
        ),
        60,
    ));
    mock.set("example.com", RecordType::TXT, answer);
    let resolver = Resolver::with_clock(config, mock, Arc::new(FakeClock(AtomicU64::new(100))));
    assert!(
        resolver
            .answer(query("example.com", RecordType::A))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn invalid_sibling_value_is_not_a_confirmed_hidden_name_miss() {
    let (config, mock, _, resolver) = setup();
    let mut answer = reply();
    answer.answers.push(txt(
        &config,
        "example.com",
        &publication(vec![entry("public", "192.0.2.1")], 100),
        60,
    ));
    answer.answers.push(Record::from_rdata(
        canonical_name("example.com").unwrap(),
        60,
        RData::TXT(TXT::new(vec!["td1.invalid".into()])),
    ));
    mock.set("example.com", RecordType::TXT, answer);
    assert!(
        resolver
            .answer(query("secret.example.com", RecordType::A))
            .await
            .is_err()
    );
    assert_eq!(mock.calls(), vec![("example.com.".into(), RecordType::TXT)]);
}

#[tokio::test]
async fn cname_chain_loop_and_txt_indirection() {
    let (config, mock, _, resolver) = setup();
    let mut answer = reply();
    let alias = Entry {
        subdomain: "www".into(),
        value: Value::Cname(canonical_name("nas.example.com").unwrap()),
    };
    answer.answers.push(txt(
        &config,
        "example.com",
        &publication(vec![alias, entry("nas", "192.0.2.1")], 100),
        60,
    ));
    mock.set("example.com", RecordType::TXT, answer);
    let result = resolver
        .answer(query("www.example.com", RecordType::A))
        .await
        .unwrap();
    assert_eq!(result.answers.len(), 2);
    assert!(matches!(result.answers[0].data, RData::CNAME(_)));
    assert!(matches!(result.answers[1].data, RData::A(_)));
    assert_eq!(
        resolver
            .answer(query("www.example.com", RecordType::CNAME))
            .await
            .unwrap()
            .answers
            .len(),
        1
    );
    let mut answer = reply();
    let alias = Entry {
        subdomain: "www".into(),
        value: Value::Cname(canonical_name("www.example.com").unwrap()),
    };
    answer.answers.push(txt(
        &config,
        "example.com",
        &publication(vec![alias], 100),
        60,
    ));
    mock.set("example.com", RecordType::TXT, answer);
    let resolver = Resolver::with_clock(
        config.clone(),
        mock.clone(),
        Arc::new(FakeClock(AtomicU64::new(100))),
    );
    assert!(
        resolver
            .answer(query("www.example.com", RecordType::A))
            .await
            .is_err()
    );
    let mut answer = reply();
    answer.answers.push(Record::from_rdata(
        canonical_name("example.com").unwrap(),
        60,
        RData::CNAME(CNAME(canonical_name("elsewhere.com").unwrap())),
    ));
    mock.set("example.com", RecordType::TXT, answer);
    let resolver = Resolver::with_clock(config, mock, Arc::new(FakeClock(AtomicU64::new(100))));
    assert!(
        resolver
            .answer(query("example.com", RecordType::A))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn programmatic_private_questions_normalize_relative_names() {
    let (config, mock, _, resolver) = setup();
    let mut parent = reply();
    parent.answers.push(txt(
        &config,
        "example.com",
        &publication(vec![entry("nas", "192.0.2.1")], 100),
        60,
    ));
    mock.set("example.com", RecordType::TXT, parent);
    let mut direct = reply();
    direct.answers.push(txt(
        &config,
        "direct.example.com",
        &publication(vec![entry("", "192.0.2.1")], 100),
        60,
    ));
    mock.set("direct.example.com", RecordType::TXT, direct);
    for owner in ["NAS.EXAMPLE.COM", "DIRECT.EXAMPLE.COM"] {
        for with_deadline in [false, true] {
            let mut request = Message::query();
            request.queries.push(Query::query(
                Name::from_ascii(owner).unwrap(),
                RecordType::A,
            ));
            let result = if with_deadline {
                resolver
                    .answer_with_deadline(
                        request.clone(),
                        tokio::time::Instant::now() + std::time::Duration::from_secs(2),
                    )
                    .await
            } else {
                resolver.answer(request.clone()).await
            }
            .unwrap();
            assert_eq!(result.queries, request.queries);
            assert_eq!(result.metadata.response_code, ResponseCode::NoError);
            assert_eq!(result.answers[0].name, canonical_name(owner).unwrap());
            assert_eq!(
                result.answers[0].data,
                RData::A(A("192.0.2.1".parse().unwrap()))
            );
        }
    }
    assert_eq!(
        mock.calls(),
        vec![
            ("example.com.".into(), RecordType::TXT),
            ("direct.example.com.".into(), RecordType::TXT),
        ]
    );
}

#[tokio::test]
async fn unclaimed_programmatic_questions_keep_their_relative_name() {
    let (_, mock, _, resolver) = setup();
    let name = Name::from_ascii("External.Test").unwrap();
    mock.replies
        .lock()
        .unwrap()
        .insert((name.clone(), RecordType::A), reply());
    let mut request = Message::query();
    request
        .queries
        .push(Query::query(name.clone(), RecordType::A));
    let result = resolver.answer(request).await.unwrap();
    assert_eq!(mock.calls(), vec![("external.test".into(), RecordType::A)]);
    assert_eq!(result.queries[0].name().to_ascii(), name.to_ascii());
    assert!(!result.queries[0].name().is_fqdn());
}

#[tokio::test]
async fn programmatic_hex_apex_is_nodata_even_without_a_trailing_dot() {
    let (_, mock, _, resolver) = setup();
    let mut request = Message::query();
    request.queries.push(Query::query(
        Name::from_ascii("HeX.TeSt").unwrap(),
        RecordType::A,
    ));
    let result = resolver.answer(request.clone()).await.unwrap();
    assert_eq!(result.metadata.response_code, ResponseCode::NoError);
    assert!(result.answers.is_empty());
    assert_eq!(result.queries, request.queries);
    assert!(mock.calls().is_empty());
}

#[tokio::test]
async fn hex_synthesis_is_exact_and_never_calls_upstream() {
    let (_, mock, _, resolver) = setup();
    for (hex, address) in [
        ("c0000201", "192.0.2.1"),
        ("01020304", "1.2.3.4"),
        ("FFFFFFFF", "255.255.255.255"),
        ("00000000", "0.0.0.0"),
        ("7f000001", "127.0.0.1"),
    ] {
        let result = resolver
            .answer(query(&format!("{hex}.hex.test"), RecordType::A))
            .await
            .unwrap();
        assert_eq!(
            result.answers[0].data,
            RData::A(A(address.parse().unwrap()))
        );
        let result = resolver
            .answer(query(&format!("{hex}.hex.test"), RecordType::AAAA))
            .await
            .unwrap();
        assert!(result.answers.is_empty());
        assert_eq!(result.metadata.response_code, ResponseCode::NoError);
    }
    for name in [
        "0000000.hex.test",
        "000000000.hex.test",
        "zzzzzzzz.hex.test",
        "a.c0000201.hex.test",
    ] {
        assert_eq!(
            resolver
                .answer(query(name, RecordType::A))
                .await
                .unwrap()
                .metadata
                .response_code,
            ResponseCode::NXDomain
        );
    }
    let apex = resolver
        .answer(query("hex.test", RecordType::A))
        .await
        .unwrap();
    assert_eq!(apex.metadata.response_code, ResponseCode::NoError);
    assert!(apex.answers.is_empty());
    assert!(mock.calls().is_empty());
}

#[tokio::test]
async fn forwarding_preserves_sections_and_flags() {
    let (_, mock, _, resolver) = setup();
    let mut answer = reply();
    answer.metadata.authentic_data = true;
    answer.metadata.response_code = ResponseCode::NXDomain;
    answer.authorities.push(Record::from_rdata(
        canonical_name("external.net").unwrap(),
        60,
        RData::SOA(SOA::new(
            canonical_name("ns.external.net").unwrap(),
            canonical_name("admin.external.net").unwrap(),
            1,
            60,
            60,
            60,
            60,
        )),
    ));
    mock.set("absent.external.net", RecordType::A, answer.clone());
    let result = resolver
        .answer(query("absent.external.net", RecordType::A))
        .await
        .unwrap();
    assert_eq!(result.metadata.id, 1234);
    assert!(result.metadata.authentic_data);
    assert_eq!(result.authorities, answer.authorities);
    assert_eq!(result.metadata.response_code, ResponseCode::NXDomain);
}

#[tokio::test]
async fn hidden_children_do_not_make_their_parent_nxdomain() {
    let (config, mock, _, resolver) = setup();
    let mut answer = reply();
    answer.answers.push(txt(
        &config,
        "example.com",
        &publication(vec![entry("child", "192.0.2.1")], 100),
        60,
    ));
    mock.set("example.com", RecordType::TXT, answer);
    let result = resolver
        .answer(query("example.com", RecordType::A))
        .await
        .unwrap();
    assert_eq!(result.metadata.response_code, ResponseCode::NoError);
    assert!(result.answers.is_empty());
    assert_eq!(
        resolver
            .answer(query("child.example.com", RecordType::A))
            .await
            .unwrap()
            .answers
            .len(),
        1
    );
}

#[tokio::test]
async fn parent_search_stops_at_the_most_specific_configured_domain() {
    let config = Arc::new(
        Policy::new(
            vec![
                discovery("example.com", KEY),
                discovery("inner.example.com", KEY),
            ],
            vec![],
            60,
            1024,
        )
        .unwrap(),
    );
    let mock = Arc::new(Mock::default());
    let mut answer = reply();
    answer.answers.push(txt(
        &config,
        "inner.example.com",
        &publication(vec![entry("", "192.0.2.1")], 100),
        60,
    ));
    mock.set("inner.example.com", RecordType::TXT, answer);
    let resolver = Resolver::with_clock(
        config,
        mock.clone(),
        Arc::new(FakeClock(AtomicU64::new(100))),
    );
    assert_eq!(
        resolver
            .answer(query("inner.example.com", RecordType::A))
            .await
            .unwrap()
            .answers
            .len(),
        1
    );
    assert_eq!(
        mock.calls(),
        vec![("inner.example.com.".into(), RecordType::TXT)]
    );
}

#[tokio::test]
async fn oversized_parent_rrset_fails_without_querying_hidden_child() {
    let (config, mock, _, resolver) = setup();
    let mut answer = reply();
    let record = txt(
        &config,
        "example.com",
        &publication(vec![entry("a", "192.0.2.1")], 100),
        60,
    );
    answer.answers = vec![record; 17];
    mock.set("example.com", RecordType::TXT, answer);
    assert!(
        resolver
            .answer(query("a.example.com", RecordType::A))
            .await
            .is_err()
    );
    assert_eq!(mock.calls(), vec![("example.com.".into(), RecordType::TXT)]);
}

#[tokio::test]
async fn cname_into_forwarded_dns_preserves_chain_without_claiming_validation() {
    let (config, mock, _, resolver) = setup();
    let mut parent = reply();
    parent.answers.push(txt(
        &config,
        "example.com",
        &publication(
            vec![Entry {
                subdomain: "alias".into(),
                value: Value::Cname(canonical_name("external.net").unwrap()),
            }],
            100,
        ),
        60,
    ));
    mock.set("example.com", RecordType::TXT, parent);
    let mut target = reply();
    target.metadata.authentic_data = true;
    target.answers.push(Record::from_rdata(
        canonical_name("external.net").unwrap(),
        60,
        RData::A(A("192.0.2.1".parse().unwrap())),
    ));
    mock.set("external.net", RecordType::A, target);
    let question = query("alias.example.com", RecordType::A);
    let answer = resolver.answer(question.clone()).await.unwrap();
    assert_eq!(answer.queries, question.queries);
    assert!(!answer.metadata.authentic_data);
    assert!(!answer.metadata.authoritative);
    assert_eq!(answer.answers.len(), 2);
    assert!(matches!(answer.answers[0].data, RData::CNAME(_)));
    assert!(matches!(answer.answers[1].data, RData::A(_)));
    assert_eq!(
        mock.calls(),
        vec![
            ("example.com.".into(), RecordType::TXT),
            ("external.net.".into(), RecordType::A)
        ]
    );
}

#[tokio::test]
async fn cname_depth_limit_accepts_sixteen_names_but_not_seventeen() {
    for count in [16, 17] {
        let (config, mock, _, resolver) = setup();
        let mut entries: Vec<_> = (0..count - 1)
            .map(|i| Entry {
                subdomain: format!("n{i}"),
                value: Value::Cname(canonical_name(&format!("n{}.example.com", i + 1)).unwrap()),
            })
            .collect();
        entries.push(entry(&format!("n{}", count - 1), "192.0.2.1"));
        let mut answer = reply();
        answer
            .answers
            .push(txt(&config, "example.com", &publication(entries, 100), 60));
        mock.set("example.com", RecordType::TXT, answer);
        let answer = resolver
            .answer(query("n0.example.com", RecordType::A))
            .await;
        if count == 16 {
            assert_eq!(answer.unwrap().answers.len(), 16);
        } else {
            assert!(answer.unwrap_err().to_string().contains("CNAME chain"));
        }
        assert_eq!(mock.calls().len(), 1);
    }
}

#[tokio::test]
async fn direct_owner_does_not_use_its_hidden_child_as_its_own_address() {
    let (config, mock, _, resolver) = setup();
    mock.set("example.com", RecordType::TXT, reply());
    let mut answer = reply();
    answer.answers.push(txt(
        &config,
        "nas.example.com",
        &publication(vec![entry("hidden", "192.0.2.1")], 100),
        60,
    ));
    mock.set("nas.example.com", RecordType::TXT, answer);
    let own = resolver
        .answer(query("nas.example.com", RecordType::A))
        .await
        .unwrap();
    assert!(own.answers.is_empty());
    assert_eq!(own.metadata.response_code, ResponseCode::NoError);
    let child = resolver
        .answer(query("hidden.nas.example.com", RecordType::A))
        .await
        .unwrap();
    assert_eq!(
        child.answers[0].data,
        RData::A(A("192.0.2.1".parse().unwrap()))
    );
    assert_eq!(mock.calls().len(), 2);
}

#[tokio::test]
async fn txt_fragments_from_separate_records_are_never_concatenated() {
    let (config, mock, _, resolver) = setup();
    let owner = canonical_name("example.com").unwrap();
    let value = encrypt(
        &publication(vec![entry("nas", "192.0.2.1")], 100),
        &config.discovery()[0].key,
        &owner,
    )
    .unwrap();
    let mut answer = reply();
    for part in value.as_bytes().chunks(value.len() / 2) {
        answer.answers.push(Record::from_rdata(
            owner.clone(),
            60,
            RData::TXT(TXT::from_bytes(vec![part])),
        ));
    }
    mock.set("example.com", RecordType::TXT, answer);
    assert!(
        resolver
            .answer(query("nas.example.com", RecordType::A))
            .await
            .is_err()
    );
    assert_eq!(mock.calls(), vec![("example.com.".into(), RecordType::TXT)]);
}

#[tokio::test]
async fn only_in_class_txt_answers_at_the_expected_owner_are_used() {
    let (config, mock, _, resolver) = setup();
    let mut answer = reply();
    let bad = Record::from_rdata(
        canonical_name("example.com").unwrap(),
        60,
        RData::TXT(TXT::new(vec!["td1.invalid".into()])),
    );
    let mut wrong_owner = bad.clone();
    wrong_owner.name = canonical_name("other.example.com").unwrap();
    let mut wrong_class = bad.clone();
    wrong_class.dns_class = hickory_proto::rr::DNSClass::CH;
    answer.answers = vec![wrong_owner, wrong_class];
    answer.additionals.push(bad);
    answer.answers.push(Record::from_rdata(
        canonical_name("example.com").unwrap(),
        60,
        RData::TXT(TXT::new(vec!["v=spf1 -all".into()])),
    ));
    answer.answers.push(txt(
        &config,
        "example.com",
        &publication(vec![entry("nas", "192.0.2.1")], 100),
        60,
    ));
    mock.set("example.com", RecordType::TXT, answer);
    let answer = resolver
        .answer(query("nas.example.com", RecordType::A))
        .await
        .unwrap();
    assert_eq!(answer.answers.len(), 1);
    assert_eq!(
        answer.answers[0].data,
        RData::A(A("192.0.2.1".parse().unwrap()))
    );
}

#[tokio::test]
async fn existing_name_returns_only_requested_records_or_nodata() {
    let (config, mock, _, resolver) = setup();
    let mut answer = reply();
    answer.answers.push(txt(
        &config,
        "example.com",
        &publication(
            vec![
                entry("nas", "192.0.2.1"),
                Entry {
                    subdomain: "nas".into(),
                    value: Value::Aaaa("2001:db8::1".parse().unwrap()),
                },
            ],
            100,
        ),
        60,
    ));
    mock.set("example.com", RecordType::TXT, answer);
    for (kind, count) in [
        (RecordType::A, 1),
        (RecordType::AAAA, 1),
        (RecordType::ANY, 2),
        (RecordType::CNAME, 0),
        (RecordType::TXT, 0),
        (RecordType::HTTPS, 0),
    ] {
        let answer = resolver
            .answer(query("nas.example.com", kind))
            .await
            .unwrap();
        assert_eq!(
            answer.metadata.response_code,
            ResponseCode::NoError,
            "{kind:?}"
        );
        assert_eq!(answer.answers.len(), count, "{kind:?}");
    }
    assert_eq!(mock.calls(), vec![("example.com.".into(), RecordType::TXT)]);
}
