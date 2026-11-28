use super::*;

#[tokio::test(start_paused = true)]
async fn pending_cname_lookup_cannot_outlive_its_authenticated_publication() {
    let (config, mock, clock, resolver) = setup();
    let mut publication = publication(
        vec![Entry {
            subdomain: "alias".into(),
            value: Value::Cname(canonical_name("external.net").unwrap()),
        }],
        100,
    );
    publication.expires_at = 101;
    let mut parent = reply();
    parent
        .answers
        .push(txt(&config, "example.com", &publication, 60));
    mock.set("example.com", RecordType::TXT, parent);
    resolver
        .answer(query("alias.example.com", RecordType::CNAME))
        .await
        .unwrap();
    mock.set("external.net", RecordType::A, reply());
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    *mock.gate.lock().unwrap() = Some(gate.clone());
    let answer = resolver.answer(query("alias.example.com", RecordType::A));
    tokio::pin!(answer);
    assert_pending(answer.as_mut()).await;
    clock.0.store(101, Ordering::SeqCst);
    gate.add_permits(1);
    assert!(
        answer.await.is_err(),
        "a publication expired while waiting on its CNAME target"
    );
}

#[tokio::test(start_paused = true)]
async fn pending_cname_lookup_ages_only_synthetic_ttls() {
    let (config, mock, clock, resolver) = setup();
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
    resolver
        .answer(query("alias.example.com", RecordType::CNAME))
        .await
        .unwrap();
    let mut target = reply();
    target.answers.push(Record::from_rdata(
        canonical_name("external.net").unwrap(),
        99,
        RData::A(A("192.0.2.1".parse().unwrap())),
    ));
    mock.set("external.net", RecordType::A, target);
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    *mock.gate.lock().unwrap() = Some(gate.clone());
    let answer = resolver.answer(query("alias.example.com", RecordType::A));
    tokio::pin!(answer);
    assert_pending(answer.as_mut()).await;
    tokio::time::advance(std::time::Duration::from_secs(5)).await;
    gate.add_permits(1);
    let answer = answer.await.unwrap();
    assert_eq!(answer.answers[0].ttl, 55);
    assert_eq!(answer.answers[1].ttl, 99);

    let answer = resolver.answer(query("alias.example.com", RecordType::A));
    tokio::pin!(answer);
    assert_pending(answer.as_mut()).await;
    clock.0.store(199, Ordering::SeqCst);
    gate.add_permits(1);
    let answer = answer.await.unwrap();
    assert_eq!(
        answer.answers[0].ttl, 1,
        "wall-clock changes must also bound the returned TTL"
    );
    assert_eq!(answer.answers[1].ttl, 99);
}

#[tokio::test]
async fn expiry_bounds_ttl_and_invalidates_cached_payload() {
    let (config, mock, clock, resolver) = setup();
    let mut answer = reply();
    let mut p = publication(vec![entry("", "192.0.2.1")], 100);
    p.expires_at = 105;
    answer.answers.push(txt(&config, "example.com", &p, 600));
    mock.set("example.com", RecordType::TXT, answer);
    let result = resolver
        .answer(query("example.com", RecordType::A))
        .await
        .unwrap();
    assert!(result.answers[0].ttl <= 5);
    clock.0.store(105, Ordering::SeqCst);
    assert!(
        resolver
            .answer(query("example.com", RecordType::A))
            .await
            .is_err()
    );
    assert_eq!(mock.calls().len(), 2);
}

#[tokio::test]
async fn concurrent_parent_queries_share_one_fetch() {
    let (config, mock, _, resolver) = setup();
    let mut answer = reply();
    answer.answers.push(txt(
        &config,
        "example.com",
        &publication(vec![entry("a", "192.0.2.1"), entry("b", "192.0.2.2")], 100),
        60,
    ));
    mock.set("example.com", RecordType::TXT, answer);
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    *mock.gate.lock().unwrap() = Some(gate.clone());
    let a = resolver.answer(query("a.example.com", RecordType::A));
    let b = resolver.answer(query("b.example.com", RecordType::A));
    tokio::pin!(a, b);
    assert_pending(a.as_mut()).await;
    assert_pending(b.as_mut()).await;
    assert_eq!(
        mock.calls().len(),
        1,
        "both requests must be in flight before releasing the upstream"
    );
    gate.add_permits(1);
    let (a, b) = tokio::join!(a, b);
    assert!(a.is_ok() && b.is_ok());
    assert_eq!(mock.calls().len(), 1);
}

#[tokio::test(start_paused = true)]
async fn dns_ttl_refreshes_positive_and_negative_cache_entries() {
    for positive in [false, true] {
        let (config, mock, _, resolver) = setup();
        let mut answer = reply();
        if positive {
            answer.answers.push(txt(
                &config,
                "example.com",
                &publication(vec![entry("", "192.0.2.1")], 100),
                1,
            ));
        } else {
            answer.metadata.response_code = ResponseCode::NXDomain;
            answer.authorities.push(Record::from_rdata(
                canonical_name("example.com").unwrap(),
                30,
                RData::SOA(SOA::new(
                    canonical_name("ns.example.com").unwrap(),
                    canonical_name("admin.example.com").unwrap(),
                    1,
                    30,
                    30,
                    30,
                    1,
                )),
            ));
        }
        mock.set("example.com", RecordType::TXT, answer);
        for _ in 0..2 {
            let result = resolver
                .answer(query("example.com", RecordType::A))
                .await
                .unwrap();
            assert_eq!(result.answers.len(), usize::from(positive));
        }
        assert_eq!(mock.calls().len(), 1);
        let mut answer = reply();
        answer.answers.push(txt(
            &config,
            "example.com",
            &publication(vec![entry("", "192.0.2.2")], 100),
            60,
        ));
        mock.set("example.com", RecordType::TXT, answer);
        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        let result = resolver
            .answer(query("example.com", RecordType::A))
            .await
            .unwrap();
        assert_eq!(
            result.answers[0].data,
            RData::A(A("192.0.2.2".parse().unwrap()))
        );
        assert_eq!(mock.calls().len(), 2);
    }
}

#[tokio::test]
async fn cancellation_releases_the_per_owner_fetch_lock() {
    let (config, mock, _, resolver) = setup();
    let mut answer = reply();
    answer.answers.push(txt(
        &config,
        "example.com",
        &publication(vec![entry("nas", "192.0.2.1")], 100),
        60,
    ));
    mock.set("example.com", RecordType::TXT, answer);
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    *mock.gate.lock().unwrap() = Some(gate.clone());
    let mut first = Box::pin(resolver.answer(query("nas.example.com", RecordType::A)));
    assert_pending(first.as_mut()).await;
    drop(first);
    gate.add_permits(1);
    let second = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        resolver.answer(query("nas.example.com", RecordType::A)),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(second.answers.len(), 1);
    assert_eq!(mock.calls().len(), 2);
}

#[tokio::test]
async fn unrelated_owners_can_fetch_concurrently() {
    let (config, mock, _, resolver) = setup();
    for owner in ["example.com", "other.example.com"] {
        let mut answer = reply();
        answer.answers.push(txt(
            &config,
            owner,
            &publication(vec![entry("nas", "192.0.2.1")], 100),
            60,
        ));
        mock.set(owner, RecordType::TXT, answer);
    }
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    *mock.gate.lock().unwrap() = Some(gate.clone());
    let first = resolver.answer(query("nas.example.com", RecordType::A));
    let second = resolver.answer(query("nas.other.example.com", RecordType::A));
    tokio::pin!(first, second);
    assert_pending(first.as_mut()).await;
    assert_pending(second.as_mut()).await;
    assert_eq!(mock.calls().len(), 2);
    gate.add_permits(2);
    let (first, second) = tokio::join!(first, second);
    assert!(first.is_ok() && second.is_ok());
}

#[tokio::test(start_paused = true)]
async fn combined_values_use_the_shortest_ttl_and_expiry() {
    let (config, mock, clock, resolver) = setup();
    let mut answer = reply();
    let mut short = publication(vec![entry("nas", "192.0.2.1")], 100);
    short.expires_at = 105;
    answer.answers.push(txt(&config, "example.com", &short, 60));
    answer.answers.push(txt(
        &config,
        "example.com",
        &publication(vec![entry("nas", "192.0.2.2")], 100),
        3,
    ));
    mock.set("example.com", RecordType::TXT, answer);
    let result = resolver
        .answer(query("nas.example.com", RecordType::A))
        .await
        .unwrap();
    assert!(result.answers.iter().all(|r| r.ttl == 3));
    tokio::time::advance(std::time::Duration::from_secs(2)).await;
    clock.0.store(102, Ordering::SeqCst);
    let result = resolver
        .answer(query("nas.example.com", RecordType::A))
        .await
        .unwrap();
    assert!(result.answers.iter().all(|r| r.ttl == 1));
    assert_eq!(mock.calls().len(), 1);
    clock.0.store(105, Ordering::SeqCst);
    assert!(
        resolver
            .answer(query("nas.example.com", RecordType::A))
            .await
            .is_err()
    );
    assert_eq!(
        mock.calls(),
        vec![("example.com.".into(), RecordType::TXT); 2]
    );
}

#[tokio::test]
async fn zero_ttl_and_unproven_negative_answers_are_not_cached() {
    for negative in [false, true] {
        let (config, mock, _, resolver) = setup();
        let mut answer = reply();
        if !negative {
            answer.answers.push(txt(
                &config,
                "example.com",
                &publication(vec![entry("", "192.0.2.1")], 100),
                0,
            ));
        }
        mock.set("example.com", RecordType::TXT, answer);
        for _ in 0..2 {
            resolver
                .answer(query("example.com", RecordType::A))
                .await
                .unwrap();
        }
        assert_eq!(mock.calls().len(), 2, "negative={negative}");
    }
}

#[tokio::test]
async fn cache_eviction_refetches_without_cross_domain_key_reuse() {
    let other_key = tendns::protocol::Secret::generate().unwrap();
    let config = Arc::new(
        Policy::new(
            vec![
                discovery("example.com", KEY),
                discovery("inner.example.com", &other_key),
            ],
            vec![],
            60,
            1,
        )
        .unwrap(),
    );
    let mock = Arc::new(Mock::default());
    for (owner, ip) in [
        ("example.com", "192.0.2.1"),
        ("inner.example.com", "192.0.2.2"),
    ] {
        let mut answer = reply();
        answer.answers.push(txt(
            &config,
            owner,
            &publication(vec![entry("", ip)], 100),
            60,
        ));
        mock.set(owner, RecordType::TXT, answer);
    }
    let resolver = Resolver::with_clock(
        config,
        mock.clone(),
        Arc::new(FakeClock(AtomicU64::new(100))),
    );
    for (owner, ip) in [
        ("example.com", "192.0.2.1"),
        ("inner.example.com", "192.0.2.2"),
        ("example.com", "192.0.2.1"),
    ] {
        let answer = resolver.answer(query(owner, RecordType::A)).await.unwrap();
        assert_eq!(answer.answers[0].data, RData::A(A(ip.parse().unwrap())));
    }
    assert_eq!(
        mock.calls(),
        vec![
            ("example.com.".into(), RecordType::TXT),
            ("inner.example.com.".into(), RecordType::TXT),
            ("example.com.".into(), RecordType::TXT)
        ]
    );
}

#[tokio::test]
async fn failed_parent_fetches_do_not_poison_the_cache_or_leak_child_names() {
    for kind in [
        "servfail",
        "refused",
        "truncated",
        "expired",
        "future",
        "contradictory",
    ] {
        let (config, mock, _, resolver) = setup();
        let mut answer = reply();
        match kind {
            "servfail" => answer.metadata.response_code = ResponseCode::ServFail,
            "refused" => answer.metadata.response_code = ResponseCode::Refused,
            "truncated" => answer.metadata.truncation = true,
            _ => {
                let issued = match kind {
                    "expired" => 0,
                    "future" => 161,
                    _ => 100,
                };
                answer.answers.push(txt(
                    &config,
                    "example.com",
                    &publication(vec![entry("nas", "192.0.2.1")], issued),
                    60,
                ));
                if kind == "contradictory" {
                    answer.metadata.response_code = ResponseCode::NXDomain;
                }
            }
        }
        mock.set("example.com", RecordType::TXT, answer);
        assert!(
            resolver
                .answer(query("nas.example.com", RecordType::A))
                .await
                .is_err(),
            "{kind}"
        );
        let mut valid = reply();
        valid.answers.push(txt(
            &config,
            "example.com",
            &publication(vec![entry("nas", "192.0.2.1")], 100),
            60,
        ));
        mock.set("example.com", RecordType::TXT, valid);
        assert_eq!(
            resolver
                .answer(query("nas.example.com", RecordType::A))
                .await
                .unwrap()
                .answers
                .len(),
            1
        );
        assert_eq!(
            mock.calls(),
            vec![("example.com.".into(), RecordType::TXT); 2],
            "{kind}"
        );
    }
}
