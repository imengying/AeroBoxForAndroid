use super::*;
use std::{future::pending, net::IpAddr, time::Duration};
use tendns::{IpStrategy, LookupError, TimeoutError};
use tokio::time::Instant;

async fn no_fallback(_: Name, _: Instant) -> Result<Vec<IpAddr>> {
    panic!("private name must not reach the ordinary address resolver");
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

fn set_parent_entries(policy: &Policy, mock: &Mock, entries: Vec<Entry>) {
    let mut parent = reply();
    parent
        .answers
        .push(txt(policy, "example.com", &publication(entries, 100), 60));
    mock.set("example.com", RecordType::TXT, parent);
}

fn alias(label: &str, target: &str) -> Entry {
    Entry {
        subdomain: label.into(),
        value: Value::Cname(canonical_name(target).unwrap()),
    }
}

#[tokio::test]
async fn private_addresses_obey_family_selection_without_querying_original_name() {
    let (config, mock, _, resolver) = setup();
    set_parent_entries(
        &config,
        &mock,
        vec![
            entry("nas", "192.0.2.1"),
            entry("nas", "192.0.2.2"),
            Entry {
                subdomain: "nas".into(),
                value: Value::Aaaa("2001:db8::1".parse().unwrap()),
            },
        ],
    );
    for (strategy, expected) in [
        (IpStrategy::Ipv4Only, vec!["192.0.2.1", "192.0.2.2"]),
        (IpStrategy::Ipv6Only, vec!["2001:db8::1"]),
        (IpStrategy::Ipv4ThenIpv6, vec!["192.0.2.1", "192.0.2.2"]),
        (IpStrategy::Ipv6ThenIpv4, vec!["2001:db8::1"]),
        (
            IpStrategy::Ipv4AndIpv6,
            vec!["192.0.2.1", "192.0.2.2", "2001:db8::1"],
        ),
    ] {
        let result = resolver
            .lookup_ip(
                Name::from_ascii("NAS.EXAMPLE.COM").unwrap(),
                strategy,
                deadline(),
                no_fallback,
            )
            .await
            .unwrap();
        assert_eq!(
            result,
            expected
                .into_iter()
                .map(|s| s.parse::<IpAddr>().unwrap())
                .collect::<Vec<_>>()
        );
    }
    assert_eq!(mock.calls(), vec![("example.com.".into(), RecordType::TXT)]);
}

#[tokio::test]
async fn missing_family_is_nodata_and_never_uses_a_shadowed_direct_entry() {
    let (config, mock, _, resolver) = setup();
    set_parent_entries(&config, &mock, vec![entry("nas", "192.0.2.1")]);
    let error = resolver
        .lookup_ip(
            canonical_name("nas.example.com").unwrap(),
            IpStrategy::Ipv6Only,
            deadline(),
            no_fallback,
        )
        .await
        .unwrap_err();
    assert_eq!(
        error.downcast_ref::<LookupError>(),
        Some(&LookupError::NoData)
    );
    let addresses = resolver
        .lookup_ip(
            canonical_name("nas.example.com").unwrap(),
            IpStrategy::Ipv6ThenIpv4,
            deadline(),
            no_fallback,
        )
        .await
        .unwrap();
    assert_eq!(addresses, vec!["192.0.2.1".parse::<IpAddr>().unwrap()]);
    assert_eq!(mock.calls(), vec![("example.com.".into(), RecordType::TXT)]);
}

#[tokio::test]
async fn lookup_follows_local_aliases_and_preserves_public_native_fallback() {
    let (config, mock, _, resolver) = setup();
    set_parent_entries(
        &config,
        &mock,
        vec![
            alias("www", "next.example.com"),
            alias("next", "external.test"),
            alias("hex", "c0000201.hex.test"),
        ],
    );
    let end = deadline();
    let result = resolver
        .lookup_ip(
            canonical_name("www.example.com").unwrap(),
            IpStrategy::Ipv4AndIpv6,
            end,
            |name, actual_deadline| async move {
                assert_eq!(name, canonical_name("external.test").unwrap());
                assert_eq!(actual_deadline, end);
                Ok(vec![
                    "192.0.2.8".parse().unwrap(),
                    "192.0.2.8".parse().unwrap(),
                ])
            },
        )
        .await
        .unwrap();
    assert_eq!(result, vec!["192.0.2.8".parse::<IpAddr>().unwrap()]);
    let result = resolver
        .lookup_ip(
            canonical_name("hex.example.com").unwrap(),
            IpStrategy::Ipv4Only,
            deadline(),
            no_fallback,
        )
        .await
        .unwrap();
    assert_eq!(result, vec!["192.0.2.1".parse::<IpAddr>().unwrap()]);
    assert_eq!(mock.calls(), vec![("example.com.".into(), RecordType::TXT)]);
}

#[tokio::test]
async fn unrelated_names_delegate_without_dns_exchange() {
    let (_, mock, _, resolver) = setup();
    let result = resolver
        .lookup_ip(
            canonical_name("external.test").unwrap(),
            IpStrategy::Ipv4AndIpv6,
            deadline(),
            |name, _| async move {
                assert_eq!(name, canonical_name("external.test").unwrap());
                Ok(vec![
                    "2001:db8::1".parse().unwrap(),
                    "192.0.2.1".parse().unwrap(),
                ])
            },
        )
        .await
        .unwrap();
    assert_eq!(result.len(), 2);
    assert!(mock.calls().is_empty());
    let original = Name::from_ascii("LocalHost").unwrap();
    resolver
        .lookup_ip(
            original.clone(),
            IpStrategy::Ipv4AndIpv6,
            deadline(),
            |name, _| async move {
                assert_eq!(name.to_ascii(), original.to_ascii());
                assert_eq!(name.is_fqdn(), original.is_fqdn());
                Ok(vec!["127.0.0.1".parse().unwrap()])
            },
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn lookup_rechecks_authenticated_expiry_after_public_fallback() {
    let (config, mock, clock, resolver) = setup();
    set_parent_entries(&config, &mock, vec![alias("www", "external.test")]);
    let error = resolver
        .lookup_ip(
            canonical_name("www.example.com").unwrap(),
            IpStrategy::Ipv4Only,
            deadline(),
            |_, _| async move {
                clock.0.store(200, Ordering::SeqCst);
                Ok(vec!["192.0.2.1".parse().unwrap()])
            },
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("expired during resolution"));
}

#[tokio::test]
async fn expired_private_chain_never_starts_native_fallback() {
    let (policy, mock, clock, resolver) = setup();
    let mut first = publication(vec![alias("a", "b.sub.example.com")], 100);
    first.expires_at = 101;
    let mut parent = reply();
    parent.answers.push(txt(&policy, "example.com", &first, 60));
    mock.set("example.com", RecordType::TXT, parent);
    let mut next = reply();
    next.answers.push(txt(
        &policy,
        "sub.example.com",
        &publication(vec![alias("b", "external.test")], 100),
        60,
    ));
    mock.set("sub.example.com", RecordType::TXT, next);
    let gate = Arc::new(tokio::sync::Semaphore::new(1));
    *mock.gate.lock().unwrap() = Some(gate.clone());
    let future = resolver.lookup_ip(
        canonical_name("a.example.com").unwrap(),
        IpStrategy::Ipv4Only,
        deadline(),
        no_fallback,
    );
    tokio::pin!(future);
    assert_pending(future.as_mut()).await;
    clock.0.store(101, Ordering::SeqCst);
    gate.add_permits(1);
    let error = future.await.unwrap_err();
    assert!(error.to_string().contains("expired during resolution"));
    assert_eq!(
        mock.calls(),
        vec![
            ("example.com.".into(), RecordType::TXT),
            ("sub.example.com.".into(), RecordType::TXT),
        ]
    );
}

#[tokio::test]
async fn missing_invalid_and_expired_publications_never_fall_back() {
    for mode in ["missing", "invalid", "expired", "unavailable"] {
        let (config, mock, clock, resolver) = setup();
        let mut parent = reply();
        match mode {
            "missing" => {
                mock.set("nas.example.com", RecordType::TXT, reply());
            }
            "invalid" => {
                parent.answers.push(Record::from_rdata(
                    canonical_name("example.com").unwrap(),
                    60,
                    RData::TXT(TXT::new(vec!["td1.invalid".into()])),
                ));
            }
            "expired" => {
                parent.answers.push(txt(
                    &config,
                    "example.com",
                    &publication(vec![entry("nas", "192.0.2.1")], 100),
                    60,
                ));
                clock.0.store(200, Ordering::SeqCst);
            }
            _ => {}
        }
        if mode != "unavailable" {
            mock.set("example.com", RecordType::TXT, parent);
        }
        let error = resolver
            .lookup_ip(
                canonical_name("nas.example.com").unwrap(),
                IpStrategy::Ipv4Only,
                deadline(),
                no_fallback,
            )
            .await
            .unwrap_err();
        assert!(!error.is::<TimeoutError>(), "{mode}: {error:#}");
        if mode == "missing" {
            assert_eq!(
                error.downcast_ref::<LookupError>(),
                Some(&LookupError::NotFound)
            );
        } else {
            assert!(error.downcast_ref::<LookupError>().is_none());
            assert_eq!(mock.calls().len(), 1);
        }
    }
}

#[tokio::test]
async fn invalid_hex_names_and_missing_families_never_fall_back() {
    let (_, mock, _, resolver) = setup();
    for (name, strategy, expected) in [
        (
            "zzzzzzzz.hex.test",
            IpStrategy::Ipv4Only,
            LookupError::NotFound,
        ),
        (
            "0000000.hex.test",
            IpStrategy::Ipv4Only,
            LookupError::NotFound,
        ),
        (
            "000000000.hex.test",
            IpStrategy::Ipv4Only,
            LookupError::NotFound,
        ),
        (
            "a.c0000201.hex.test",
            IpStrategy::Ipv4Only,
            LookupError::NotFound,
        ),
        ("hex.test", IpStrategy::Ipv4Only, LookupError::NoData),
        (
            "c0000201.hex.test",
            IpStrategy::Ipv6Only,
            LookupError::NoData,
        ),
    ] {
        let error = resolver
            .lookup_ip(
                canonical_name(name).unwrap(),
                strategy,
                deadline(),
                no_fallback,
            )
            .await
            .unwrap_err();
        assert_eq!(
            error.downcast_ref::<LookupError>(),
            Some(&expected),
            "{name}"
        );
    }
    assert!(mock.calls().is_empty());
}

#[tokio::test]
async fn local_cname_loops_and_depth_limits_are_enforced_for_address_lookups() {
    for count in [1, 17] {
        let (config, mock, _, resolver) = setup();
        let entries = (0..count)
            .map(|i| {
                alias(
                    &format!("n{i}"),
                    &format!("n{}.example.com", (i + 1) % count),
                )
            })
            .collect();
        set_parent_entries(&config, &mock, entries);
        let error = resolver
            .lookup_ip(
                canonical_name("n0.example.com").unwrap(),
                IpStrategy::Ipv4Only,
                deadline(),
                no_fallback,
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains(if count == 1 {
            "CNAME loop"
        } else {
            "exceeds 16"
        }));
    }
}

#[tokio::test]
async fn sixteen_names_can_end_in_an_ipv6_only_public_target() {
    let (config, mock, _, resolver) = setup();
    let mut entries: Vec<_> = (0..14)
        .map(|i| alias(&format!("n{i}"), &format!("n{}.example.com", i + 1)))
        .collect();
    entries.push(alias("n14", "external.test"));
    set_parent_entries(&config, &mock, entries);
    let addresses = resolver
        .lookup_ip(
            canonical_name("n0.example.com").unwrap(),
            IpStrategy::Ipv4ThenIpv6,
            deadline(),
            |name, _| async move {
                assert_eq!(name, canonical_name("external.test").unwrap());
                Ok(vec!["2001:db8::1".parse().unwrap()])
            },
        )
        .await
        .unwrap();
    assert_eq!(addresses, vec!["2001:db8::1".parse::<IpAddr>().unwrap()]);
}

#[tokio::test]
async fn ordinary_dns_forwarding_receives_the_same_deadline() {
    let (_, mock, _, resolver) = setup();
    mock.set("external.test", RecordType::A, reply());
    let end = deadline();
    resolver
        .answer_with_deadline(query("external.test", RecordType::A), end)
        .await
        .unwrap();
    assert_eq!(*mock.deadlines.lock().unwrap(), vec![end]);
}

#[tokio::test(start_paused = true)]
async fn one_deadline_covers_parent_and_direct_txt_queries() {
    let (_, mock, _, resolver) = setup();
    mock.set("example.com", RecordType::TXT, reply());
    mock.set("nas.example.com", RecordType::TXT, reply());
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    *mock.gate.lock().unwrap() = Some(gate.clone());
    let end = Instant::now() + Duration::from_secs(5);
    let future = resolver.answer_with_deadline(query("nas.example.com", RecordType::A), end);
    tokio::pin!(future);
    assert_pending(future.as_mut()).await;
    tokio::time::advance(Duration::from_secs(3)).await;
    gate.add_permits(1);
    assert_pending(future.as_mut()).await;
    assert_eq!(*mock.deadlines.lock().unwrap(), vec![end, end]);
    tokio::time::advance(Duration::from_secs(2)).await;
    let error = future.await.unwrap_err();
    assert!(error.to_string().contains("timed out"));
    assert!(error.is::<TimeoutError>());
}

#[tokio::test(start_paused = true)]
async fn elapsed_deadline_does_not_start_the_next_txt_query() {
    let (_, mock, _, resolver) = setup();
    mock.set("example.com", RecordType::TXT, reply());
    mock.set("nas.example.com", RecordType::TXT, reply());
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    *mock.gate.lock().unwrap() = Some(gate.clone());
    let end = Instant::now() + Duration::from_secs(5);
    let future = resolver.answer_with_deadline(query("nas.example.com", RecordType::A), end);
    tokio::pin!(future);
    assert_pending(future.as_mut()).await;
    tokio::time::advance(Duration::from_secs(5)).await;
    gate.add_permits(1);
    let error = future.await.unwrap_err();
    assert!(error.to_string().contains("timed out"));
    assert!(error.is::<TimeoutError>());
    assert_eq!(mock.calls(), vec![("example.com.".into(), RecordType::TXT)]);
}

#[tokio::test(start_paused = true)]
async fn elapsed_deadline_does_not_start_native_fallback() {
    let (policy, mock, _, resolver) = setup();
    set_parent_entries(&policy, &mock, vec![alias("www", "external.test")]);
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    *mock.gate.lock().unwrap() = Some(gate.clone());
    let end = Instant::now() + Duration::from_secs(5);
    let future = resolver.lookup_ip(
        canonical_name("www.example.com").unwrap(),
        IpStrategy::Ipv4Only,
        end,
        |_, _| -> std::future::Ready<Result<Vec<IpAddr>>> {
            panic!("expired deadline must not invoke the fallback closure");
        },
    );
    tokio::pin!(future);
    assert_pending(future.as_mut()).await;
    tokio::time::advance(Duration::from_secs(5)).await;
    gate.add_permits(1);
    let error = future.await.unwrap_err();
    assert!(error.to_string().contains("timed out"));
    assert!(error.is::<TimeoutError>());
    assert_eq!(mock.calls(), vec![("example.com.".into(), RecordType::TXT)]);
}

#[tokio::test(start_paused = true)]
async fn elapsed_deadline_rejects_a_ready_private_answer() {
    for address_lookup in [false, true] {
        let (policy, mock, _, resolver) = setup();
        set_parent_entries(&policy, &mock, vec![entry("nas", "192.0.2.1")]);
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        *mock.gate.lock().unwrap() = Some(gate.clone());
        let end = Instant::now() + Duration::from_secs(5);
        let future = async {
            if address_lookup {
                resolver
                    .lookup_ip(
                        canonical_name("nas.example.com").unwrap(),
                        IpStrategy::Ipv4Only,
                        end,
                        no_fallback,
                    )
                    .await
                    .map(|_| ())
            } else {
                resolver
                    .answer_with_deadline(query("nas.example.com", RecordType::A), end)
                    .await
                    .map(|_| ())
            }
        };
        tokio::pin!(future);
        assert_pending(future.as_mut()).await;
        tokio::time::advance(Duration::from_secs(5)).await;
        gate.add_permits(1);
        let error = future.await.unwrap_err();
        assert!(error.to_string().contains("timed out"));
        assert!(error.is::<TimeoutError>());
        assert_eq!(mock.calls(), vec![("example.com.".into(), RecordType::TXT)]);
    }
}

#[tokio::test(start_paused = true)]
async fn deadline_covers_native_fallback_and_already_expired_requests_do_no_work() {
    let (_, mock, _, resolver) = setup();
    let end = Instant::now() + Duration::from_secs(2);
    let result = resolver
        .lookup_ip(
            canonical_name("external.test").unwrap(),
            IpStrategy::Ipv4Only,
            end,
            |_, _| pending::<Result<Vec<IpAddr>>>(),
        )
        .await;
    let error = result.unwrap_err();
    assert!(error.to_string().contains("timed out"));
    assert!(error.is::<TimeoutError>());
    assert_eq!(Instant::now(), end);
    let error = resolver
        .answer_with_deadline(query("nas.example.com", RecordType::A), end)
        .await
        .unwrap_err();
    assert!(error.is::<TimeoutError>());
    let error = resolver
        .lookup_ip(
            canonical_name("external.test").unwrap(),
            IpStrategy::Ipv4Only,
            end,
            no_fallback,
        )
        .await
        .unwrap_err();
    assert!(error.is::<TimeoutError>());
    assert!(mock.calls().is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_cache_waiter_times_out_without_canceling_the_fetch_owner() {
    let (config, mock, _, resolver) = setup();
    set_parent_entries(&config, &mock, vec![entry("nas", "192.0.2.1")]);
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    *mock.gate.lock().unwrap() = Some(gate.clone());
    let owner = resolver.answer_with_deadline(query("nas.example.com", RecordType::A), deadline());
    tokio::pin!(owner);
    assert_pending(owner.as_mut()).await;
    let waiter = resolver.answer_with_deadline(
        query("nas.example.com", RecordType::A),
        Instant::now() + Duration::from_secs(1),
    );
    assert!(waiter.await.is_err());
    gate.add_permits(1);
    assert_eq!(owner.await.unwrap().answers.len(), 1);
    assert_eq!(mock.calls().len(), 1);
}
