use std::sync::Arc;

use tendns::{Discovery, Policy, hickory_proto::rr::Name, protocol::Secret};

fn discovery(domain: &str) -> Discovery {
    Discovery {
        domain: Name::from_ascii(domain).unwrap(),
        key: Arc::new(Secret::decode("BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc").unwrap()),
    }
}

#[test]
fn canonical_names_and_most_specific_key_selection() {
    let inner_key = discovery("INNER.example.com");
    let policy = Policy::new(
        vec![
            discovery("EXAMPLE.com"),
            inner_key.clone(),
            discovery("other.test"),
        ],
        vec![Name::from_ascii("HEX.TEST").unwrap()],
        60,
        1024,
    )
    .unwrap();
    for name in [
        "example.com.",
        "a.example.com.",
        "HEX.TEST.",
        "01020304.hex.test.",
    ] {
        assert!(policy.claims(&Name::from_ascii(name).unwrap()), "{name}");
    }
    for name in ["badexample.com.", "example.com.other.", "."] {
        assert!(!policy.claims(&Name::from_ascii(name).unwrap()), "{name}");
    }
    let selected = policy
        .discovery_for(&Name::from_ascii("a.inner.example.com.").unwrap())
        .unwrap();
    assert!(Arc::ptr_eq(&selected.key, &inner_key.key));
    assert_eq!(selected.domain.to_ascii(), "inner.example.com.");
    assert_eq!(
        policy
            .discovery()
            .iter()
            .map(|item| item.domain.to_ascii())
            .collect::<Vec<_>>(),
        ["inner.example.com.", "example.com.", "other.test."]
    );
    assert_eq!(policy.hex_zones()[0].to_ascii(), "hex.test.");
    assert_eq!(policy.ttl(), 60);
    assert_eq!(policy.cache_capacity(), 1024);
}

#[test]
fn invalid_or_ambiguous_namespaces_and_limits_are_rejected() {
    for domains in [
        vec!["."],
        vec!["_dns.example"],
        vec!["example.com", "EXAMPLE.com."],
        vec!["example.com", "other.test", "EXAMPLE.com."],
    ] {
        assert!(
            Policy::new(
                domains.into_iter().map(discovery).collect(),
                vec![],
                60,
                1024
            )
            .is_err()
        );
    }
    for hex in [
        vec!["."],
        vec!["hex.test", "HEX.test."],
        vec!["hex.test", "child.hex.test"],
    ] {
        assert!(
            Policy::new(
                vec![],
                hex.into_iter()
                    .map(|s| Name::from_ascii(s).unwrap())
                    .collect(),
                60,
                1024
            )
            .is_err()
        );
    }
    for hex in ["example.com", "hex.example.com", "com"] {
        assert!(
            Policy::new(
                vec![discovery("example.com")],
                vec![Name::from_ascii(hex).unwrap()],
                60,
                1024
            )
            .is_err()
        );
    }
    for (ttl, capacity) in [(0, 1), (60, 0), (60, 65_537)] {
        assert!(Policy::new(vec![], vec![], ttl, capacity).is_err());
    }
    let empty = Policy::new(vec![], vec![], u32::MAX, 65_536).unwrap();
    assert!(!empty.claims(&Name::from_ascii("example.com.").unwrap()));
}
