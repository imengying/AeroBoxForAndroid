use super::*;
use std::{
    collections::HashSet,
    io::{BufRead, BufReader, Read},
    sync::{
        Arc, Barrier,
        atomic::{AtomicUsize, Ordering},
    },
};

struct Script {
    words: Vec<u64>,
    index: usize,
}
impl Words for Script {
    fn int63(&mut self) -> Result<u64, Error> {
        let word = *self.words.get(self.index).ok_or(Error::WorkLimit)?;
        assert!(word <= i64::MAX as u64);
        self.index += 1;
        Ok(word)
    }
    fn consumed(&self) -> usize {
        self.index * 8
    }
}
fn script(words: &[u64]) -> GoRandom<Script> {
    GoRandom(Script {
        words: words.to_vec(),
        index: 0,
    })
}

#[test]
fn strict_float_coins_keep_the_possible_zero_exception_and_consume_zero_weight() {
    let mut rng = script(&[0, 1, i64::MAX as u64, 0, i64::MAX as u64]);
    assert!(!rng.coin(1.0).unwrap());
    assert!(rng.coin(1.0).unwrap());
    assert!(!rng.coin(0.0).unwrap());
    assert!(!rng.coin(0.5).unwrap());
    assert!(rng.coin(0.5).unwrap());
    assert_eq!(rng.0.consumed(), 40);
}

#[test]
fn public_intn_and_shuffle_rejection_follow_different_go_algorithms() {
    // Public Int31n(3) rejects 2^31-1, then takes 5%3.
    let mut public = script(&[i64::MAX as u64, 5u64 << 32, 7u64 << 32]);
    assert_eq!(public.intn(3), Ok(2));
    assert_eq!(public.intn(4), Ok(3));
    assert_eq!(public.0.consumed(), 24);
    // Shuffle's multiply-high path rejects uint32=0 for n=3, accepts max
    // for j=2, then max for j=1; neither swap changes the ordered input.
    let mut shuffled = script(&[0, i64::MAX as u64, i64::MAX as u64]);
    let mut values = [0, 1, 2];
    shuffled.shuffle(&mut values).unwrap();
    assert_eq!(values, [0, 1, 2]);
    assert_eq!(shuffled.0.consumed(), 24);
    let mut perm = script(&[123, 123]);
    assert_eq!(perm.perm(1).unwrap(), [0]);
    assert_eq!(perm.0.consumed(), 8);
    assert_eq!(perm.intn(0), Err(Error::InvalidBound));
}

#[test]
fn bounded_rng_never_wraps_or_substitutes_another_seed() {
    let mut rng = GoRandom(Prng::new(&[0; 32]));
    for _ in 0..MAX_RANDOM_BYTES / 8 {
        rng.0.int63().unwrap();
    }
    assert_eq!(rng.0.int63(), Err(Error::WorkLimit));
    assert_eq!(rng.0.int63(), Err(Error::WorkLimit));
    assert_eq!(rng.0.consumed(), MAX_RANDOM_BYTES);
    assert_eq!(rng.perm(33), Err(Error::InvalidBound));
    assert_eq!(rng.shuffle(&mut [0; 33]), Err(Error::InvalidBound));
    let mut rejecting = script(&[i64::MAX as u64; 3]);
    assert_eq!(rejecting.intn(3), Err(Error::WorkLimit));
}

#[test]
fn process_resolver_is_once_only_for_success_failure_and_policy_rejection() {
    for fail in [false, true] {
        let resolver = Arc::new(Resolver::new());
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(Barrier::new(9));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let (resolver, calls, gate) = (resolver.clone(), calls.clone(), gate.clone());
                std::thread::spawn(move || {
                    gate.wait();
                    resolver
                        .resolve(|bytes| {
                            calls.fetch_add(1, Ordering::SeqCst);
                            if fail {
                                Err(Error::Entropy("injected failure".into()))
                            } else {
                                bytes.fill(0);
                                Ok(())
                            }
                        })
                        .cloned()
                })
            })
            .collect();
        gate.wait();
        let expected = if fail {
            Err(Error::Entropy("injected failure".into()))
        } else {
            generate(&[0; 32])
        };
        for thread in threads {
            assert_eq!(thread.join().unwrap(), expected);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            resolver
                .resolve(|_| panic!("retried initialization"))
                .cloned(),
            expected
        );
    }
    // Find the upstream inconsistent-hybrid shape without altering the process
    // resolver. It must be rejected for ordinary TLS but remain usable after
    // REALITY's prescribed hybrid removal, with no entropy on either path.
    let seed = (0u16..1024)
        .find_map(|index| {
            let mut seed = [0; 32];
            seed[..2].copy_from_slice(&index.to_be_bytes());
            let plan = generate(&seed).unwrap();
            (plan.shares.contains(&HYBRID) && !plan.groups.contains(&HYBRID)).then_some(seed)
        })
        .expect("inconsistent hybrid witness");
    let resolver = Resolver::new();
    let plan = resolver
        .resolve(|bytes| {
            bytes.copy_from_slice(&seed);
            Ok(())
        })
        .unwrap();
    assert_eq!(
        plan.for_stream(false),
        Err(Error::ShareNotAdvertised(HYBRID))
    );
    let reality = plan.for_stream(true).unwrap();
    assert!(!reality.groups.contains(&HYBRID) && !reality.shares.contains(&HYBRID));
    assert_eq!(plan.suites, reality.suites);
    assert_eq!(plan.extensions, reality.extensions);
    assert!(std::ptr::eq(
        plan,
        resolver
            .resolve(|_| panic!("policy caused resampling"))
            .unwrap()
    ));
}

#[test]
fn rare_tls12_branch_preserves_rc4_and_never_forces_tls13_after_a_zero_coin() {
    struct ForcedTls12 {
        source: Prng,
        calls: usize,
    }
    impl Words for ForcedTls12 {
        fn int63(&mut self) -> Result<u64, Error> {
            let value = self.source.int63()?;
            self.calls += 1;
            // Seed zero's Perm(22) uses exactly 22 words without rejection.
            Ok(if self.calls == 24 { 0 } else { value })
        }
        fn consumed(&self) -> usize {
            self.source.consumed()
        }
    }
    let plan = generate_with(
        &[0; 32],
        GoRandom(ForcedTls12 {
            source: Prng::new(&[0; 32]),
            calls: 0,
        }),
    )
    .unwrap();
    assert_eq!((plan.minimum, plan.maximum), (0x0301, 0x0303));
    assert!(plan.shares.is_empty());
    assert!(!plan.suites.iter().any(|s| (0x1301..=0x1303).contains(s)));
    assert!(plan.suites.iter().any(|s| [5, 0xc011, 0xc007].contains(s)));
    assert!(
        !plan
            .extensions
            .iter()
            .any(|e| [51, 45, 43, 17513].contains(e))
    );
    assert_eq!(plan.for_stream(true), Err(Error::RealityRequiresTls13));
}

#[test]
fn structural_plans_are_bounded_stable_and_separate_from_connection_entropy() {
    for index in 0u16..2048 {
        let mut seed = [0; 32];
        seed[..2].copy_from_slice(&index.to_be_bytes());
        let plan = generate(&seed).unwrap();
        assert_eq!(plan, generate(&seed).unwrap());
        assert!(!plan.suites.is_empty() && plan.suites.len() <= 22);
        assert!(!plan.signatures.is_empty() && plan.signatures.len() <= 11);
        assert!(plan.groups.len() <= 5 && plan.shares.len() <= 3);
        assert!(plan.extensions.len() <= 15 && plan.random_bytes <= MAX_RANDOM_BYTES);
        for list in [
            &plan.suites,
            &plan.signatures,
            &plan.groups,
            &plan.shares,
            &plan.extensions,
        ] {
            assert_eq!(list.iter().collect::<HashSet<_>>().len(), list.len());
        }
        if plan.extensions.contains(&17513) {
            assert!(plan.maximum == 0x0304 && plan.extensions.contains(&16));
        }
        assert!(!plan.signatures.contains(&0x0807)); // No Ed25519 offer.
        assert!(
            !plan
                .extensions
                .iter()
                .any(|id| [34, 28, 27, 65037].contains(id))
        );
    }
}

#[test]
#[ignore = "requires independently validated uTLS randomized structural vectors"]
fn independent_utls_and_python_plans_match_every_structural_field() {
    let path = std::env::var_os("AEROBOX_RANDOMIZED_PLAN_VECTORS").expect("reference vectors");
    let mut input = BufReader::new(std::fs::File::open(path).unwrap());
    let mut count = 0;
    loop {
        let mut text = String::new();
        let n = input.by_ref().take(8193).read_line(&mut text).unwrap();
        if n == 0 {
            break;
        }
        assert!(n <= 8192 && text.ends_with('\n'));
        let row: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(row["index"].as_u64(), Some(count));
        let hex = row["seed_hex"].as_str().unwrap();
        assert_eq!(hex.len(), 64);
        let mut seed = [0; 32];
        for (i, byte) in seed.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        let plan = generate(&seed).unwrap();
        let actual = serde_json::json!({"minimum":plan.minimum, "maximum":plan.maximum,
            "suites":plan.suites, "signatures":plan.signatures, "groups":plan.groups,
            "shares":plan.shares, "extensions":plan.extensions, "structural_rng_bytes":plan.random_bytes});
        assert_eq!(actual, row["plan"], "reference seed {hex}");
        count += 1;
        assert!(count <= 2048);
    }
    assert_eq!(count, 2048, "incomplete independent corpus");
}
