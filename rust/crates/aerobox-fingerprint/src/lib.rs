//! Android's `random` fingerprint selects one fixed browser profile per process.
//!
//! Both configuration entry points use this crate's single static resolver.
//! The choice survives configuration errors, reloads and core restarts. It does
//! not cache ClientHello bytes or provide entropy for TLS keys. The original
//! sing-box v1.14.4 pool and order are preserved; selection uses OS entropy rather
//! than emulating Go's global math/rand state or its debugging overrides.
#![forbid(unsafe_code)]

pub mod randomized;

use std::{fmt, sync::OnceLock};

/// The five candidates in sing-box v1.14.4's package initializer, in that order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Profile {
    Chrome133,
    Firefox120,
    Edge85,
    Safari16,
    Ios14,
}

impl Profile {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Chrome133 => "chrome133",
            Self::Firefox120 => "firefox120",
            Self::Edge85 => "edge85",
            Self::Safari16 => "safari16",
            Self::Ios14 => "ios14",
        }
    }
}

const CANDIDATES: [Profile; 5] = [
    Profile::Chrome133,
    Profile::Firefox120,
    Profile::Edge85,
    Profile::Safari16,
    Profile::Ios14,
];

/// An initialization failure is retained for the lifetime of the process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InitError {
    Entropy(String),
    RejectionLimit,
}

impl fmt::Display for InitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Entropy(message) => write!(f, "random TLS fingerprint entropy failed: {message}"),
            Self::RejectionLimit => f.write_str("random TLS fingerprint sampling limit exceeded"),
        }
    }
}

impl std::error::Error for InitError {}

/// Resolve the process-wide selection, or return the same initialization error.
///
/// This is lazy: fixed or disabled fingerprints do not request entropy. Neither
/// incompatible policy nor a failed connection causes another choice.
pub fn random_profile() -> Result<Profile, InitError> {
    static RANDOM: Resolver = Resolver::new();
    RANDOM.resolve(|bytes| {
        getrandom::getrandom(bytes).map_err(|error| InitError::Entropy(error.to_string()))
    })
}

struct Resolver {
    result: OnceLock<Result<Profile, InitError>>,
}

impl Resolver {
    const fn new() -> Self {
        Self {
            result: OnceLock::new(),
        }
    }

    fn resolve(
        &self,
        entropy: impl FnOnce(&mut [u8]) -> Result<(), InitError>,
    ) -> Result<Profile, InitError> {
        self.result
            .get_or_init(|| {
                // 0..=254 contains exactly 51 representatives of each index.
                // Discard 255, with a fixed work bound; never fall back or bias
                // the choice if the source cannot provide an accepted byte.
                let mut bytes = [0u8; 32];
                entropy(&mut bytes)?;
                bytes
                    .into_iter()
                    .find(|byte| *byte != u8::MAX)
                    .map(|byte| CANDIDATES[usize::from(byte % 5)])
                    .ok_or(InitError::RejectionLimit)
            })
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc, Barrier,
        atomic::{AtomicUsize, Ordering},
    };

    #[test]
    fn every_candidate_has_the_fixed_android_name_and_is_selected_once() {
        for (index, name) in ["chrome133", "firefox120", "edge85", "safari16", "ios14"]
            .into_iter()
            .enumerate()
        {
            let resolver = Resolver::new();
            let selected = resolver
                .resolve(|bytes| {
                    bytes.fill(index as u8);
                    Ok(())
                })
                .unwrap();
            assert_eq!(selected.as_str(), name);
            assert_eq!(
                resolver.resolve(|_| panic!("a new configuration reselected its fingerprint")),
                Ok(selected)
            );
        }
    }

    #[test]
    fn rejection_sampling_has_equal_preimage_counts_and_skips_255() {
        let mut counts = [0usize; 5];
        for accepted in 0u8..255 {
            let selected = Resolver::new()
                .resolve(|bytes| {
                    bytes.fill(255);
                    bytes[31] = accepted;
                    Ok(())
                })
                .unwrap();
            counts[CANDIDATES
                .iter()
                .position(|item| *item == selected)
                .unwrap()] += 1;
        }
        assert_eq!(counts, [51; 5]);
    }

    #[test]
    fn entropy_failure_remains_the_original_error_and_does_not_retry() {
        let resolver = Resolver::new();
        let expected = InitError::Entropy("injected OS failure".into());
        assert_eq!(
            resolver.resolve(|_| Err(expected.clone())),
            Err(expected.clone())
        );
        assert_eq!(
            resolver.resolve(|_| panic!("failed initialization must remain failed")),
            Err(expected)
        );
    }

    #[test]
    fn bounded_rejection_failure_does_not_choose_a_fallback() {
        let resolver = Resolver::new();
        assert_eq!(
            resolver.resolve(|bytes| {
                bytes.fill(255);
                Ok(())
            }),
            Err(InitError::RejectionLimit)
        );
        assert_eq!(
            resolver.resolve(|_| panic!("sampling failure must not reroll")),
            Err(InitError::RejectionLimit)
        );
    }

    #[test]
    fn concurrent_first_use_initializes_exactly_once_on_success_and_failure() {
        for fail in [false, true] {
            let resolver = Arc::new(Resolver::new());
            let calls = Arc::new(AtomicUsize::new(0));
            let barrier = Arc::new(Barrier::new(9));
            let mut threads = Vec::new();
            for _ in 0..8 {
                let resolver = resolver.clone();
                let calls = calls.clone();
                let barrier = barrier.clone();
                threads.push(std::thread::spawn(move || {
                    barrier.wait();
                    resolver.resolve(|bytes| {
                        calls.fetch_add(1, Ordering::SeqCst);
                        if fail {
                            Err(InitError::Entropy("shared failure".into()))
                        } else {
                            bytes.fill(1);
                            Ok(())
                        }
                    })
                }));
            }
            barrier.wait();
            let expected = if fail {
                Err(InitError::Entropy("shared failure".into()))
            } else {
                Ok(Profile::Firefox120)
            };
            for thread in threads {
                assert_eq!(thread.join().unwrap(), expected);
            }
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }
    }
}
