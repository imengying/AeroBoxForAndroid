use super::*;
use rand_core::RngCore;

struct FixtureRng {
    bytes: Vec<u8>,
    fail: bool,
    calls: usize,
}

impl RngCore for FixtureRng {
    fn next_u32(&mut self) -> u32 {
        panic!("FFDHE must use the fallible byte API")
    }
    fn next_u64(&mut self) -> u64 {
        panic!("FFDHE must use the fallible byte API")
    }
    fn fill_bytes(&mut self, _: &mut [u8]) {
        panic!("FFDHE must use the fallible byte API")
    }
    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), rand_core::Error> {
        self.calls += 1;
        if self.fail {
            output.fill(0xa5);
            return Err(std::num::NonZeroU32::new(rand_core::Error::CUSTOM_START)
                .unwrap()
                .into());
        }
        assert_eq!(output.len(), self.bytes.len());
        output.copy_from_slice(&self.bytes);
        Ok(())
    }
}
impl rand_core::CryptoRng for FixtureRng {}

fn decode(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn subtract_one(bytes: &[u8]) -> Vec<u8> {
    let mut result = bytes.to_vec();
    for byte in result.iter_mut().rev() {
        let (next, borrow) = byte.overflowing_sub(1);
        *byte = next;
        if !borrow {
            return result;
        }
    }
    panic!("zero input")
}

#[test]
fn group_parameters_equal_rfc_constants_and_are_not_enabled_by_default() {
    assert_eq!(
        params::Modulus2048::MODULUS.to_be_bytes().as_slice(),
        rustls::ffdhe_groups::FFDHE2048.p
    );
    assert_eq!(
        params::Modulus3072::MODULUS.to_be_bytes().as_slice(),
        rustls::ffdhe_groups::FFDHE3072.p
    );
    for group in [&FFDHE2048 as &dyn SupportedKxGroup, &FFDHE3072] {
        assert_eq!(group.ffdhe_group().unwrap().g, &[2]);
        assert!(!group.fips());
        assert!(group.usable_for_version(ProtocolVersion::TLSv1_3));
        for version in [
            ProtocolVersion::TLSv1_0,
            ProtocolVersion::TLSv1_1,
            ProtocolVersion::TLSv1_2,
            ProtocolVersion::Unknown(0x0305),
        ] {
            assert!(!group.usable_for_version(version));
        }
        assert!(
            crate::provider()
                .kx_groups
                .iter()
                .all(|normal| normal.name() != group.name())
        );
    }
}

#[test]
fn public_and_shared_keys_match_independent_python_modular_exponentiation() {
    let vectors: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("vectors.json")).unwrap();
    assert_eq!(vectors.len(), 8);
    let mut leading_zero_cases = 0;
    for vector in vectors {
        let bits = vector["group"].as_u64().unwrap();
        let mut rng = FixtureRng {
            bytes: decode(vector["secret"].as_str().unwrap()),
            fail: false,
            calls: 0,
        };
        let active = if bits == 2048 {
            FFDHE2048.start_with_rng(&mut rng).unwrap()
        } else {
            assert_eq!(bits, 3072);
            FFDHE3072.start_with_rng(&mut rng).unwrap()
        };
        assert_eq!(rng.calls, 1);
        assert_eq!(active.pub_key(), decode(vector["public"].as_str().unwrap()));
        let peer = decode(vector["peer"].as_str().unwrap());
        let secret = active.complete(&peer).unwrap();
        let expected = decode(vector["shared"].as_str().unwrap());
        assert_eq!(secret.secret_bytes(), expected);
        assert_eq!(secret.secret_bytes().len(), bits as usize / 8);
        if vector["case"] == "leading-zero" {
            assert_eq!(secret.secret_bytes()[0], 0);
            leading_zero_cases += 1;
        }
    }
    assert_eq!(leading_zero_cases, 2);
}

#[test]
fn invalid_public_values_and_noncanonical_lengths_are_rejected_before_private_work() {
    for group in [&FFDHE2048 as &dyn SupportedKxGroup, &FFDHE3072] {
        let prime = group.ffdhe_group().unwrap().p;
        let mut one = vec![0; prime.len()];
        *one.last_mut().unwrap() = 1;
        let mut oversized = vec![0];
        oversized.extend_from_slice(prime);
        for invalid in [
            vec![],
            vec![2],
            vec![0; prime.len()],
            one,
            subtract_one(prime),
            prime.to_vec(),
            vec![255; prime.len()],
            prime[..prime.len() - 1].to_vec(),
            oversized,
        ] {
            assert!(matches!(
                group.start_and_complete(&invalid),
                Err(Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare))
            ));
        }
        // A valid peer of the other named group has the wrong encoded length.
        let other = if prime.len() == 256 {
            rustls::ffdhe_groups::FFDHE3072.p
        } else {
            rustls::ffdhe_groups::FFDHE2048.p
        };
        assert!(group.start_and_complete(&subtract_one(other)).is_err());
    }
}

#[test]
fn fallible_rng_failure_never_creates_a_key_or_panics() {
    let mut rng = FixtureRng {
        bytes: vec![],
        fail: true,
        calls: 0,
    };
    assert!(matches!(
        FFDHE2048.start_with_rng(&mut rng),
        Err(Error::FailedToGetRandomBytes)
    ));
    assert!(matches!(
        FFDHE3072.start_with_rng(&mut rng),
        Err(Error::FailedToGetRandomBytes)
    ));
    assert_eq!(rng.calls, 2);
}

#[test]
fn each_start_uses_a_fresh_private_key_and_peers_compute_the_same_secret() {
    for group in [&FFDHE2048 as &dyn SupportedKxGroup, &FFDHE3072] {
        let left = group.start().unwrap();
        let right = group.start().unwrap();
        assert_eq!(left.group(), group.name());
        assert_eq!(left.ffdhe_group(), group.ffdhe_group());
        assert_ne!(left.pub_key(), right.pub_key());
        let left_public = left.pub_key().to_vec();
        let right_public = right.pub_key().to_vec();
        let left_secret = left.complete(&right_public).unwrap();
        let right_secret = right.complete(&left_public).unwrap();
        assert_eq!(left_secret.secret_bytes(), right_secret.secret_bytes());
    }
}

#[test]
fn successful_combined_exchange_preserves_full_group_width() {
    for group in [&FFDHE2048 as &dyn SupportedKxGroup, &FFDHE3072] {
        let first = group.start().unwrap();
        let second = group.start_and_complete(first.pub_key()).unwrap();
        let shared = first.complete(&second.pub_key).unwrap();
        assert_eq!(second.group, group.name());
        assert_eq!(second.pub_key.len(), group.ffdhe_group().unwrap().p.len());
        assert_eq!(shared.secret_bytes(), second.secret.secret_bytes());
    }
}

#[test]
fn legacy_tls_cannot_call_through_the_tls13_only_exchange() {
    for group in [&FFDHE2048 as &dyn SupportedKxGroup, &FFDHE3072] {
        let active = group.start().unwrap();
        let peer = active.pub_key().to_vec();
        assert!(
            active
                .complete_for_tls_version(&peer, &rustls::version::TLS12)
                .is_err()
        );
    }
}
