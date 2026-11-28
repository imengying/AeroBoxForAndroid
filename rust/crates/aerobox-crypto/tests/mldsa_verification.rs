//! Public Wycheproof vectors and the real rustls/WebPKI verification entry points.
//! This is verification foundation coverage, not a live TLS handshake test.

use aerobox_crypto::mldsa;
use rustls::{
    CertificateError, DigitallySignedStruct, Error, PeerMisbehaved, SignatureScheme,
    crypto::{verify_tls12_signature, verify_tls13_signature_with_raw_key},
    internal::msgs::codec::Codec,
    pki_types::{CertificateDer, SignatureVerificationAlgorithm, SubjectPublicKeyInfoDer, alg_id},
};
use serde_json::Value;
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug)]
enum ParameterSet {
    P44,
    P65,
    P87,
}

const PARAMETERS: [ParameterSet; 3] = [ParameterSet::P44, ParameterSet::P65, ParameterSet::P87];

impl ParameterSet {
    fn algorithm(self) -> &'static dyn SignatureVerificationAlgorithm {
        match self {
            Self::P44 => mldsa::ML_DSA_44,
            Self::P65 => mldsa::ML_DSA_65,
            Self::P87 => mldsa::ML_DSA_87,
        }
    }

    fn scheme(self) -> SignatureScheme {
        match self {
            Self::P44 => SignatureScheme::ML_DSA_44,
            Self::P65 => SignatureScheme::ML_DSA_65,
            Self::P87 => SignatureScheme::ML_DSA_87,
        }
    }

    fn sizes(self) -> (usize, usize) {
        match self {
            Self::P44 => (1312, 2420),
            Self::P65 => (1952, 3309),
            Self::P87 => (2592, 4627),
        }
    }

    // total, valid-empty, valid-nonempty, invalid-empty, invalid-nonempty.
    // These counts describe the pinned public corpus, not an executed result.
    fn counts(self) -> [usize; 5] {
        match self {
            Self::P44 => [80, 61, 2, 16, 1],
            Self::P65 => [83, 63, 2, 17, 1],
            Self::P87 => [76, 54, 2, 19, 1],
        }
    }

    fn fixture(self) -> Value {
        serde_json::from_str(match self {
            Self::P44 => include_str!("fixtures/mldsa/mldsa_44_verify_test.json"),
            Self::P65 => include_str!("fixtures/mldsa/mldsa_65_verify_test.json"),
            Self::P87 => include_str!("fixtures/mldsa/mldsa_87_verify_test.json"),
        })
        .expect("pinned public vector JSON")
    }
}

fn hex(value: &str) -> Vec<u8> {
    assert!(value.len().is_multiple_of(2));
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII hex"), 16)
                .expect("valid public vector hex")
        })
        .collect()
}

fn bytes(value: &Value) -> Vec<u8> {
    hex(value.as_str().expect("public vector hex string"))
}

fn verify_corpus(parameter: ParameterSet) {
    let corpus = parameter.fixture();
    let mut counts = [0; 5];
    let mut ids = BTreeSet::new();
    for group in corpus["testGroups"].as_array().expect("test groups") {
        let public_key = bytes(&group["publicKey"]);
        for case in group["tests"].as_array().expect("test cases") {
            let id = case["tcId"].as_u64().expect("numeric tcId");
            assert!(ids.insert(id), "duplicate tcId {id}");
            let context = case.get("ctx").map(bytes).unwrap_or_default();
            let source_valid = match case["result"].as_str().expect("result") {
                "valid" => true,
                "invalid" => false,
                other => panic!("unsupported public expectation {other}"),
            };
            // The corpus may validate a different nonempty FIPS 204 context.
            // Our TLS/PKIX adapter has a fixed empty context and must reject it.
            let expected = source_valid && context.is_empty();
            let message = bytes(&case["msg"]);
            let signature = bytes(&case["sig"]);
            let accepted = parameter
                .algorithm()
                .verify_signature(&public_key, &message, &signature)
                .is_ok();
            counts[0] += 1;
            counts[match (source_valid, context.is_empty()) {
                (true, true) => 1,
                (true, false) => 2,
                (false, true) => 3,
                (false, false) => 4,
            }] += 1;
            assert_eq!(
                accepted,
                expected,
                "{parameter:?} tcId {id}: {} (source valid={source_valid}, context={} bytes)",
                case["comment"],
                context.len()
            );
        }
    }
    assert_eq!(counts, parameter.counts());
    assert_eq!(ids.len(), counts[0]);
    assert_eq!(corpus["numberOfTests"].as_u64(), Some(counts[0] as u64));
}

#[test]
fn wycheproof_ml_dsa_44_all_80_cases() {
    verify_corpus(ParameterSet::P44);
}

#[test]
fn wycheproof_ml_dsa_65_all_83_cases() {
    verify_corpus(ParameterSet::P65);
}

#[test]
fn wycheproof_ml_dsa_87_all_76_cases() {
    verify_corpus(ParameterSet::P87);
}

struct Sample {
    key: Vec<u8>,
    spki: Vec<u8>,
    message: Vec<u8>,
    signature: Vec<u8>,
}

fn sample(parameter: ParameterSet) -> Sample {
    let corpus = parameter.fixture();
    for group in corpus["testGroups"].as_array().unwrap() {
        for case in group["tests"].as_array().unwrap() {
            if case["result"] == "valid"
                && case.get("ctx").is_none_or(|v| v.as_str() == Some(""))
                && !case["msg"].as_str().unwrap().is_empty()
            {
                return Sample {
                    key: bytes(&group["publicKey"]),
                    spki: bytes(&group["publicKeyDer"]),
                    message: bytes(&case["msg"]),
                    signature: bytes(&case["sig"]),
                };
            }
        }
    }
    panic!("{parameter:?} has no valid public sample with nonempty message")
}

fn dss(scheme: SignatureScheme, signature: &[u8]) -> DigitallySignedStruct {
    let mut wire = u16::from(scheme).to_be_bytes().to_vec();
    wire.extend_from_slice(&u16::try_from(signature.len()).unwrap().to_be_bytes());
    wire.extend_from_slice(signature);
    DigitallySignedStruct::read_bytes(&wire).expect("well-framed signature")
}

#[test]
fn three_parameter_sets_verify_through_real_tls13_spki_entry_point() {
    for parameter in PARAMETERS {
        let sample = sample(parameter);
        assert_eq!(
            (sample.key.len(), sample.signature.len()),
            parameter.sizes()
        );
        verify_tls13_signature_with_raw_key(
            &sample.message,
            &SubjectPublicKeyInfoDer::from(sample.spki),
            &dss(parameter.scheme(), &sample.signature),
            &mldsa::ALGORITHMS,
        )
        .expect("public vector through rustls/WebPKI");
    }
}

#[test]
fn every_parameter_set_verifies_an_independent_sample_on_a_one_mib_stack() {
    for parameter in PARAMETERS {
        // Parse fixture JSON on the test thread so the requested stack covers
        // the product verifier, including public-key expansion and signature
        // decoding. Spawn and join each worker before creating the next one.
        let sample = sample(parameter);
        std::thread::Builder::new()
            .name(format!("mldsa-{parameter:?}-one-mib"))
            .stack_size(1024 * 1024)
            .spawn(move || {
                parameter
                    .algorithm()
                    .verify_signature(&sample.key, &sample.message, &sample.signature)
                    .expect("independent ML-DSA vector on requested 1 MiB stack");
            })
            .expect("spawn one bounded-stack verification worker")
            .join()
            .expect("bounded-stack verification worker completed");
    }
}

#[test]
fn modified_signature_key_and_message_are_rejected_for_every_parameter_set() {
    for parameter in PARAMETERS {
        let sample = sample(parameter);
        let algorithm = parameter.algorithm();
        let mut signature = sample.signature.clone();
        signature[0] ^= 1;
        assert!(
            algorithm
                .verify_signature(&sample.key, &sample.message, &signature)
                .is_err()
        );
        let mut key = sample.key.clone();
        key[0] ^= 1;
        assert!(
            algorithm
                .verify_signature(&key, &sample.message, &sample.signature)
                .is_err()
        );
        let mut message = sample.message.clone();
        message[0] ^= 1;
        assert!(
            algorithm
                .verify_signature(&sample.key, &message, &sample.signature)
                .is_err()
        );
        assert_eq!(
            verify_tls13_signature_with_raw_key(
                &message,
                &SubjectPublicKeyInfoDer::from(sample.spki),
                &dss(parameter.scheme(), &sample.signature),
                &mldsa::ALGORITHMS,
            )
            .unwrap_err(),
            Error::InvalidCertificate(CertificateError::BadSignature)
        );
    }
}

#[test]
fn encoded_lengths_are_exact_and_parameter_sets_cannot_be_interchanged() {
    for parameter in PARAMETERS {
        let sample = sample(parameter);
        let (key_len, signature_len) = parameter.sizes();
        for length in [0, 1, key_len - 1, key_len + 1, 131072] {
            let mut wrong = sample.key.clone();
            wrong.resize(length, 0);
            assert!(
                parameter
                    .algorithm()
                    .verify_signature(&wrong, &sample.message, &sample.signature)
                    .is_err()
            );
        }
        for length in [0, 1, signature_len - 1, signature_len + 1, 131072] {
            let mut wrong = sample.signature.clone();
            wrong.resize(length, 0);
            assert!(
                parameter
                    .algorithm()
                    .verify_signature(&sample.key, &sample.message, &wrong)
                    .is_err()
            );
        }
        for other in PARAMETERS {
            if other.scheme() != parameter.scheme() {
                assert!(
                    other
                        .algorithm()
                        .verify_signature(&sample.key, &sample.message, &sample.signature)
                        .is_err()
                );
                assert!(matches!(
                    verify_tls13_signature_with_raw_key(
                        &sample.message,
                        &SubjectPublicKeyInfoDer::from(sample.spki.clone()),
                        &dss(other.scheme(), &sample.signature),
                        &mldsa::ALGORITHMS,
                    ),
                    Err(Error::InvalidCertificate(
                        CertificateError::UnsupportedSignatureAlgorithmForPublicKeyContext { .. }
                    ))
                ));
            }
        }
    }
}

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if value.len() < 128 {
        out.push(u8::try_from(value.len()).unwrap());
    } else {
        let length = u32::try_from(value.len()).unwrap().to_be_bytes();
        let start = length.iter().position(|byte| *byte != 0).unwrap();
        out.push(0x80 | u8::try_from(length.len() - start).unwrap());
        out.extend_from_slice(&length[start..]);
    }
    out.extend_from_slice(value);
    out
}

fn spki(algorithm: &[u8], key: &[u8], unused_bits: u8) -> SubjectPublicKeyInfoDer<'static> {
    let mut bit_string = vec![unused_bits];
    bit_string.extend_from_slice(key);
    let mut contents = tlv(0x30, algorithm);
    contents.extend_from_slice(&tlv(0x03, &bit_string));
    tlv(0x30, &contents).into()
}

#[test]
fn spki_requires_exact_oid_and_absent_parameters() {
    for parameter in PARAMETERS {
        let sample = sample(parameter);
        let algorithm = parameter.algorithm();
        let signature = dss(parameter.scheme(), &sample.signature);
        let expected_id = algorithm.public_key_alg_id();
        assert_eq!(algorithm.signature_alg_id(), expected_id);
        // Confirm the helper reproduces the independent DER before mutating it.
        assert_eq!(
            spki(expected_id.as_ref(), &sample.key, 0).as_ref(),
            sample.spki
        );
        for suffix in [&[0x05, 0x00][..], &[0x04, 0x00][..]] {
            let mut bad_id = expected_id.as_ref().to_vec();
            bad_id.extend_from_slice(suffix);
            let error = verify_tls13_signature_with_raw_key(
                &sample.message,
                &spki(&bad_id, &sample.key, 0),
                &signature,
                &mldsa::ALGORITHMS,
            )
            .unwrap_err();
            assert_eq!(
                error,
                Error::InvalidCertificate(
                    CertificateError::UnsupportedSignatureAlgorithmForPublicKeyContext {
                        signature_algorithm_id: expected_id.as_ref().to_vec(),
                        public_key_algorithm_id: bad_id,
                    }
                )
            );
        }
        let mut unknown_id = expected_id.as_ref().to_vec();
        *unknown_id.last_mut().unwrap() = 0x7f;
        assert!(matches!(
            verify_tls13_signature_with_raw_key(
                &sample.message,
                &spki(&unknown_id, &sample.key, 0),
                &signature,
                &mldsa::ALGORITHMS,
            ),
            Err(Error::InvalidCertificate(
                CertificateError::UnsupportedSignatureAlgorithmForPublicKeyContext { .. }
            ))
        ));
        assert_eq!(
            verify_tls13_signature_with_raw_key(
                &sample.message,
                &spki(expected_id.as_ref(), &sample.key, 1),
                &signature,
                &mldsa::ALGORITHMS,
            )
            .unwrap_err(),
            Error::InvalidCertificate(CertificateError::BadEncoding)
        );
    }
}

#[test]
fn tls12_rejects_mldsa_before_certificate_parsing_even_with_explicit_mapping() {
    for parameter in PARAMETERS {
        let sample = sample(parameter);
        assert_eq!(
            verify_tls12_signature(
                &sample.message,
                &CertificateDer::from(Vec::new()),
                &dss(parameter.scheme(), &sample.signature),
                &mldsa::ALGORITHMS,
            )
            .unwrap_err(),
            Error::PeerMisbehaved(PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme)
        );
    }
}

#[test]
fn explicit_collection_leaves_default_and_fixed_profiles_without_mldsa() {
    assert_eq!(
        mldsa::ALGORITHMS.supported_schemes(),
        [
            SignatureScheme::ML_DSA_44,
            SignatureScheme::ML_DSA_65,
            SignatureScheme::ML_DSA_87,
        ]
    );
    assert_eq!(mldsa::ALGORITHMS.all.len(), 3);
    for provider in [
        aerobox_crypto::provider(),
        aerobox_crypto::firefox::provider(),
        aerobox_crypto::browser360::provider(),
        aerobox_crypto::android_browser::provider(
            aerobox_crypto::android_browser::Profile::Safari16,
        ),
        aerobox_crypto::android_browser::provider(aerobox_crypto::android_browser::Profile::Ios14),
    ] {
        for (scheme, _) in provider.signature_verification_algorithms.mapping {
            assert!(
                !PARAMETERS
                    .into_iter()
                    .any(|parameter| parameter.scheme() == *scheme)
            );
        }
        for algorithm in provider.signature_verification_algorithms.all {
            assert!(
                ![alg_id::ML_DSA_44, alg_id::ML_DSA_65, alg_id::ML_DSA_87]
                    .contains(&algorithm.signature_alg_id())
            );
        }
    }
}
