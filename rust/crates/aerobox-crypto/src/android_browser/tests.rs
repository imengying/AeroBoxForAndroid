use super::*;
use rsa::pkcs8::der::Decode;
use rustls::{
    ProtocolVersion,
    client::{LegacyTlsProvider, WebPkiServerVerifier, danger::ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};

fn bytes(value: &serde_json::Value) -> Vec<u8> {
    let value = value.as_str().unwrap();
    assert_eq!(value.len() % 2, 0);
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
        .collect()
}
fn fixtures() -> serde_json::Value {
    serde_json::from_str(include_str!("sha1-fixtures.json")).unwrap()
}

#[test]
fn exact_android_browser_crypto_choices_preserve_duplicate_signatures() {
    for (profile, expected) in [
        (
            Profile::Safari16,
            vec![
                0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8, 0xc00a,
                0xc009, 0xc014, 0xc013, 0x009d, 0x009c, 0x0035, 0x002f, 0xc008, 0xc012, 0x000a,
            ],
        ),
        (
            Profile::Ios14,
            vec![
                0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8, 0xc024,
                0xc023, 0xc00a, 0xc009, 0xc028, 0xc027, 0xc014, 0xc013, 0x009d, 0x009c, 0x003d,
                0x003c, 0x0035, 0x002f, 0xc008, 0xc012, 0x000a,
            ],
        ),
    ] {
        let p = provider(profile);
        assert_eq!(
            p.cipher_suites
                .iter()
                .map(|v| u16::from(v.suite()))
                .collect::<Vec<_>>(),
            expected
        );
        assert_eq!(
            p.kx_groups
                .iter()
                .map(|v| u16::from(v.name()))
                .collect::<Vec<_>>(),
            [29, 23, 24, 25]
        );
        assert_eq!(
            p.signature_verification_algorithms
                .supported_schemes()
                .into_iter()
                .map(u16::from)
                .collect::<Vec<_>>(),
            [
                0x0403, 0x0804, 0x0401, 0x0503, 0x0203, 0x0805, 0x0805, 0x0501, 0x0806, 0x0601,
                0x0201
            ]
        );
        for suite in p.cipher_suites.iter().filter_map(|s| match s {
            SupportedCipherSuite::Tls12(s) => Some(s),
            _ => None,
        }) {
            // Every advertised CBC algorithm has an actual authenticated
            // record implementation. SHA2-CBC and AEAD never map to old TLS.
            let id = u16::from(suite.common.suite);
            let old = matches!(
                id,
                0xc00a | 0xc009 | 0xc014 | 0xc013 | 0x0035 | 0x002f | 0xc008 | 0xc012 | 0x000a
            );
            for version in [ProtocolVersion::TLSv1_0, ProtocolVersion::TLSv1_1] {
                assert_eq!(
                    crate::legacy_tdes::LEGACY_TLS_WITH_TDES
                        .cipher_suite(suite.common.suite, version)
                        .is_some(),
                    old
                );
            }
        }
    }
}

#[test]
fn sha1_handshake_policy_does_not_expand_certificate_chain_or_ordinary_policy() {
    let browser = provider(Profile::Safari16);
    for other in [crate::provider(), crate::legacy_provider::provider()] {
        assert!(
            !other
                .signature_verification_algorithms
                .supported_schemes()
                .contains(&SignatureScheme::ECDSA_SHA1_Legacy)
        );
        assert_eq!(
            browser.signature_verification_algorithms.all.len(),
            other.signature_verification_algorithms.all.len()
        );
        for (actual, expected) in browser
            .signature_verification_algorithms
            .all
            .iter()
            .zip(other.signature_verification_algorithms.all)
        {
            assert_eq!(actual.public_key_alg_id(), expected.public_key_alg_id());
            assert_eq!(actual.signature_alg_id(), expected.signature_alg_id());
        }
    }
    let input = fixtures();
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(bytes(&input["ca_der"])))
        .unwrap();
    let verifier = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), Arc::new(browser))
        .build()
        .unwrap();
    let name = ServerName::try_from("localhost").unwrap();
    let now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(1893456000));
    for curve in input["curves"].as_array().unwrap() {
        verifier
            .verify_server_cert(
                &bytes(&curve["sha256_cert_der"]).into(),
                &[],
                &name,
                &[],
                now,
            )
            .unwrap();
        // A SHA-1-signed leaf under the same trusted CA is still rejected.
        assert!(
            verifier
                .verify_server_cert(&bytes(&curve["sha1_cert_der"]).into(), &[], &name, &[], now)
                .is_err()
        );
    }
}

#[test]
fn ecdsa_sha1_verifies_independent_openssl_vectors_and_rejects_tampering() {
    let input = fixtures();
    for (index, curve) in input["curves"].as_array().unwrap().iter().enumerate() {
        let encoded = bytes(&curve["public_spki"]);
        let spki = rsa::pkcs8::SubjectPublicKeyInfoRef::from_der(&encoded).unwrap();
        let public = spki.subject_public_key.as_bytes().unwrap();
        let verifier = sha1::VERIFIERS[index];
        for vector in curve["vectors"].as_array().unwrap() {
            let message = bytes(&vector["message"]);
            let signature = bytes(&vector["signature"]);
            verifier
                .verify_signature(public, &message, &signature)
                .unwrap();
            let mut changed = message.clone();
            changed.push(0);
            assert!(
                verifier
                    .verify_signature(public, &changed, &signature)
                    .is_err()
            );
            let mut changed = signature.clone();
            *changed.last_mut().unwrap() ^= 1;
            assert!(
                verifier
                    .verify_signature(public, &message, &changed)
                    .is_err()
            );
            let mut trailing = signature.clone();
            trailing.push(0);
            assert!(
                verifier
                    .verify_signature(public, &message, &trailing)
                    .is_err()
            );
            for truncated in [&signature[..signature.len() - 1], &signature[..0]] {
                assert!(
                    verifier
                        .verify_signature(public, &message, truncated)
                        .is_err()
                );
            }
            assert!(
                verifier
                    .verify_signature(&[0; 133], &message, &signature)
                    .is_err()
            );
            assert!(
                sha1::VERIFIERS[(index + 1) % 3]
                    .verify_signature(public, &message, &signature)
                    .is_err()
            );
        }
    }
}

#[test]
fn client_ecdsa_sha1_requires_explicit_provider_and_peer_offer_on_all_three_curves() {
    let input = fixtures();
    let message = b"TLS1.2 CertificateVerify transcript\0not a prehashed digest";
    for (index, curve) in input["curves"].as_array().unwrap().iter().enumerate() {
        let der = PrivateKeyDer::Pkcs8(bytes(&curve["key_der"]).into());
        let ordinary = crate::provider()
            .key_provider
            .load_private_key(der.clone_key())
            .unwrap();
        let android11 = crate::legacy_provider::provider()
            .key_provider
            .load_private_key(der.clone_key())
            .unwrap();
        let key = provider(Profile::Ios14)
            .key_provider
            .load_private_key(der)
            .unwrap();
        assert!(
            ordinary
                .choose_scheme(&[SignatureScheme::ECDSA_SHA1_Legacy])
                .is_none()
        );
        assert!(
            android11
                .choose_scheme(&[SignatureScheme::ECDSA_SHA1_Legacy])
                .is_none()
        );
        assert!(key.choose_scheme(&[]).is_none());
        assert!(
            key.choose_scheme(&[SignatureScheme::RSA_PKCS1_SHA1])
                .is_none()
        );
        assert_eq!(
            key.public_key().unwrap().as_ref(),
            ordinary.public_key().unwrap().as_ref()
        );
        let modern = [
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
        ][index];
        assert_eq!(
            key.choose_scheme(&[SignatureScheme::ECDSA_SHA1_Legacy, modern])
                .unwrap()
                .scheme(),
            modern
        );
        let signer = key
            .choose_scheme(&[SignatureScheme::ECDSA_SHA1_Legacy])
            .unwrap();
        assert_eq!(signer.scheme(), SignatureScheme::ECDSA_SHA1_Legacy);
        let signature = signer.sign(message).unwrap();
        let encoded = bytes(&curve["public_spki"]);
        let spki = rsa::pkcs8::SubjectPublicKeyInfoRef::from_der(&encoded).unwrap();
        sha1::VERIFIERS[index]
            .verify_signature(
                spki.subject_public_key.as_bytes().unwrap(),
                message,
                &signature,
            )
            .unwrap();
    }
}
