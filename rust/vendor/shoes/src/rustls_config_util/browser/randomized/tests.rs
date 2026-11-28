//! Deterministic adapter cases do not replace, reset or inject the process seed.
use super::*;
use crate::config::tls::TlsClientFingerprint;
use crate::rustls_config_util::try_create_client_config_with_options;
use rustls::client::ClientHelloLayout;
use serde_json::json;

const SIGNATURES: &[u16] = &[0x0403, 0x0401, 0x0503, 0x0501, 0x0201, 0x0601, 0x0804];
const GROUPS: &[u16] = &[29, 23, 24];
const EXTENSIONS: &[u16] = &[0, 35, 13, 11, 10, 21, 51, 45, 43];
fn modern() -> Fields<'static> {
    Fields {
        minimum: 0x0303,
        maximum: 0x0304,
        suites: &[0x1303, 0x1301, 0xc02b, 0xc013],
        signatures: SIGNATURES,
        groups: GROUPS,
        shares: &[29],
        extensions: EXTENSIONS,
    }
}
fn config(fields: Fields<'_>, only: bool, alpn: &[&str]) -> io::Result<ClientConfig> {
    let mut config = ClientConfig::builder_with_provider(Arc::new(fields.provider()?))
        .with_protocol_versions(&fields.versions(only)?)
        .map_err(io::Error::other)?
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
    fields.configure(&mut config, false, only)?;
    Ok(config)
}
fn connect(config: ClientConfig) -> rustls::ClientConnection {
    rustls::ClientConnection::new(Arc::new(config), "localhost".try_into().unwrap()).unwrap()
}
fn hello_extensions(config: ClientConfig) -> Vec<(u16, Vec<u8>)> {
    let mut wire = vec![];
    connect(config).write_tls(&mut wire).unwrap();
    let mut handshake = vec![];
    let mut at = 0;
    while at < wire.len() {
        assert_eq!(wire[at], 22);
        let len = usize::from(u16::from_be_bytes([wire[at + 3], wire[at + 4]]));
        handshake.extend_from_slice(&wire[at + 5..at + 5 + len]);
        at += 5 + len;
    }
    assert_eq!(handshake[0], 1);
    let mut at = 4 + 2 + 32;
    at += 1 + usize::from(handshake[at]);
    let suites = usize::from(u16::from_be_bytes([handshake[at], handshake[at + 1]]));
    at += 2 + suites;
    at += 1 + usize::from(handshake[at]);
    let len = usize::from(u16::from_be_bytes([handshake[at], handshake[at + 1]]));
    at += 2;
    assert_eq!(at + len, handshake.len());
    let mut result = vec![];
    while at < handshake.len() {
        let id = u16::from_be_bytes([handshake[at], handshake[at + 1]]);
        let len = usize::from(u16::from_be_bytes([handshake[at + 2], handshake[at + 3]]));
        at += 4;
        result.push((id, handshake[at..at + len].to_vec()));
        at += len;
    }
    result
}
fn native(options: &TlsClientOptions, only: bool, alpn: Vec<String>) -> io::Result<ClientConfig> {
    try_create_client_config_with_options(
        true,
        vec![],
        alpn,
        true,
        None,
        only,
        &Default::default(),
        options,
    )
}
fn options() -> TlsClientOptions {
    TlsClientOptions {
        fingerprint: Some(TlsClientFingerprint::Randomized),
        ..Default::default()
    }
}

#[test]
fn randomized_adapter_retains_original_structure_for_ordinary_and_tls13_only() {
    // The first case exercises the full old-version sequence, while the second
    // begins at TLS1.2. Both keep the original cipher offer under Vision policy.
    for minimum in [0x0301, 0x0303] {
        for only in [false, true] {
            let fields = Fields {
                minimum,
                extensions: &[65281, 0, 35, 13, 11, 10, 21, 51, 45, 43],
                ..modern()
            };
            let client = config(fields, only, &[]).unwrap();
            assert_eq!(
                client.client_hello_layout,
                Some(ClientHelloLayout::Randomized)
            );
            assert!(client.randomized_client_hello.is_some());
            assert!(!client.require_ems);
            assert_eq!(client.enable_tls12_renegotiation, !only);
            assert_eq!(client.initial_key_share_groups, [NamedGroup::X25519]);
            assert!(client.alpn_protocols.is_empty());
            assert!(client.cert_compressors.is_empty() && client.cert_decompressors.is_empty());
            assert!(
                !client.enable_early_data
                    && !client.enable_delegated_credentials
                    && !client.advertise_record_size_limit
            );
            assert_eq!(
                fields
                    .provider()
                    .unwrap()
                    .cipher_suites
                    .iter()
                    .map(|s| u16::from(s.suite()))
                    .collect::<Vec<_>>(),
                fields.suites
            );
            let mut connection = connect(client);
            let mut wire = vec![];
            connection.write_tls(&mut wire).unwrap();
            assert!(!wire.is_empty());
        }
    }
    let old = Fields {
        minimum: 0x0301,
        maximum: 0x0303,
        suites: &[0xc02b, 0xc013, 5],
        signatures: &SIGNATURES[..6],
        groups: &[23, 24],
        shares: &[],
        extensions: &[0, 35, 13, 11, 10, 65281],
    };
    connect(config(old, false, &[]).unwrap());
    assert!(
        config(old, true, &[])
            .unwrap_err()
            .to_string()
            .contains("TLS1.3-only")
    );
}

#[test]
fn randomized_alpn_and_legacy_alps_follow_the_fixed_extension_objects() {
    assert!(
        config(modern(), false, &["h2"])
            .unwrap_err()
            .to_string()
            .contains("did not select ALPN")
    );
    let with_alpn = Fields {
        extensions: &[0, 35, 13, 11, 10, 21, 51, 45, 43, 16],
        ..modern()
    };
    let client = config(with_alpn, false, &[]).unwrap();
    assert_eq!(
        client.alpn_protocols,
        [b"h2".to_vec(), b"http/1.1".to_vec()]
    );
    assert!(client.application_settings.is_none());
    connect(client);
    let with_alps = Fields {
        extensions: &[0, 35, 13, 11, 10, 21, 51, 45, 43, 16, 17513],
        ..modern()
    };
    let client = config(with_alps, false, &["http/1.1"]).unwrap();
    assert_eq!(client.alpn_protocols, [b"http/1.1".to_vec()]);
    assert!(client.application_settings.is_some());
    let extensions = hello_extensions(client);
    assert_eq!(
        extensions.iter().find(|(id, _)| *id == 17513).unwrap().1,
        [0, 3, 2, b'h', b'2']
    );
    assert!(!extensions.iter().any(|(id, _)| *id == 17613));
    assert_eq!(
        extensions.iter().find(|(id, _)| *id == 16).unwrap().1,
        [0, 9, 8, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1']
    );
}

#[test]
fn randomized_adapter_rejects_inconsistent_capabilities_and_exact_policy_conflicts() {
    for fields in [
        Fields {
            shares: &[29, 4588],
            ..modern()
        },
        Fields {
            groups: &[29, 23, 24, 0xffff],
            ..modern()
        },
        Fields {
            suites: &[0x1301, 0x1301],
            ..modern()
        },
        Fields {
            suites: &[0xffff],
            ..modern()
        },
    ] {
        let first = config(fields, false, &[]).unwrap_err().to_string();
        assert_eq!(config(fields, false, &[]).unwrap_err().to_string(), first);
    }
    let fields = modern();
    let groups: TlsKeyExchangeGroups =
        serde_json::from_value(json!(["X25519", "SecP256r1", "SecP384r1"])).unwrap();
    let exact = TlsClientOptions {
        min_version: Some(TlsVersion::V12),
        max_version: Some(TlsVersion::V13),
        ..options()
    };
    fields.validate_policy(&groups, &exact).unwrap();
    for bad in [
        TlsClientOptions {
            min_version: Some(TlsVersion::V10),
            ..exact.clone()
        },
        TlsClientOptions {
            max_version: Some(TlsVersion::V12),
            ..exact.clone()
        },
        serde_json::from_value(
            json!({"fingerprint":"randomized","ech":{"query_server_name":"cover.test"}}),
        )
        .unwrap(),
    ] {
        assert!(fields.validate_policy(&groups, &bad).is_err());
    }
    let reordered: TlsKeyExchangeGroups =
        serde_json::from_value(json!(["SecP256r1", "X25519", "SecP384r1"])).unwrap();
    assert!(fields.validate_policy(&reordered, &exact).is_err());
}

#[test]
fn randomized_process_plan_drives_native_builders_without_resampling() {
    let original = aerobox_fingerprint::randomized::process_plan().unwrap();
    for _ in 0..3 {
        match original.for_stream(false) {
            Err(expected) => {
                let error = native(&options(), false, vec![]).unwrap_err();
                assert_eq!(error.to_string(), expected.to_string());
            }
            Ok(expected) => {
                let client = native(&options(), false, vec![]).unwrap();
                assert_eq!(
                    client
                        .initial_key_share_groups
                        .iter()
                        .copied()
                        .map(u16::from)
                        .collect::<Vec<_>>(),
                    expected.shares()
                );
                assert_eq!(
                    !client.alpn_protocols.is_empty(),
                    expected.extensions().contains(&16)
                );
                connect(client);
                let names = provider(false)
                    .unwrap()
                    .cipher_suites
                    .iter()
                    .map(|s| s.suite().as_str().unwrap().to_owned())
                    .collect::<Vec<_>>();
                let mut explicit = TlsClientOptions {
                    cipher_suites: names,
                    ..options()
                };
                connect(native(&explicit, false, vec![]).unwrap());
                explicit.cipher_suites.reverse();
                assert!(
                    native(&explicit, false, vec![])
                        .unwrap_err()
                        .to_string()
                        .contains("explicit cipher suite policy")
                );
                let alpn = native(&options(), false, vec!["http/1.1".into()]);
                assert_eq!(alpn.is_ok(), expected.extensions().contains(&16));
                let only = native(&options(), true, vec![]);
                assert_eq!(only.is_ok(), expected.maximum() == 0x0304);
                if let Ok(client) = only {
                    connect(client);
                }
            }
        }
        assert!(std::ptr::eq(
            original,
            aerobox_fingerprint::randomized::process_plan().unwrap()
        ));
        assert_eq!(
            super::super::ciphers(TlsClientFingerprint::Randomized).unwrap(),
            original.suites()
        );
        let ordinary = native(&Default::default(), false, vec![]).unwrap();
        assert!(
            ordinary.client_hello_layout.is_none() && ordinary.randomized_client_hello.is_none()
        );
    }
}

#[test]
fn randomized_reality_applies_hybrid_removal_before_capability_validation() {
    use crate::reality::{CipherSuite, RealityClientConfig};
    let original = aerobox_fingerprint::randomized::process_plan().unwrap();
    for _ in 0..2 {
        match original.for_stream(true) {
            Err(expected) => assert_eq!(
                provider(true).unwrap_err().to_string(),
                expected.to_string()
            ),
            Ok(plan) => {
                let crypto = provider(true).unwrap();
                assert!(
                    !crypto
                        .kx_groups
                        .iter()
                        .any(|g| g.name() == NamedGroup::X25519MLKEM768)
                );
                assert_eq!(
                    crypto
                        .kx_groups
                        .iter()
                        .map(|g| u16::from(g.name()))
                        .collect::<Vec<_>>(),
                    plan.groups()
                );
                let exact = plan
                    .suites()
                    .iter()
                    .filter_map(|id| match id {
                        0x1301 => Some(CipherSuite::AES_128_GCM_SHA256),
                        0x1302 => Some(CipherSuite::AES_256_GCM_SHA384),
                        0x1303 => Some(CipherSuite::CHACHA20_POLY1305_SHA256),
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                validate_reality_suites(&exact).unwrap();
                let mut wrong = exact.clone();
                wrong.reverse();
                if wrong == exact {
                    wrong.push(CipherSuite::AES_128_GCM_SHA256);
                }
                assert!(validate_reality_suites(&wrong).is_err());
                let make = || RealityClientConfig {
                    mldsa65_verify: None,
                    public_key: [9; 32],
                    short_id: [1; 8],
                    server_name: "cover.test".try_into().unwrap(),
                    cipher_suites: exact.clone(),
                };
                make()
                    .create_connection_with_profile(vec![], Some(TlsClientFingerprint::Randomized))
                    .unwrap();
                assert_eq!(
                    make()
                        .create_connection_with_profile(
                            vec!["http/1.1".into()],
                            Some(TlsClientFingerprint::Randomized)
                        )
                        .is_ok(),
                    plan.extensions().contains(&16)
                );
            }
        }
        assert!(std::ptr::eq(
            original,
            aerobox_fingerprint::randomized::process_plan().unwrap()
        ));
    }
}

async fn compile(
    protocol: serde_json::Value,
    quic: bool,
) -> io::Result<crate::config::ValidatedConfigs> {
    let hop = if quic {
        json!({"address":"127.0.0.1:9","transport":"quic","quic_settings":{"options":{"fingerprint":"randomized"}},"protocol":{"type":"noop"}})
    } else {
        json!({"address":"127.0.0.1:9","protocol":protocol})
    };
    crate::config::compile_configs(
        serde_json::from_value(json!([{"address":"127.0.0.1:0","protocol":{"type":"socks"},
        "rules":[{"conditions":{"any_destination":true},"client_chain":hop}]}]))
        .map_err(io::Error::other)?,
    )
    .await
}

#[tokio::test]
async fn randomized_native_compiler_rejects_unsupported_transports_before_connecting() {
    let original = aerobox_fingerprint::randomized::process_plan().unwrap();
    let ordinary = json!({"type":"tls","sni_hostname":"cover.test","options":{"fingerprint":"randomized"},"protocol":{"type":"noop"}});
    for _ in 0..2 {
        assert_eq!(
            compile(ordinary.clone(), false).await.is_ok(),
            original.for_stream(false).is_ok()
        );
        assert!(
            compile(json!(null), true)
                .await
                .err()
                .expect("configuration must fail")
                .to_string()
                .contains("cannot be used with QUIC")
        );
        let mut naive = ordinary.clone();
        naive["protocol"] = json!({"type":"naiveproxy","username":"user","password":"test"});
        assert!(
            compile(naive, false)
                .await
                .err()
                .expect("configuration must fail")
                .to_string()
                .contains("cannot be used with Naive")
        );
        let mut reality = json!({"type":"reality","fingerprint":"randomized","sni_hostname":"cover.test",
            "public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","short_id":"0101010101010101","protocol":{"type":"noop"}});
        assert_eq!(
            compile(reality.clone(), false).await.is_ok(),
            original.for_stream(true).is_ok()
        );
        reality["protocol"] = json!({"type":"naiveproxy","username":"user","password":"test"});
        assert!(
            compile(reality, false)
                .await
                .err()
                .expect("configuration must fail")
                .to_string()
                .contains("cannot be used with Naive")
        );
        let mut vision = ordinary.clone();
        vision["vision"] = true.into();
        let rejected = compile(vision.clone(), false)
            .await
            .err()
            .expect("Vision requires VLESS");
        assert!(rejected.to_string().contains("requires VLESS"));
        vision["protocol"] =
            json!({"type":"vless", "user_id":"01010101-0101-4101-8101-010101010101"});
        assert_eq!(
            compile(vision, false).await.is_ok(),
            original.for_stream(false).is_ok() && original.maximum() == 0x0304
        );
        assert!(std::ptr::eq(
            original,
            aerobox_fingerprint::randomized::process_plan().unwrap()
        ));
    }
}

fn verified_config(fields: Fields<'_>, only: bool, policy: &TlsClientOptions) -> ClientConfig {
    // Use the same native trust and pin helpers with a deterministic private
    // adapter fixture, so malformed process seeds cannot skip authentication.
    let provider = Arc::new(fields.provider().unwrap());
    let roots = crate::rustls_config_util::tls_options::roots(policy).unwrap();
    let verifier =
        rustls::client::WebPkiServerVerifier::builder_with_provider(roots, provider.clone())
            .build()
            .unwrap();
    let verifier = crate::rustls_config_util::tls_options::pin_verifier(verifier, policy).unwrap();
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&fields.versions(only).unwrap())
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    fields.configure(&mut config, false, only).unwrap();
    config
}
fn authenticate(
    client: ClientConfig,
    tls12: bool,
    name: &str,
    cert: &rcgen::CertifiedKey<rcgen::KeyPair>,
) -> Result<(), rustls::Error> {
    let mut client =
        rustls::ClientConnection::new(Arc::new(client), name.to_owned().try_into().unwrap())?;
    let mut server = rustls::ServerConfig::builder_with_provider(aerobox_crypto::shared_provider())
        .with_protocol_versions(&[if tls12 {
            &rustls::version::TLS12
        } else {
            &rustls::version::TLS13
        }])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )
        .unwrap();
    server.require_ems = false;
    let mut server = rustls::ServerConnection::new(Arc::new(server))?;
    for _ in 0..12 {
        let mut wire = vec![];
        client.write_tls(&mut wire).unwrap();
        server.read_tls(&mut wire.as_slice()).unwrap();
        server.process_new_packets()?;
        wire.clear();
        server.write_tls(&mut wire).unwrap();
        for part in wire.chunks(23) {
            client.read_tls(&mut part.as_ref()).unwrap();
            client.process_new_packets()?;
        }
        if !client.is_handshaking() && !server.is_handshaking() {
            if tls12 {
                assert!(matches!(
                    client.export_keying_material([0u8; 32], b"randomized no EMS", None),
                    Err(rustls::Error::General(_))
                ));
            } else {
                assert_eq!(
                    client.export_keying_material(
                        [0u8; 32],
                        b"randomized authenticated",
                        Some(b"context")
                    )?,
                    server.export_keying_material(
                        [0u8; 32],
                        b"randomized authenticated",
                        Some(b"context")
                    )?
                );
            }
            return Ok(());
        }
    }
    panic!("randomized authenticated handshake did not converge")
}
#[test]
fn randomized_native_trust_name_pin_and_tls13_only_remain_enforced() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let (_, parsed) = x509_parser::parse_x509_certificate(cert.cert.der()).unwrap();
    let pin = STANDARD.encode(aerobox_primitives::digest::digest(
        &aerobox_primitives::digest::SHA256,
        parsed.public_key().raw,
    ));
    let good = TlsClientOptions {
        root_certificates: vec![cert.cert.pem()],
        certificate_public_key_sha256: vec![pin],
        ..options()
    };
    for only in [false, true] {
        authenticate(
            verified_config(modern(), only, &good),
            false,
            "localhost",
            &cert,
        )
        .unwrap();
        let error = authenticate(
            verified_config(modern(), only, &good),
            false,
            "wrong.test",
            &cert,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            rustls::Error::InvalidCertificate(
                rustls::CertificateError::NotValidForName
                    | rustls::CertificateError::NotValidForNameContext { .. }
            )
        ));
        let mut bad = good.clone();
        bad.certificate_public_key_sha256 = vec![STANDARD.encode([0; 32])];
        assert!(
            authenticate(
                verified_config(modern(), only, &bad),
                false,
                "localhost",
                &cert
            )
            .unwrap_err()
            .to_string()
            .contains("pin")
        );
        let other = rcgen::generate_simple_self_signed(vec!["different issuer".into()]).unwrap();
        bad = good.clone();
        bad.root_certificates = vec![other.cert.pem()];
        assert!(
            authenticate(
                verified_config(modern(), only, &bad),
                false,
                "localhost",
                &cert
            )
            .is_err()
        );
    }
    authenticate(
        verified_config(modern(), false, &good),
        true,
        "localhost",
        &cert,
    )
    .unwrap();
    assert!(
        authenticate(
            verified_config(modern(), true, &good),
            true,
            "localhost",
            &cert
        )
        .is_err()
    );
    // The actual public runtime route uses its independently fixed plan. When
    // ordinary setup is invalid, its exact stable failure was checked above.
    if let Ok(plan) = plan(false) {
        if plan.maximum() == 0x0304 {
            authenticate(
                native(&good, false, vec![]).unwrap(),
                false,
                "localhost",
                &cert,
            )
            .unwrap();
            let mut bad = good;
            bad.certificate_public_key_sha256 = vec![STANDARD.encode([0; 32])];
            assert!(
                authenticate(
                    native(&bad, false, vec![]).unwrap(),
                    false,
                    "localhost",
                    &cert
                )
                .unwrap_err()
                .to_string()
                .contains("pin")
            );
        }
    }
}
