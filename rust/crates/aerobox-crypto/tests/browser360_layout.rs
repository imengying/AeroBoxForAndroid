//! Actual advertised values, exact independent captures, and unsupported replies.
#[path = "support/browser360.rs"]
mod support;
use rustls::{ClientConfig, ClientConnection, Error};
use std::{
    io::{Read, Write},
    sync::Arc,
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn start(config: ClientConfig, name: &str) -> (ClientConnection, Vec<u8>) {
    let mut client =
        ClientConnection::new(Arc::new(config), name.to_owned().try_into().unwrap()).unwrap();
    let mut wire = Vec::new();
    client.write_tls(&mut wire).unwrap();
    (client, wire)
}

#[test]
#[ignore = "requires AEROBOX_360_REFERENCE_CAPTURE and AEROBOX_360_RUST_CAPTURE"]
fn all_fixed_utls_sni_alpn_first_flights() {
    let reference = std::env::var_os("AEROBOX_360_REFERENCE_CAPTURE").unwrap();
    let output = std::env::var_os("AEROBOX_360_RUST_CAPTURE").unwrap();
    let cases: Vec<serde_json::Value> =
        serde_json::from_slice(&std::fs::read(reference).unwrap()).unwrap();
    let mut actual = vec![];
    for case in cases {
        if case["name"] != "360" || case.get("skipped_reason").is_some() {
            continue;
        }
        assert_eq!(case["build_error"], "");
        assert_eq!(case["handshake_complete"], false);
        assert!(case.get("panic").is_none());
        assert!(case.get("validation_error").is_none());
        let mut cfg = support::config();
        if let Some(alpn) = case["requested_alpn"].as_array().filter(|a| !a.is_empty()) {
            cfg.alpn_protocols = alpn
                .iter()
                .map(|p| p.as_str().unwrap().as_bytes().to_vec())
                .collect();
        }
        let name = case["server_name"].as_str().unwrap();
        cfg.enable_sni = !name.is_empty();
        let (_, wire) = start(
            cfg,
            if name.is_empty() {
                "browser-profile.example"
            } else {
                name
            },
        );
        actual.push(serde_json::json!({"name":"360", "case":case["case"],
            "profile":case["profile"], "wire_hex":hex(&wire)}));
    }
    assert!(actual.len() >= 10, "complete base SNI/ALPN matrix required");
    std::fs::write(output, serde_json::to_vec_pretty(&actual).unwrap()).unwrap();
}

#[test]
fn capability_set_is_real_bounded_and_does_not_change_the_ordinary_provider() {
    use rustls::client::LegacyTlsProvider;
    let provider = aerobox_crypto::browser360::provider();
    assert_eq!(
        provider
            .cipher_suites
            .iter()
            .map(|s| u16::from(s.suite()))
            .collect::<Vec<_>>(),
        aerobox_crypto::browser360::CIPHER_IDS
    );
    assert_eq!(
        provider
            .signature_verification_algorithms
            .supported_schemes()
            .iter()
            .map(|s| u16::from(*s))
            .collect::<Vec<_>>(),
        [0x0401, 0x0501, 0x0201, 0x0403, 0x0503, 0x0203]
    );
    assert_eq!(
        provider
            .kx_groups
            .iter()
            .map(|g| u16::from(g.name()))
            .collect::<Vec<_>>(),
        [23, 24, 25]
    );
    for id in [0x0039, 0x006b, 0x003d, 0x0033, 0x0067, 0x0032, 0x0004] {
        assert!(
            provider
                .cipher_suites
                .iter()
                .all(|s| u16::from(s.suite()) != id)
        );
        for version in [
            rustls::ProtocolVersion::TLSv1_0,
            rustls::ProtocolVersion::TLSv1_1,
        ] {
            assert!(
                aerobox_crypto::browser360::LEGACY_TLS
                    .cipher_suite(id.into(), version)
                    .is_none()
            );
        }
    }
    let ordinary = aerobox_crypto::provider();
    assert!(
        ordinary
            .cipher_suites
            .iter()
            .all(|s| !matches!(u16::from(s.suite()), 0xc007 | 0xc011 | 0x0005 | 0x000a))
    );
    assert!(
        !ordinary
            .signature_verification_algorithms
            .supported_schemes()
            .contains(&rustls::SignatureScheme::RSA_PKCS1_SHA1)
    );
    assert!(
        !ordinary
            .signature_verification_algorithms
            .supported_schemes()
            .contains(&rustls::SignatureScheme::ECDSA_SHA1_Legacy)
    );
}

pub fn message(typ: u8, body: &[u8]) -> Vec<u8> {
    let mut msg = vec![
        typ,
        (body.len() >> 16) as u8,
        (body.len() >> 8) as u8,
        body.len() as u8,
    ];
    msg.extend(body);
    msg
}
pub fn record(body: &[u8]) -> Vec<u8> {
    let mut wire = vec![22, 3, 3, (body.len() >> 8) as u8, body.len() as u8];
    wire.extend(body);
    wire
}
fn reply(cipher: u16, extension: Option<(u16, &[u8])>) -> Vec<u8> {
    let mut body = vec![3, 3];
    body.extend([42; 32]);
    body.push(0);
    body.extend(cipher.to_be_bytes());
    body.push(0);
    let mut extensions = vec![];
    if let Some((typ, data)) = extension {
        extensions.extend(typ.to_be_bytes());
        extensions.extend((data.len() as u16).to_be_bytes());
        extensions.extend(data);
    }
    body.extend((extensions.len() as u16).to_be_bytes());
    body.extend(extensions);
    record(&message(2, &body))
}
fn rejected(wire: Vec<u8>, expected: &str) {
    let (mut client, _) = start(support::config(), "localhost");
    client.read_tls(&mut wire.as_slice()).unwrap();
    let error = client.process_new_packets().unwrap_err();
    assert!(format!("{error:?}").contains(expected), "{error:?}");
    assert_eq!(client.process_new_packets().unwrap_err(), error);
    assert!(client.writer().write(b"not application data").is_err());
    let mut byte = [0; 1];
    assert!(client.reader().read(&mut byte).is_err());
    assert_eq!(byte, [0]);
    assert!(
        client
            .export_keying_material([0; 32], b"unverified", None)
            .is_err()
    );
}
#[test]
fn fake_disabled_suites_and_advertisement_only_extensions_fail_explicitly() {
    for id in [0x0039, 0x006b, 0x003d, 0x0033, 0x0067, 0x0032, 0x0004] {
        rejected(reply(id, None), "advertised-only cipher suite");
    }
    for typ in [13172, 30031] {
        for data in [b"".as_slice(), b"\x08http/1.1"] {
            rejected(
                reply(0xc013, Some((typ, data))),
                "does not implement NPN or ChannelID",
            );
        }
    }
    rejected(
        reply(0xc013, Some((23, b""))),
        "UnsolicitedServerHelloExtension",
    );
    rejected(reply(0x1301, None), "SelectedUnofferedCipherSuite");
}
#[test]
fn incompatible_policy_fails_before_emitting_any_hello() {
    for change in 0..10 {
        let mut config = support::config();
        match change {
            0 => config.enable_tls12_renegotiation = false,
            1 => config.require_ems = true,
            2 => config.enable_early_data = true,
            3 => config.resumption = rustls::client::Resumption::default(),
            4 => config.alpn_protocols.clear(),
            5 => config.initial_key_share_groups = vec![rustls::NamedGroup::secp256r1],
            6 => config.cert_decompressors = vec![rustls::compress::ZLIB_DECOMPRESSOR],
            7 => config.enable_delegated_credentials = true,
            8 => config.advertise_record_size_limit = true,
            9 => config.enable_secret_extraction = true,
            _ => unreachable!(),
        }
        let result = ClientConnection::new(Arc::new(config), "localhost".try_into().unwrap());
        assert!(
            matches!(result, Err(Error::General(_))),
            "conflict {change}: {result:?}"
        );
    }
}

fn vector24(value: &[u8]) -> Vec<u8> {
    let mut output = vec![
        (value.len() >> 16) as u8,
        (value.len() >> 8) as u8,
        value.len() as u8,
    ];
    output.extend(value);
    output
}

#[test]
fn actual_signed_server_flights_require_an_implemented_final_signature_offer() {
    // Sign the real randoms and fresh ECDHE parameters. An unoffered signature
    // must be refused even when the peer possesses the authenticated RSA key.
    for scheme in [
        0x0401u16, 0x0201, 0x0804, 0x0601, 0x0402, 0x0202, 0x0403, 0x0203,
    ] {
        let ecdsa = matches!(scheme, 0x0403 | 0x0203);
        let allowed = matches!(scheme, 0x0401 | 0x0201 | 0x0403 | 0x0203);
        let (cert, key): (&[u8], &[u8]) = if ecdsa {
            (
                include_bytes!("fixtures/ecdsa-cert.der"),
                include_bytes!("fixtures/ecdsa-key.der"),
            )
        } else {
            (
                include_bytes!("fixtures/rsa-cert.der"),
                include_bytes!("fixtures/rsa-key.der"),
            )
        };
        let crypto = aerobox_crypto::android_browser::provider(
            aerobox_crypto::android_browser::Profile::Ios14,
        );
        let key = crypto
            .key_provider
            .load_private_key(rustls::pki_types::PrivatePkcs8KeyDer::from(key.to_vec()).into())
            .unwrap();
        let signing_scheme = if matches!(scheme, 0x0402 | 0x0202) {
            0x0401
        } else {
            scheme
        };
        let signer = key.choose_scheme(&[signing_scheme.into()]).unwrap();
        let group = crypto
            .kx_groups
            .iter()
            .find(|g| g.name() == rustls::NamedGroup::secp256r1)
            .unwrap()
            .start()
            .unwrap();
        let mut params = vec![3, 0, 23, group.pub_key().len() as u8];
        params.extend(group.pub_key());
        let (mut client, hello) = start(support::config(), "localhost");
        let mut signed = hello[11..43].to_vec();
        signed.extend([42; 32]);
        signed.extend(&params);
        let signature = signer.sign(&signed).unwrap();
        let mut kx = params;
        kx.extend(scheme.to_be_bytes());
        kx.extend((signature.len() as u16).to_be_bytes());
        kx.extend(signature);
        let certificate = message(11, &vector24(&vector24(cert)));
        let mut flight = reply(if ecdsa { 0xc009 } else { 0xc013 }, Some((65281, &[0])));
        flight.extend(record(&certificate));
        flight.extend(record(&message(12, &kx)));
        flight.extend(record(&message(14, &[])));
        client.read_tls(&mut flight.as_slice()).unwrap();
        if allowed {
            client.process_new_packets().unwrap();
            assert!(
                client.is_handshaking(),
                "Finished is deliberately not supplied"
            );
        } else {
            let error = client.process_new_packets().unwrap_err();
            assert!(
                format!("{error:?}").contains("SignedHandshakeWithUnadvertisedSigScheme"),
                "{scheme:04x}: {error:?}"
            );
            assert_eq!(client.process_new_packets().unwrap_err(), error);
            assert!(client.writer().write(b"unverified").is_err());
        }
        assert!(
            client
                .export_keying_material([0; 32], b"unfinished", None)
                .is_err()
        );
    }
}
