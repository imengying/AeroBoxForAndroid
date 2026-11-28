//! Pinned Android11 wire layout and legacy client policy boundaries.
use rustls::{ClientConfig, ClientConnection, ProtocolVersion, client::ClientHelloLayout};
use std::sync::Arc;

fn config(profile: bool) -> ClientConfig {
    let mut config =
        ClientConfig::builder_with_provider(Arc::new(aerobox_crypto::legacy_provider::provider()))
            .with_protocol_versions(&[&rustls::version::TLS12])
            .unwrap()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
    config.cert_compressors.clear();
    config.cert_decompressors.clear();
    config
        .enable_legacy_tls(
            &aerobox_crypto::legacy_provider::LEGACY_TLS,
            &[
                ProtocolVersion::TLSv1_0,
                ProtocolVersion::TLSv1_1,
                ProtocolVersion::TLSv1_2,
            ],
        )
        .unwrap();
    if profile {
        config.client_hello_layout = Some(ClientHelloLayout::Android11);
    }
    config
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn android11_complete_hello_matches_pinned_utls_capture() {
    let captures: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/utls-reference/normalized-captures.json"
    ))
    .unwrap();
    let expected = captures
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["profile"] == "Android-11" && c["case"] == "default")
        .unwrap();
    let expected = expected["wire"]["random_and_session_id_zeroed_hex"]
        .as_str()
        .unwrap();
    let mut prior: Option<Vec<u8>> = None;
    for _ in 0..8 {
        let mut conn = ClientConnection::new(
            Arc::new(config(true)),
            "android11.example".try_into().unwrap(),
        )
        .unwrap();
        let mut hello = Vec::new();
        conn.write_tls(&mut hello).unwrap();
        assert_eq!(hello.len(), 192);
        assert_eq!(hello[43], 32);
        assert_ne!(&hello[11..43], &[0; 32]);
        assert_ne!(&hello[44..76], &[0; 32]);
        if let Some(prior) = &prior {
            assert_ne!(&hello[11..76], prior.as_slice());
        }
        prior = Some(hello[11..76].to_vec());
        hello[11..43].fill(0);
        hello[44..76].fill(0);
        assert_eq!(hex(&hello), expected);
    }
}

fn server_hello(version: ProtocolVersion, cipher: u16, downgrade: bool) -> Vec<u8> {
    let mut body = u16::from(version).to_be_bytes().to_vec();
    let mut random = [42; 32];
    if downgrade {
        random[24..].copy_from_slice(b"DOWNGRD\0");
    }
    body.extend(random);
    body.push(0); // no resumed session
    body.extend(cipher.to_be_bytes());
    body.extend([0, 0, 0]); // null compression, no extensions
    let mut handshake = vec![2, 0, (body.len() >> 8) as u8, body.len() as u8];
    handshake.extend(body);
    let mut record = vec![
        22,
        3,
        1,
        (handshake.len() >> 8) as u8,
        handshake.len() as u8,
    ];
    record.extend(handshake);
    record
}

fn reject(config: ClientConfig, reply: Vec<u8>, expected: &str) {
    let mut conn =
        ClientConnection::new(Arc::new(config), "android11.example".try_into().unwrap()).unwrap();
    conn.write_tls(&mut Vec::new()).unwrap();
    conn.read_tls(&mut reply.as_slice()).unwrap();
    let error = conn.process_new_packets().unwrap_err();
    assert!(format!("{error:?}").contains(expected), "{error:?}");
    assert!(conn.reader().read_to_end(&mut Vec::new()).is_err());
}

use std::io::Read;

#[test]
fn old_versions_require_opt_in_and_cannot_select_aead_or_downgrade() {
    let ordinary = ClientConfig::builder_with_provider(Arc::new(aerobox_crypto::provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    reject(
        ordinary,
        server_hello(ProtocolVersion::TLSv1_0, 0xc02f, false),
        "ServerDoesNotSupportTls12Or13",
    );
    for version in [ProtocolVersion::TLSv1_0, ProtocolVersion::TLSv1_1] {
        reject(
            config(true),
            server_hello(version, 0xc02f, false),
            "SelectedUnusableCipherSuiteForVersion",
        );
        reject(
            config(true),
            server_hello(version, 0xc013, true),
            "AttemptedDowngrade",
        );
    }
}

#[test]
fn android11_rejects_conflicting_extensions_and_resumption() {
    for mode in 0..4 {
        let mut c = config(true);
        match mode {
            0 => c.alpn_protocols = vec![b"h2".to_vec()],
            1 => c.enable_tls12_renegotiation = true,
            2 => c.enable_early_data = true,
            3 => c.resumption = rustls::client::Resumption::default(),
            _ => unreachable!(),
        }
        assert!(
            ClientConnection::new(Arc::new(c), "android11.example".try_into().unwrap()).is_err(),
            "mode {mode}"
        );
    }
}
