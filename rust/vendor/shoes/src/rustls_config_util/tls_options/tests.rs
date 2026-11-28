use super::*;
use crate::rustls_config_util::{try_create_client_config_with_options, try_create_server_config};

fn fixture() -> (String, String, String) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let (_, parsed) = x509_parser::parse_x509_certificate(cert.cert.der()).unwrap();
    let pin = STANDARD.encode(aerobox_primitives::digest::digest(
        &aerobox_primitives::digest::SHA256,
        parsed.public_key().raw,
    ));
    (cert.cert.pem(), cert.signing_key.serialize_pem(), pin)
}

fn client(
    options: &TlsClientOptions,
    verify: bool,
    quic: bool,
) -> io::Result<rustls::ClientConfig> {
    try_create_client_config_with_options(
        verify,
        vec![],
        vec![],
        true,
        None,
        quic,
        &Default::default(),
        options,
    )
}

fn handshake(
    config: rustls::ClientConfig,
    cert: &str,
    key: &str,
    name: &str,
) -> Result<(rustls::ClientConnection, rustls::ServerConnection), rustls::Error> {
    let mut client =
        rustls::ClientConnection::new(Arc::new(config), name.to_owned().try_into().unwrap())?;
    let mut server = rustls::ServerConnection::new(Arc::new(
        try_create_server_config(
            cert.as_bytes(),
            key.as_bytes(),
            vec![],
            &[],
            &[],
            &Default::default(),
        )
        .unwrap(),
    ))?;
    for _ in 0..12 {
        let mut bytes = Vec::new();
        client.write_tls(&mut bytes).unwrap();
        for fragment in bytes.chunks(23) {
            server.read_tls(&mut &fragment[..]).unwrap();
            server.process_new_packets()?;
        }
        bytes.clear();
        server.write_tls(&mut bytes).unwrap();
        for fragment in bytes.chunks(23) {
            client.read_tls(&mut &fragment[..]).unwrap();
            client.process_new_packets()?;
        }
        if !client.is_handshaking()
            && !server.is_handshaking()
            && !client.wants_write()
            && !server.wants_write()
        {
            return Ok((client, server));
        }
    }
    panic!("TLS options handshake did not converge")
}

#[test]
fn custom_roots_and_leaf_spki_pins_both_apply() {
    let (cert, key, pin) = fixture();
    let (_, _, other_pin) = fixture();
    let options = TlsClientOptions {
        root_certificates: vec![cert.clone()],
        certificate_public_key_sha256: vec![other_pin.clone(), pin],
        ..Default::default()
    };
    handshake(
        client(&options, true, false).unwrap(),
        &cert,
        &key,
        "localhost",
    )
    .unwrap();
    assert!(
        handshake(
            client(&options, true, false).unwrap(),
            &cert,
            &key,
            "wrong.test"
        )
        .is_err()
    );
    let mut wrong_pin = options.clone();
    wrong_pin.certificate_public_key_sha256 = vec![other_pin];
    assert!(
        handshake(
            client(&wrong_pin, true, false).unwrap(),
            &cert,
            &key,
            "localhost"
        )
        .is_err()
    );
    assert!(
        handshake(
            client(&wrong_pin, false, false).unwrap(),
            &cert,
            &key,
            "localhost"
        )
        .is_err()
    );
    let mut wrong_roots = options.clone();
    wrong_roots.root_certificates = vec![fixture().0];
    assert!(
        handshake(
            client(&wrong_roots, true, false).unwrap(),
            &cert,
            &key,
            "localhost"
        )
        .is_err()
    );
    // Explicit verify:false skips PKI/name validation but never bypasses pins.
    handshake(
        client(&wrong_roots, false, false).unwrap(),
        &cert,
        &key,
        "wrong.test",
    )
    .unwrap();
}

#[test]
fn disabling_sni_preserves_certificate_name_validation_and_tls_bounds() {
    let (cert, key, _) = fixture();
    for (version, suite, expected) in [
        (
            TlsVersion::V12,
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            rustls::ProtocolVersion::TLSv1_2,
        ),
        (
            TlsVersion::V13,
            "TLS_AES_256_GCM_SHA384",
            rustls::ProtocolVersion::TLSv1_3,
        ),
        (
            TlsVersion::V13,
            "TLS_CHACHA20_POLY1305_SHA256",
            rustls::ProtocolVersion::TLSv1_3,
        ),
    ] {
        let options = TlsClientOptions {
            root_certificates: vec![cert.clone()],
            min_version: Some(version),
            max_version: Some(version),
            cipher_suites: vec![suite.into()],
            disable_sni: true,
            ..Default::default()
        };
        let config = client(&options, true, false).unwrap();
        assert!(!config.enable_sni);
        assert_eq!(
            config
                .crypto_provider()
                .cipher_suites
                .iter()
                .filter(|suite| suite.tls13().is_some())
                .count(),
            3,
        );
        assert_eq!(
            config
                .crypto_provider()
                .cipher_suites
                .iter()
                .filter(|suite| suite.tls13().is_none())
                .count(),
            usize::from(version == TlsVersion::V12),
        );
        let (connection, server) = handshake(config, &cert, &key, "localhost").unwrap();
        assert_eq!(connection.protocol_version(), Some(expected));
        assert_eq!(server.server_name(), None);
        assert!(
            handshake(
                client(&options, true, false).unwrap(),
                &cert,
                &key,
                "wrong.test"
            )
            .is_err()
        );
        if version == TlsVersion::V13 {
            quinn::crypto::rustls::QuicClientConfig::with_initial(
                Arc::new(client(&options, true, true).unwrap()),
                aerobox_crypto::TLS13_AES_128_GCM_SHA256
                    .quic_suite()
                    .unwrap(),
            )
            .unwrap();
        }
    }
}

#[test]
fn invalid_tls_policies_fail_before_any_connection() {
    for json in [r#"{"min_version":"1.4"}"#, r#"{"unknown_option":true}"#] {
        assert!(serde_json::from_str::<TlsClientOptions>(json).is_err());
    }
    for json in [
        r#"{"max_version":"1.0"}"#,
        r#"{"max_version":"1.1"}"#,
        r#"{"min_version":"1.3","max_version":"1.2"}"#,
        r#"{"root_certificates":["not a PEM certificate"]}"#,
        r#"{"certificate_public_key_sha256":["invalid base64"]}"#,
        r#"{"certificate_public_key_sha256":["AQID"]}"#,
        r#"{"cipher_suites":["TLS_RSA_WITH_RC4_128_SHA"]}"#,
        r#"{"cipher_suites":["TLS_AES_128_GCM_SHA256","TLS13_AES_128_GCM_SHA256"]}"#,
        r#"{"min_version":"1.0","max_version":"1.1","cipher_suites":["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"]}"#,
    ] {
        let options: TlsClientOptions = serde_json::from_str(json).unwrap();
        assert!(client(&options, false, false).is_err(), "{json}");
    }
    assert!(
        client(
            &TlsClientOptions {
                max_version: Some(TlsVersion::V12),
                ..Default::default()
            },
            false,
            true
        )
        .is_err()
    );
}

#[test]
fn explicit_tls12_suites_leave_tls13_and_quic_policy_unchanged() {
    let default = client(&TlsClientOptions::default(), true, false).unwrap();
    // Use public IANA spellings: rustls Debug renders several real suites as
    // CipherSuite(0x...), which is not a configuration name.
    let names = [
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        "TLS_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_RSA_WITH_AES_128_CBC_SHA",
        "TLS_RSA_WITH_AES_256_CBC_SHA",
    ];
    let suites = aerobox_crypto::legacy_cbc::suites()
        .into_iter()
        .chain(aerobox_crypto::legacy_rsa::suites());
    for (name, suite) in names.into_iter().zip(suites) {
        assert!(!default.crypto_provider().cipher_suites.contains(&suite));
        let name = name.to_owned();
        let mut options = TlsClientOptions {
            cipher_suites: vec![name.clone()],
            ..Default::default()
        };
        let configured = client(&options, true, false).unwrap();
        let tls12: Vec<_> = configured
            .crypto_provider()
            .cipher_suites
            .iter()
            .copied()
            .filter(|suite| suite.tls13().is_none())
            .collect();
        assert_eq!(tls12, vec![suite]);
        assert!(client(&options, true, true).is_ok());
        options.cipher_suites.push(name);
        assert!(client(&options, true, false).is_err());
    }
}

#[tokio::test]
async fn named_and_file_roots_are_embedded_and_validated() {
    let (cert, _, pin) = fixture();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("root.pem");
    std::fs::write(&path, &cert).unwrap();
    for root in ["named-root".to_owned(), path.to_string_lossy().to_string()] {
        let entries = serde_json::json!([
            {"pem":"named-root", "data":cert},
            {"address":"127.0.0.1:19080", "protocol":{"type":"socks"}, "rules":[{
                "mask":"0.0.0.0/0", "action":"allow", "client_chain":[{
                    "address":"127.0.0.1:443", "protocol":{"type":"tls", "sni_hostname":"localhost", "options":{
                        "root_certificates":[root], "certificate_public_key_sha256":[pin], "disable_sni":true
                    }, "protocol":{"type":"socks"}}
                }]
            }]}
        ]);
        crate::embedding::EmbeddedCore::check_json(&entries.to_string())
            .await
            .unwrap();
    }
}
