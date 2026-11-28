#![allow(clippy::disallowed_types)]

use std::sync::{Arc, Mutex};

use rustls::crypto::{ActiveKeyExchange, SupportedKxGroup, aws_lc_rs};
use rustls::pki_types::ServerName;
use rustls::reality::ClientHooks;
use rustls::{ClientConnection, Error, ServerConnection};
use rustls_test::{KeyType, do_handshake, make_client_config_with_versions, make_server_config};

#[derive(Debug, Default)]
struct HelloCapture {
    client: Vec<u8>,
    server: Vec<u8>,
}

#[derive(Debug)]
struct Hooks(Arc<Mutex<HelloCapture>>);

impl ClientHooks for Hooks {
    fn start_key_exchange(
        &mut self,
        group: &'static dyn SupportedKxGroup,
    ) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        group.start()
    }

    fn session_id(&mut self, hello: &[u8]) -> Result<[u8; 32], Error> {
        assert_eq!(hello[0], 1);
        assert_eq!(hello[38], 32);
        Ok([0xa7; 32])
    }

    fn server_hello(&mut self, client: &[u8], server: &[u8]) -> Result<(), Error> {
        let mut capture = self.0.lock().unwrap();
        capture.client = client.to_vec();
        capture.server = server.to_vec();
        Ok(())
    }
}

#[test]
fn finalized_session_id_and_exact_hello_context_complete_handshake() {
    let provider = aws_lc_rs::default_provider();
    let config =
        make_client_config_with_versions(KeyType::Rsa2048, &[&rustls::version::TLS13], &provider);
    let capture = Arc::new(Mutex::new(HelloCapture::default()));
    let mut client = ClientConnection::new_reality(
        Arc::new(config),
        ServerName::try_from("localhost").unwrap(),
        Box::new(Hooks(capture.clone())),
    )
    .unwrap();
    let mut server =
        ServerConnection::new(Arc::new(make_server_config(KeyType::Rsa2048, &provider))).unwrap();
    let mut client_wire = Vec::new();
    client
        .write_tls(&mut client_wire)
        .unwrap();
    assert_eq!(&client_wire[44..76], &[0xa7; 32]);
    server
        .read_tls(&mut client_wire.as_slice())
        .unwrap();
    server.process_new_packets().unwrap();
    let mut server_wire = Vec::new();
    server
        .write_tls(&mut server_wire)
        .unwrap();
    let server_hello_len = u16::from_be_bytes([server_wire[3], server_wire[4]]) as usize;
    let mut remaining = server_wire.as_slice();
    while !remaining.is_empty() {
        assert!(client.read_tls(&mut remaining).unwrap() > 0);
        client.process_new_packets().unwrap();
    }
    do_handshake(&mut client, &mut server);
    assert!(!client.is_handshaking());
    assert!(!server.is_handshaking());
    let capture = capture.lock().unwrap();
    assert_eq!(capture.client, client_wire[5..]);
    assert_eq!(capture.server, server_wire[5..5 + server_hello_len]);
}

#[test]
fn reality_rejects_tls12_configuration() {
    let provider = aws_lc_rs::default_provider();
    let config = rustls_test::make_client_config(KeyType::Rsa2048, &provider);
    let result = ClientConnection::new_reality(
        Arc::new(config),
        ServerName::try_from("localhost").unwrap(),
        Box::new(Hooks(Arc::default())),
    );
    assert!(matches!(result, Err(Error::General(_))));
}

#[test]
fn reality_rejects_wrong_session_id_echo() {
    let provider = aws_lc_rs::default_provider();
    let config =
        make_client_config_with_versions(KeyType::Rsa2048, &[&rustls::version::TLS13], &provider);
    let mut client = ClientConnection::new_reality(
        Arc::new(config),
        ServerName::try_from("localhost").unwrap(),
        Box::new(Hooks(Arc::default())),
    )
    .unwrap();
    let mut server =
        ServerConnection::new(Arc::new(make_server_config(KeyType::Rsa2048, &provider))).unwrap();
    let mut wire = Vec::new();
    client.write_tls(&mut wire).unwrap();
    server
        .read_tls(&mut wire.as_slice())
        .unwrap();
    server.process_new_packets().unwrap();
    wire.clear();
    server.write_tls(&mut wire).unwrap();
    wire[44] ^= 1;
    client
        .read_tls(&mut wire.as_slice())
        .unwrap();
    assert!(matches!(
        client.process_new_packets(),
        Err(Error::PeerIncompatible(
            rustls::PeerIncompatible::RealityUnsupported
        ))
    ));
}

fn target_hello(
    provider: &rustls::crypto::CryptoProvider,
) -> (ClientConnection, rustls::ServerConfig, Vec<u8>, Vec<u8>) {
    let config =
        make_client_config_with_versions(KeyType::Ed25519, &[&rustls::version::TLS13], provider);
    let server_config = rustls_test::make_server_config_with_versions(
        KeyType::Ed25519,
        &[&rustls::version::TLS13],
        provider,
    );
    let mut client =
        ClientConnection::new(Arc::new(config), ServerName::try_from("localhost").unwrap())
            .unwrap();
    let mut target = ServerConnection::new(Arc::new(server_config.clone())).unwrap();
    let mut wire = Vec::new();
    client.write_tls(&mut wire).unwrap();
    let mut remaining = wire.as_slice();
    while !remaining.is_empty() {
        assert!(target.read_tls(&mut remaining).unwrap() > 0);
        target.process_new_packets().unwrap();
    }
    let mut response = Vec::new();
    target.write_tls(&mut response).unwrap();
    let len = u16::from_be_bytes([response[3], response[4]]) as usize;
    (client, server_config, wire, response[5..5 + len].to_vec())
}

fn mask_key_share(hello: &[u8]) -> Vec<u8> {
    let mut masked = hello.to_vec();
    let mut offset = 44 + usize::from(hello[38]);
    while offset < hello.len() {
        let typ = u16::from_be_bytes([hello[offset], hello[offset + 1]]);
        let len = u16::from_be_bytes([hello[offset + 2], hello[offset + 3]]) as usize;
        if typ == 51 {
            masked[offset + 8..offset + 4 + len].fill(0);
        }
        offset += 4 + len;
    }
    masked
}

#[test]
fn prepared_server_hello_preserves_target_and_completes_all_suites_and_groups() {
    for group in [
        aws_lc_rs::kx_group::X25519,
        aws_lc_rs::kx_group::X25519MLKEM768,
    ] {
        for suite in aws_lc_rs::default_provider()
            .cipher_suites
            .into_iter()
            .filter(|s| s.tls13().is_some())
        {
            for reverse in [false, true] {
                let provider = rustls::crypto::CryptoProvider {
                    cipher_suites: vec![suite],
                    kx_groups: vec![group],
                    ..aws_lc_rs::default_provider()
                };
                let (mut client, server_config, client_wire, mut template) =
                    target_hello(&provider);
                if reverse {
                    let offset = 44 + usize::from(template[38]);
                    let len =
                        u16::from_be_bytes([template[offset + 2], template[offset + 3]]) as usize;
                    template[offset..].rotate_left(4 + len);
                }
                let prepared = rustls::reality::PreparedServerHello::new(
                    &client_wire[5..],
                    &template,
                    &provider,
                )
                .unwrap();
                assert_eq!(
                    mask_key_share(prepared.server_hello()),
                    mask_key_share(&template)
                );
                assert_ne!(prepared.server_hello(), template);
                assert_eq!(prepared.cipher_suite(), suite.suite());
                assert_eq!(prepared.group(), group.name());
                let final_hello = prepared.server_hello().to_vec();
                let mut server =
                    ServerConnection::new_reality(Arc::new(server_config), prepared).unwrap();
                let mut remaining = client_wire.as_slice();
                while !remaining.is_empty() {
                    server.read_tls(&mut remaining).unwrap();
                    server.process_new_packets().unwrap();
                }
                let mut response = Vec::new();
                server.write_tls(&mut response).unwrap();
                assert_eq!(&response[5..5 + final_hello.len()], final_hello);
                let mut remaining = response.as_slice();
                while !remaining.is_empty() {
                    assert!(client.read_tls(&mut remaining).unwrap() > 0);
                    client.process_new_packets().unwrap();
                }
                do_handshake(&mut client, &mut server);
                assert_eq!(client.negotiated_cipher_suite(), Some(suite));
            }
        }
    }
}

#[test]
fn prepared_hello_rejects_unsupported_template_and_client_substitution() {
    let provider = aws_lc_rs::default_provider();
    let (_, server_config, client_wire, template) = target_hello(&provider);
    for offset in [0, 1, 4, 39] {
        let mut bad = template.clone();
        bad[offset] ^= 1;
        assert!(
            rustls::reality::PreparedServerHello::new(&client_wire[5..], &bad, &provider).is_err()
        );
    }
    let prepared =
        rustls::reality::PreparedServerHello::new(&client_wire[5..], &template, &provider).unwrap();
    let mut server = ServerConnection::new_reality(Arc::new(server_config), prepared).unwrap();
    let mut different_client = client_wire;
    different_client[11] ^= 1;
    server
        .read_tls(&mut different_client.as_slice())
        .unwrap();
    assert!(server.process_new_packets().is_err());
}

fn record_lengths(wire: &[u8]) -> Vec<usize> {
    let mut lengths = Vec::new();
    let mut remaining = wire;
    while !remaining.is_empty() {
        let len = 5 + u16::from_be_bytes([remaining[3], remaining[4]]) as usize;
        lengths.push(len);
        remaining = &remaining[len..];
    }
    lengths
}

#[derive(Debug, Default)]
struct HandshakeSecret(Mutex<Vec<u8>>);

impl rustls::KeyLog for HandshakeSecret {
    fn log(&self, label: &str, _: &[u8], secret: &[u8]) {
        if label == "SERVER_HANDSHAKE_TRAFFIC_SECRET" {
            *self.0.lock().unwrap() = secret.to_vec();
        }
    }
}

#[test]
fn reality_does_not_change_ordinary_tls_sni_acknowledgement() {
    use rustls::crypto::cipher::{AeadKey, InboundOpaqueMessage, Iv};
    use rustls::crypto::tls13::{OkmBlock, expand};
    use rustls::{ContentType, ProtocolVersion, SupportedCipherSuite};

    let cipher = aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384;
    let SupportedCipherSuite::Tls13(suite) = cipher else {
        unreachable!();
    };
    let provider = rustls::crypto::CryptoProvider {
        cipher_suites: vec![cipher],
        ..aws_lc_rs::default_provider()
    };
    let (_, mut config, _, _) = target_hello(&provider);
    let secret = Arc::new(HandshakeSecret::default());
    config.key_log = secret.clone();
    let config = Arc::new(config);
    for reality in [false, true, false] {
        let (mut client, _, client_wire, template) = target_hello(&provider);
        let mut server = if reality {
            let prepared =
                rustls::reality::PreparedServerHello::new(&client_wire[5..], &template, &provider)
                    .unwrap();
            ServerConnection::new_reality(config.clone(), prepared).unwrap()
        } else {
            ServerConnection::new(config.clone()).unwrap()
        };
        let mut remaining = client_wire.as_slice();
        while !remaining.is_empty() {
            assert!(server.read_tls(&mut remaining).unwrap() > 0);
            server.process_new_packets().unwrap();
        }
        let mut wire = Vec::new();
        server.write_tls(&mut wire).unwrap();
        let expander = suite
            .hkdf_provider
            .expander_for_okm(&OkmBlock::new(&secret.0.lock().unwrap()));
        let key = expand::<AeadKey, 32>(&*expander, &[&[0, 32, 9], b"tls13 key", &[0]]);
        let iv = expand::<Iv, 12>(&*expander, &[&[0, 12, 8], b"tls13 iv", &[0]]);
        let mut offset = 0;
        for len in record_lengths(&wire) {
            if wire[offset] == u8::from(ContentType::ApplicationData) {
                let mut record = wire[offset + 5..offset + len].to_vec();
                let plain = suite
                    .aead_alg
                    .decrypter(key, iv)
                    .decrypt(
                        InboundOpaqueMessage::new(
                            ContentType::ApplicationData,
                            ProtocolVersion::TLSv1_2,
                            &mut record,
                        ),
                        0,
                    )
                    .unwrap();
                assert_eq!(plain.typ, ContentType::Handshake);
                let expected: &[u8] = if reality {
                    &[8, 0, 0, 2, 0, 0]
                } else {
                    &[8, 0, 0, 6, 0, 4, 0, 0, 0, 0]
                };
                assert_eq!(&plain.payload[..expected.len()], expected);
                break;
            }
            offset += len;
        }
        assert!(offset < wire.len(), "missing encrypted handshake");
        let mut remaining = wire.as_slice();
        while !remaining.is_empty() {
            assert!(client.read_tls(&mut remaining).unwrap() > 0);
            client.process_new_packets().unwrap();
        }
        do_handshake(&mut client, &mut server);
        assert!(!client.is_handshaking() && !server.is_handshaking());
    }
}

#[test]
fn shaped_flights_preserve_record_lengths_and_application_key_epoch() {
    use std::io::{Read, Write};
    for group in [
        aws_lc_rs::kx_group::X25519,
        aws_lc_rs::kx_group::X25519MLKEM768,
    ] {
        for suite in aws_lc_rs::default_provider()
            .cipher_suites
            .into_iter()
            .filter(|s| s.tls13().is_some())
        {
            for lengths in [vec![4096], vec![28, 4096, 128, 80], vec![64, 4096, 128, 80]] {
                for trailing in [None, Some(128)] {
                    let provider = rustls::crypto::CryptoProvider {
                        cipher_suites: vec![suite],
                        kx_groups: vec![group],
                        ..aws_lc_rs::default_provider()
                    };
                    let (mut client, config, client_wire, template) = target_hello(&provider);
                    let plan = rustls::reality::FlightPlan::new(&lengths, trailing).unwrap();
                    let prepared = rustls::reality::PreparedServerHello::new(
                        &client_wire[5..],
                        &template,
                        &provider,
                    )
                    .unwrap()
                    .with_flight_plan(plan);
                    let mut server =
                        ServerConnection::new_reality(Arc::new(config), prepared).unwrap();
                    let mut remaining = client_wire.as_slice();
                    while !remaining.is_empty() {
                        assert!(server.read_tls(&mut remaining).unwrap() > 0);
                        server.process_new_packets().unwrap();
                    }
                    let mut wire = Vec::new();
                    while server.wants_write() {
                        server.write_tls(&mut wire).unwrap();
                    }
                    let mut expected = vec![template.len() + 5, 6];
                    expected.extend(&lengths);
                    expected.extend(trailing);
                    assert_eq!(record_lengths(&wire), expected);
                    let mut remaining = wire.as_slice();
                    while !remaining.is_empty() {
                        assert!(client.read_tls(&mut remaining).unwrap() > 0);
                        client.process_new_packets().unwrap();
                    }
                    do_handshake(&mut client, &mut server);
                    server.refresh_traffic_keys().unwrap();
                    server
                        .writer()
                        .write_all(b"after key update")
                        .unwrap();
                    rustls_test::transfer(&mut server, &mut client);
                    client.process_new_packets().unwrap();
                    let mut received = [0; 16];
                    client
                        .reader()
                        .read_exact(&mut received)
                        .unwrap();
                    assert_eq!(&received, b"after key update");
                }
            }
        }
    }
}

fn extensions_offset(hello: &[u8], client: bool) -> usize {
    let mut pos = 39 + usize::from(hello[38]);
    if client {
        pos += 2 + usize::from(u16::from_be_bytes([hello[pos], hello[pos + 1]]));
        pos += 1 + usize::from(hello[pos]);
    } else {
        pos += 3;
    }
    pos
}

fn extension_body(hello: &[u8], client: bool, kind: u16) -> std::ops::Range<usize> {
    let mut pos = extensions_offset(hello, client) + 2;
    while pos < hello.len() {
        let len = usize::from(u16::from_be_bytes([hello[pos + 2], hello[pos + 3]]));
        if u16::from_be_bytes([hello[pos], hello[pos + 1]]) == kind {
            return pos + 4..pos + 4 + len;
        }
        pos += 4 + len;
    }
    panic!("missing extension {kind}");
}

fn append_extension(hello: &mut Vec<u8>, client: bool, extension: &[u8]) {
    let pos = extensions_offset(hello, client);
    hello.extend_from_slice(extension);
    let len = (hello.len() - pos - 2) as u16;
    hello[pos..pos + 2].copy_from_slice(&len.to_be_bytes());
    let len = (hello.len() - 4) as u32;
    hello[1..4].copy_from_slice(&len.to_be_bytes()[1..]);
}

const RETRY_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

#[test]
fn prepared_hello_rejects_unnegotiable_templates() {
    let provider = aws_lc_rs::default_provider();
    let (_, _, wire, template) = target_hello(&provider);
    for case in [
        "retry",
        "psk",
        "unknown",
        "duplicate",
        "cipher",
        "excluded",
        "groups",
        "server-share",
        "client-share",
        "early-data",
    ] {
        let mut ch = wire[5..].to_vec();
        let mut sh = template.clone();
        let mut crypto = provider.clone();
        match case {
            "retry" => sh[6..38].copy_from_slice(&RETRY_RANDOM),
            "psk" => append_extension(&mut sh, false, &[0, 41, 0, 2, 0, 0]),
            "unknown" => append_extension(&mut sh, false, &[0xfe, 0x30, 0, 0]),
            "duplicate" => append_extension(&mut sh, false, &[0, 43, 0, 2, 3, 4]),
            "cipher" => {
                let pos = 39 + usize::from(sh[38]);
                sh[pos..pos + 2].copy_from_slice(&0x1305u16.to_be_bytes());
            }
            "excluded" => crypto.cipher_suites.clear(),
            "groups" => {
                let span = extension_body(&ch, true, 10);
                ch[span.start + 2..span.end].fill(0);
            }
            "server-share" => {
                let span = extension_body(&sh, false, 51);
                sh[span.start + 3] ^= 1;
            }
            "client-share" => {
                let span = extension_body(&ch, true, 51);
                ch[span.start + 5] ^= 1;
            }
            "early-data" => append_extension(&mut ch, true, &[0, 42, 0, 0]),
            _ => unreachable!(),
        }
        assert!(
            rustls::reality::PreparedServerHello::new(&ch, &sh, &crypto).is_err(),
            "{case}"
        );
    }
}

#[test]
fn reality_rejects_local_configuration_before_emitting_records() {
    let provider = aws_lc_rs::default_provider();
    let (_, config, wire, template) = target_hello(&provider);
    for case in ["fragment-size", "tls12", "alpn", "early-data"] {
        let mut config = config.clone();
        match case {
            "fragment-size" => config.max_fragment_size = Some(512),
            "tls12" => config = make_server_config(KeyType::Ed25519, &provider),
            "alpn" => config
                .alpn_protocols
                .push(b"h2".to_vec()),
            "early-data" => config.max_early_data_size = 1,
            _ => unreachable!(),
        }
        let prepared =
            rustls::reality::PreparedServerHello::new(&wire[5..], &template, &provider).unwrap();
        assert!(
            matches!(
                ServerConnection::new_reality(Arc::new(config), prepared),
                Err(Error::General(_))
            ),
            "{case}"
        );
    }
    let mut client_config =
        make_client_config_with_versions(KeyType::Ed25519, &[&rustls::version::TLS13], &provider);
    client_config.enable_early_data = true;
    assert!(matches!(
        ClientConnection::new_reality(
            Arc::new(client_config),
            "localhost".try_into().unwrap(),
            Box::new(Hooks(Arc::default()))
        ),
        Err(Error::General(_))
    ));
}

#[test]
fn undersized_flight_fails_during_staging() {
    let provider = aws_lc_rs::default_provider();
    let (_, config, wire, template) = target_hello(&provider);
    for lengths in [
        vec![22],
        vec![22, 4096, 128, 80],
        vec![27, 4096, 128, 80],
        vec![64, 22, 128, 80],
        vec![64, 4096, 22, 80],
        vec![64, 4096, 128, 22],
    ] {
        let prepared = rustls::reality::PreparedServerHello::new(&wire[5..], &template, &provider)
            .unwrap()
            .with_flight_plan(rustls::reality::FlightPlan::new(&lengths, None).unwrap());
        let mut server = ServerConnection::new_reality(Arc::new(config.clone()), prepared).unwrap();
        let mut remaining = wire.as_slice();
        let error = loop {
            assert!(server.read_tls(&mut remaining).unwrap() > 0);
            if let Err(error) = server.process_new_packets() {
                break error;
            }
            assert!(!remaining.is_empty(), "undersized plan succeeded");
        };
        assert!(matches!(
            error,
            Error::PeerIncompatible(rustls::PeerIncompatible::RealityUnsupported)
        ));
        // The caller must discard the whole connection, including its queued ServerHello and alert.
        assert!(server.wants_write());
    }
}

#[test]
fn hooked_client_and_prepared_classical_server_complete_together() {
    let provider = aws_lc_rs::default_provider();
    let client_config =
        make_client_config_with_versions(KeyType::Ed25519, &[&rustls::version::TLS13], &provider);
    let mut client = ClientConnection::new_reality(
        Arc::new(client_config),
        "localhost".try_into().unwrap(),
        Box::new(Hooks(Arc::default())),
    )
    .unwrap();
    let mut wire = Vec::new();
    client.write_tls(&mut wire).unwrap();
    let provider = rustls::crypto::CryptoProvider {
        kx_groups: vec![aws_lc_rs::kx_group::X25519],
        ..provider
    };
    let config = rustls_test::make_server_config_with_versions(
        KeyType::Ed25519,
        &[&rustls::version::TLS13],
        &provider,
    );
    let mut target = ServerConnection::new(Arc::new(config.clone())).unwrap();
    let mut remaining = wire.as_slice();
    while !remaining.is_empty() {
        target.read_tls(&mut remaining).unwrap();
        target.process_new_packets().unwrap();
    }
    let mut response = Vec::new();
    target.write_tls(&mut response).unwrap();
    let len = usize::from(u16::from_be_bytes([response[3], response[4]]));
    let prepared =
        rustls::reality::PreparedServerHello::new(&wire[5..], &response[5..5 + len], &provider)
            .unwrap();
    assert_eq!(prepared.group(), rustls::NamedGroup::X25519);
    let mut server = ServerConnection::new_reality(Arc::new(config), prepared).unwrap();
    let mut remaining = wire.as_slice();
    while !remaining.is_empty() {
        server.read_tls(&mut remaining).unwrap();
        server.process_new_packets().unwrap();
    }
    do_handshake(&mut client, &mut server);
    assert!(!client.is_handshaking() && !server.is_handshaking());
}

#[test]
fn reality_client_rejects_hello_retry_without_restarting_authentication() {
    let provider = aws_lc_rs::default_provider();
    let config =
        make_client_config_with_versions(KeyType::Ed25519, &[&rustls::version::TLS13], &provider);
    let mut client = ClientConnection::new_reality(
        Arc::new(config),
        "localhost".try_into().unwrap(),
        Box::new(Hooks(Arc::default())),
    )
    .unwrap();
    let provider = rustls::crypto::CryptoProvider {
        kx_groups: vec![aws_lc_rs::kx_group::SECP256R1],
        ..provider
    };
    let config = rustls_test::make_server_config_with_versions(
        KeyType::Ed25519,
        &[&rustls::version::TLS13],
        &provider,
    );
    let mut server = ServerConnection::new(Arc::new(config)).unwrap();
    rustls_test::transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    let mut wire = Vec::new();
    server.write_tls(&mut wire).unwrap();
    assert_eq!(&wire[11..43], &RETRY_RANDOM);
    client
        .read_tls(&mut wire.as_slice())
        .unwrap();
    assert!(matches!(
        client.process_new_packets(),
        Err(Error::PeerIncompatible(
            rustls::PeerIncompatible::RealityUnsupported
        ))
    ));
}

#[test]
fn reality_rejects_ech_and_client_authentication_configuration() {
    let provider = aws_lc_rs::default_provider();
    let suite = aws_lc_rs::hpke::ALL_SUPPORTED_SUITES[0];
    let (public, _) = suite.generate_key_pair().unwrap();
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(provider.clone()))
        .with_ech(rustls::client::EchMode::Grease(
            rustls::client::EchGreaseConfig::new(suite, public),
        ))
        .unwrap();
    let config = rustls_test::finish_client_config(KeyType::Ed25519, builder);
    assert!(matches!(
        ClientConnection::new_reality(
            Arc::new(config),
            "localhost".try_into().unwrap(),
            Box::new(Hooks(Arc::default()))
        ),
        Err(Error::General(_))
    ));
    let (_, config, wire, template) = target_hello(&provider);
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        rustls_test::get_client_root_store(KeyType::Ed25519),
        Arc::new(provider.clone()),
    )
    .build()
    .unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(provider.clone()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(config.cert_resolver);
    let prepared =
        rustls::reality::PreparedServerHello::new(&wire[5..], &template, &provider).unwrap();
    assert!(matches!(
        ServerConnection::new_reality(Arc::new(config), prepared),
        Err(Error::General(_))
    ));
}
