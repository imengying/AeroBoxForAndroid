//! Static RSA must not start traffic before the server's Finished is verified.
//! Handcrafted peer messages exercise the public connection state machine.
use rustls::{
    ClientConfig, ClientConnection, ContentType, Error, ProtocolVersion, RootCertStore,
    SupportedCipherSuite,
    crypto::cipher::{AeadKey, MessageEncrypter, OutboundPlainMessage},
    pki_types::UnixTime,
    time_provider::TimeProvider,
};
use std::{
    io::{Cursor, ErrorKind, Read, Write},
    sync::{Arc, Mutex},
    time::Duration,
};

#[derive(Debug)]
struct Time;
impl TimeProvider for Time {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(Duration::from_secs(
            1_893_456_000,
        )))
    }
}
#[derive(Debug, Default)]
struct TestSecrets(Mutex<Option<(Vec<u8>, Vec<u8>)>>);
impl rustls::KeyLog for TestSecrets {
    fn log(&self, label: &str, random: &[u8], secret: &[u8]) {
        assert_eq!(label, "CLIENT_RANDOM");
        *self.0.lock().unwrap() = Some((random.to_vec(), secret.to_vec()));
    }
}
fn handshake(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut result = vec![kind];
    result.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    result.extend_from_slice(body);
    result
}
fn record(version: ProtocolVersion, kind: u8, body: &[u8]) -> Vec<u8> {
    let mut result = vec![kind];
    result.extend_from_slice(&u16::from(version).to_be_bytes());
    result.extend_from_slice(&(body.len() as u16).to_be_bytes());
    result.extend_from_slice(body);
    result
}
fn deliver(client: &mut ClientConnection, bytes: &[u8]) -> Result<(), Error> {
    let mut input = Cursor::new(bytes);
    while input.position() < bytes.len() as u64 {
        assert!(client.read_tls(&mut input).unwrap() > 0);
        client.process_new_packets()?;
    }
    Ok(())
}
fn drain(client: &mut ClientConnection) -> Vec<u8> {
    let mut result = vec![];
    while client.wants_write() {
        client.write_tls(&mut result).unwrap();
    }
    result
}
fn prepare(
    suite: SupportedCipherSuite,
    version: ProtocolVersion,
) -> (ClientConnection, Arc<TestSecrets>) {
    let cert = include_bytes!("fixtures/rsa-cert.der").as_slice();
    let mut roots = RootCertStore::empty();
    roots.add(cert.into()).unwrap();
    let mut provider = aerobox_crypto::provider();
    provider.cipher_suites = vec![suite];
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.time_provider = Arc::new(Time);
    if version != ProtocolVersion::TLSv1_2 {
        config
            .enable_legacy_tls(&aerobox_crypto::legacy_provider::LEGACY_TLS, &[version])
            .unwrap();
    }
    let secrets = Arc::new(TestSecrets::default());
    config.key_log = secrets.clone();
    let mut client =
        ClientConnection::new(Arc::new(config), "localhost".try_into().unwrap()).unwrap();
    drain(&mut client);
    let mut hello = u16::from(version).to_be_bytes().to_vec();
    hello.extend_from_slice(&[0x42; 32]);
    hello.push(0); // empty session ID
    hello.extend_from_slice(&u16::from(suite.suite()).to_be_bytes());
    hello.extend_from_slice(&[0, 0, 5, 0xff, 1, 0, 1, 0]); // compression, secure renegotiation
    deliver(&mut client, &record(version, 22, &handshake(2, &hello))).unwrap();
    let mut chain = vec![];
    chain.extend_from_slice(&((cert.len() + 3) as u32).to_be_bytes()[1..]);
    chain.extend_from_slice(&(cert.len() as u32).to_be_bytes()[1..]);
    chain.extend_from_slice(cert);
    deliver(&mut client, &record(version, 22, &handshake(11, &chain))).unwrap();
    (client, secrets)
}
fn assert_retired(client: &mut ClientConnection, error: Error) {
    assert!(client.is_handshaking());
    assert_eq!(client.process_new_packets().unwrap_err(), error);
    let mut output = [0; 64];
    assert_eq!(
        client.reader().read(&mut output).unwrap_err().kind(),
        ErrorKind::WouldBlock
    );
    assert_eq!(output, [0; 64]);
}

fn static_suites_and_versions() -> Vec<(SupportedCipherSuite, ProtocolVersion)> {
    use rustls::client::LegacyTlsProvider;
    let mut suites: Vec<_> = aerobox_crypto::legacy_rsa::suites()
        .into_iter()
        .map(|suite| (suite, ProtocolVersion::TLSv1_2))
        .collect();
    for version in [ProtocolVersion::TLSv1_0, ProtocolVersion::TLSv1_1] {
        for cipher in [0x002f, 0x0035] {
            let suite = aerobox_crypto::legacy_provider::LEGACY_TLS
                .cipher_suite(rustls::CipherSuite::from(cipher), version)
                .unwrap();
            suites.push((suite.into(), version));
        }
    }
    suites
}

#[test]
fn static_rsa_rejects_unexpected_server_key_exchange_and_early_application_data() {
    for (suite, version) in static_suites_and_versions() {
        let (mut client, _) = prepare(suite, version);
        let error =
            deliver(&mut client, &record(version, 22, &handshake(12, &[0; 8]))).unwrap_err();
        assert_retired(&mut client, error);

        let (mut client, _) = prepare(suite, version);
        client
            .writer()
            .write_all(b"buffered until peer authentication")
            .unwrap();
        deliver(&mut client, &record(version, 22, &handshake(14, &[]))).unwrap();
        assert!(client.is_handshaking());
        drain(&mut client);
        let error = deliver(
            &mut client,
            &record(version, 23, b"unauthenticated response"),
        )
        .unwrap_err();
        assert_retired(&mut client, error);
    }
}

fn server_encrypter(
    suite: &rustls::Tls12CipherSuite,
    secrets: &TestSecrets,
) -> Box<dyn MessageEncrypter> {
    let secrets = secrets.0.lock().unwrap();
    let (random, master) = secrets.as_ref().unwrap();
    let shape = suite.aead_alg.key_block_shape();
    assert_eq!(shape.enc_key_len, 32);
    let mac_len = suite.aead_alg.mac_key_len();
    let mut block =
        vec![0; 2 * (mac_len + shape.enc_key_len + shape.fixed_iv_len) + shape.explicit_nonce_len];
    let mut seed = vec![0x42; 32];
    seed.extend_from_slice(random);
    suite
        .prf_provider
        .for_secret(&mut block, master, b"key expansion", &seed);
    let (_, block) = block.split_at(mac_len);
    let (server_mac, block) = block.split_at(mac_len);
    let (_, block) = block.split_at(32);
    let (server_key, block) = block.split_at(32);
    let (_, block) = block.split_at(shape.fixed_iv_len);
    let (server_iv, extra) = block.split_at(shape.fixed_iv_len);
    suite.aead_alg.encrypter_with_mac(
        AeadKey::from(<[u8; 32]>::try_from(server_key).unwrap()),
        server_iv,
        extra,
        server_mac,
    )
}

#[test]
fn static_rsa_requires_correct_finished_even_with_authenticated_records() {
    for (suite, version) in static_suites_and_versions() {
        let SupportedCipherSuite::Tls12(suite) = suite else {
            unreachable!()
        };
        if suite.aead_alg.key_block_shape().enc_key_len != 32 {
            continue;
        }
        // The invalid handshake type case proves the ciphertext authenticates
        // and reaches the Finished state. The other case checks verify_data.
        for invalid_kind in [false, true] {
            let (mut client, secrets) = prepare(suite.into(), version);
            deliver(&mut client, &record(version, 22, &handshake(14, &[]))).unwrap();
            drain(&mut client);
            deliver(&mut client, &record(version, 20, &[1])).unwrap();
            let payload = if invalid_kind {
                handshake(14, &[])
            } else {
                handshake(20, &[0; 12])
            };
            let encrypted = server_encrypter(suite, &secrets)
                .encrypt(
                    OutboundPlainMessage {
                        typ: ContentType::Handshake,
                        version,
                        payload: payload.as_slice().into(),
                    },
                    0,
                )
                .unwrap()
                .encode();
            let error = deliver(&mut client, &encrypted).unwrap_err();
            if invalid_kind {
                assert!(
                    matches!(error, Error::InappropriateHandshakeMessage { .. }),
                    "{error:?}"
                );
            } else {
                assert_eq!(error, Error::DecryptError);
            }
            assert_retired(&mut client, error);
        }
    }
}
