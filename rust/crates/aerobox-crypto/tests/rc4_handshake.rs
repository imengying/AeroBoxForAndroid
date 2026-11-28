//! Real TLS1.2 connections exercise the successful 16-byte AeadKey factory path.
//! These use two Rust endpoints; independent Go and old-version validation is
//! separate. This does not enable or claim a complete 360 fingerprint.
use rustls::{
    ClientConfig, ClientConnection, Connection, Error, ProtocolVersion, RootCertStore,
    ServerConfig, ServerConnection, SupportedCipherSuite,
    pki_types::{CertificateDer, PrivatePkcs8KeyDer, UnixTime},
    server::WebPkiClientVerifier,
    time_provider::TimeProvider,
};
use std::{
    io::{Cursor, ErrorKind, Read, Write},
    sync::Arc,
    time::Duration,
};

#[derive(Debug)]
struct FixtureTime;
impl TimeProvider for FixtureTime {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(Duration::from_secs(
            1_893_456_000,
        )))
    }
}

fn pair(suite: SupportedCipherSuite, mutual: bool, name: &'static str) -> (Connection, Connection) {
    let rsa = u16::from(suite.suite()) == 0xc011;
    assert!([0xc007, 0xc011].contains(&u16::from(suite.suite())));
    let (cert, key): (&[u8], &[u8]) = if rsa {
        (
            include_bytes!("fixtures/rsa-cert.der"),
            include_bytes!("fixtures/rsa-key.der"),
        )
    } else {
        (
            include_bytes!("fixtures/ecdsa-cert.der"),
            include_bytes!("fixtures/ecdsa-key.der"),
        )
    };
    let mut provider = aerobox_crypto::legacy_rc4::provider();
    provider.cipher_suites = vec![suite];
    let provider = Arc::new(provider);
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(cert)).unwrap();
    let mut client_roots = RootCertStore::empty();
    client_roots
        .add(include_bytes!("fixtures/p521-ca.der").as_slice().into())
        .unwrap();
    let client_builder = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap()
        .with_root_certificates(roots);
    let mut client = if mutual {
        client_builder
            .with_client_auth_cert(
                vec![include_bytes!("fixtures/p521-cert.der").as_slice().into()],
                PrivatePkcs8KeyDer::from(include_bytes!("fixtures/p521-key.der").to_vec()).into(),
            )
            .unwrap()
    } else {
        client_builder.with_no_client_auth()
    };
    client.time_provider = Arc::new(FixtureTime);
    client.resumption = rustls::client::Resumption::disabled();
    client.max_fragment_size = mutual.then_some(1024);
    let server_builder = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap();
    let server_builder = if mutual {
        server_builder.with_client_cert_verifier(
            WebPkiClientVerifier::builder_with_provider(Arc::new(client_roots), provider)
                .build()
                .unwrap(),
        )
    } else {
        server_builder.with_no_client_auth()
    };
    let mut server = server_builder
        .with_single_cert(
            vec![CertificateDer::from(cert)],
            PrivatePkcs8KeyDer::from(key.to_vec()).into(),
        )
        .unwrap();
    server.time_provider = Arc::new(FixtureTime);
    server.max_fragment_size = mutual.then_some(1024);
    (
        Connection::Client(
            ClientConnection::new(Arc::new(client), name.try_into().unwrap()).unwrap(),
        ),
        Connection::Server(ServerConnection::new(Arc::new(server)).unwrap()),
    )
}

fn drain(connection: &mut Connection) -> Vec<u8> {
    let mut wire = Vec::new();
    while connection.wants_write() {
        assert!(connection.write_tls(&mut wire).unwrap() > 0);
    }
    wire
}
fn feed(connection: &mut Connection, bytes: &[u8]) -> Result<(), Error> {
    // Deliberately split record headers, MACs and encrypted payloads at the
    // transport boundary. Fragmentation must not reset the RC4 stream.
    for chunk in bytes.chunks(137) {
        let mut input = Cursor::new(chunk);
        while input.position() < chunk.len() as u64 {
            assert!(connection.read_tls(&mut input).unwrap() > 0);
            connection.process_new_packets()?;
        }
    }
    Ok(())
}
fn handshake(client: &mut Connection, server: &mut Connection) -> Result<(), Error> {
    for _ in 0..32 {
        let left = drain(client);
        feed(server, &left)?;
        let right = drain(server);
        feed(client, &right)?;
        if !client.is_handshaking()
            && !server.is_handshaking()
            && left.is_empty()
            && right.is_empty()
        {
            return Ok(());
        }
    }
    panic!("RC4 handshake did not settle");
}
fn records(mut wire: &[u8], typ: u8) -> Vec<usize> {
    let mut sizes = Vec::new();
    while !wire.is_empty() {
        assert!(wire.len() >= 5);
        assert_eq!(wire[0], typ);
        assert_eq!(&wire[1..3], &[3, 3]);
        let size = u16::from_be_bytes([wire[3], wire[4]]) as usize;
        assert!(size >= 20 && size <= 16384 + 20 && wire.len() >= size + 5);
        sizes.push(size);
        wire = &wire[size + 5..];
    }
    assert!(!sizes.is_empty());
    sizes
}
fn assert_hidden(connection: &mut Connection) {
    let mut plain = [0u8; 128];
    assert_eq!(
        connection.reader().read(&mut plain).unwrap_err().kind(),
        ErrorKind::WouldBlock
    );
    assert_eq!(plain, [0; 128]);
}

#[test]
fn real_key_block_finished_exporter_mutual_auth_data_and_close_are_continuous() {
    for suite in aerobox_crypto::legacy_rc4::suites().into_iter().take(2) {
        for mutual in [false, true] {
            let (mut client, mut server) = pair(suite, mutual, "localhost");
            handshake(&mut client, &mut server).unwrap();
            for connection in [&client, &server] {
                assert_eq!(connection.negotiated_cipher_suite(), Some(suite));
                assert_eq!(
                    connection.protocol_version(),
                    Some(ProtocolVersion::TLSv1_2)
                );
                assert_eq!(
                    connection.handshake_kind(),
                    Some(rustls::HandshakeKind::Full)
                );
            }
            assert!(client.peer_certificates().is_some());
            assert_eq!(server.peer_certificates().is_some(), mutual);
            let export = |connection: &Connection| {
                connection
                    .export_keying_material(
                        [0; 32],
                        b"aerobox RC4 TLS12 independent directions",
                        Some(b"EMS required"),
                    )
                    .unwrap()
            };
            assert_eq!(export(&client), export(&server));
            for from_server in [false, true] {
                let (sender, receiver, salt) = if from_server {
                    (&mut server, &mut client, 29u8)
                } else {
                    (&mut client, &mut server, 17u8)
                };
                let payload: Vec<u8> = (0..65537)
                    .map(|i| ((i * 31 + usize::from(salt)) % 251) as u8)
                    .collect();
                let mut sent = 0;
                for chunk in payload.chunks(16384) {
                    sender.writer().write_all(chunk).unwrap();
                    let wire = drain(sender);
                    let sizes = records(&wire, 23);
                    assert_eq!(
                        sizes.iter().map(|size| size - 20).sum::<usize>(),
                        chunk.len(),
                        "each record has only its 20-byte MAC overhead"
                    );
                    feed(receiver, &wire).unwrap();
                    let mut received = vec![0; chunk.len()];
                    receiver.reader().read_exact(&mut received).unwrap();
                    assert_eq!(received, chunk);
                    sent += received.len();
                }
                assert_eq!(sent, 65537);
            }
            client.send_close_notify();
            let close = drain(&mut client);
            assert_eq!(records(&close, 21), [22]);
            feed(&mut server, &close).unwrap();
            assert!(server.process_new_packets().unwrap().peer_has_closed());
            server.send_close_notify();
            let close = drain(&mut server);
            assert_eq!(records(&close, 21), [22]);
            feed(&mut client, &close).unwrap();
            assert!(client.process_new_packets().unwrap().peer_has_closed());
            assert_eq!(client.reader().read(&mut [0; 1]).unwrap(), 0);
            assert_eq!(server.reader().read(&mut [0; 1]).unwrap(), 0);
        }
    }
}

#[test]
fn authenticated_transport_rejects_tamper_replay_and_lost_record_permanently() {
    for suite in aerobox_crypto::legacy_rc4::suites().into_iter().take(2) {
        for from_server in [false, true] {
            for attack in 0..3 {
                let (mut client, mut server) = pair(suite, false, "localhost");
                handshake(&mut client, &mut server).unwrap();
                let (sender, receiver) = if from_server {
                    (&mut server, &mut client)
                } else {
                    (&mut client, &mut server)
                };
                sender.writer().write_all(b"verified first").unwrap();
                let first = drain(sender);
                feed(receiver, &first).unwrap();
                let mut checked = [0; 14];
                receiver.reader().read_exact(&mut checked).unwrap();
                assert_eq!(&checked, b"verified first");
                sender.writer().write_all(b"second plaintext").unwrap();
                let second = drain(sender);
                sender.writer().write_all(b"third plaintext").unwrap();
                let third = drain(sender);
                let damaged = match attack {
                    0 => {
                        let mut damaged = second.clone();
                        *damaged.last_mut().unwrap() ^= 1;
                        damaged
                    }
                    1 => first,
                    _ => third,
                };
                let error = feed(receiver, &damaged).unwrap_err();
                assert_eq!(error, Error::DecryptError);
                assert_hidden(receiver);
                assert_eq!(feed(receiver, &second).unwrap_err(), error);
                assert_eq!(receiver.process_new_packets().unwrap_err(), error);
                assert_hidden(receiver);
                assert!(receiver.writer().write(b"after failure").is_err());
            }
        }
    }
}

#[test]
fn opt_in_rc4_keeps_real_hostname_verification_and_fails_before_application_data() {
    for suite in aerobox_crypto::legacy_rc4::suites().into_iter().take(2) {
        let (mut client, mut server) = pair(suite, false, "unrelated.test");
        let error = handshake(&mut client, &mut server).unwrap_err();
        assert!(matches!(
            error,
            Error::InvalidCertificate(
                rustls::CertificateError::NotValidForName
                    | rustls::CertificateError::NotValidForNameContext { .. }
            )
        ));
        assert_eq!(client.process_new_packets().unwrap_err(), error);
        assert!(client.is_handshaking());
        assert_hidden(&mut client);
        assert!(
            client
                .export_keying_material([0; 32], b"rejected RC4 peer", None)
                .is_err()
        );
    }
}
