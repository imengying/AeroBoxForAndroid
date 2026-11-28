//! CBC record authentication errors permanently retire the TLS connection.
//! These exercise the public rustls connection boundary, not just the cipher.
use std::{
    io::{Cursor, ErrorKind, Read, Write},
    sync::Arc,
    time::Duration,
};

use rustls::{
    ClientConfig, ClientConnection, Connection, Error, RootCertStore, ServerConfig,
    ServerConnection, SupportedCipherSuite,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime},
    time_provider::TimeProvider,
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

fn pair(suite: SupportedCipherSuite) -> (Connection, Connection) {
    let rsa = matches!(
        suite.suite(),
        rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
            | rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    );
    let (cert, key) = if rsa {
        (
            include_bytes!("fixtures/rsa-cert.der").as_slice(),
            include_bytes!("fixtures/rsa-key.der").as_slice(),
        )
    } else {
        (
            include_bytes!("fixtures/ecdsa-cert.der").as_slice(),
            include_bytes!("fixtures/ecdsa-key.der").as_slice(),
        )
    };
    let cert = CertificateDer::from(cert.to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec()));
    let mut provider = aerobox_crypto::provider();
    provider.cipher_suites = vec![suite];
    let provider = Arc::new(provider);
    let mut roots = RootCertStore::empty();
    roots.add(cert.clone()).unwrap();
    let mut client = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.time_provider = Arc::new(FixtureTime);
    let server = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    let mut client = Connection::Client(
        ClientConnection::new(Arc::new(client), "localhost".try_into().unwrap()).unwrap(),
    );
    let mut server = Connection::Server(ServerConnection::new(Arc::new(server)).unwrap());
    for _ in 0..32 {
        let left = drain(&mut client);
        deliver(&mut server, &left).unwrap();
        let right = drain(&mut server);
        deliver(&mut client, &right).unwrap();
        if !client.is_handshaking()
            && !server.is_handshaking()
            && left.is_empty()
            && right.is_empty()
        {
            assert_eq!(client.negotiated_cipher_suite(), Some(suite));
            assert_eq!(server.negotiated_cipher_suite(), Some(suite));
            return (client, server);
        }
    }
    panic!("CBC handshake did not settle: {suite:?}");
}

fn drain(connection: &mut Connection) -> Vec<u8> {
    let mut output = Vec::new();
    while connection.wants_write() {
        assert!(connection.write_tls(&mut output).unwrap() > 0);
    }
    output
}

fn deliver(connection: &mut Connection, bytes: &[u8]) -> Result<(), Error> {
    let mut input = Cursor::new(bytes);
    while input.position() < bytes.len() as u64 {
        assert!(connection.read_tls(&mut input).unwrap() > 0);
        connection.process_new_packets()?;
    }
    Ok(())
}

fn assert_no_plaintext(connection: &mut Connection) {
    let mut output = [0u8; 128];
    assert_eq!(
        connection.reader().read(&mut output).unwrap_err().kind(),
        ErrorKind::WouldBlock
    );
    assert_eq!(output, [0; 128]);
}

#[test]
fn cbc_authentication_failure_is_sticky_in_both_directions_for_every_suite() {
    for suite in aerobox_crypto::legacy_cbc::suites() {
        for from_server in [false, true] {
            for corrupt in [0, 1, 2] {
                let (mut client, mut server) = pair(suite);
                let (sender, receiver) = if from_server {
                    (&mut server, &mut client)
                } else {
                    (&mut client, &mut server)
                };

                // Establish that the connection delivers authenticated data,
                // and consume it before checking that no new bytes can escape.
                sender.writer().write_all(b"verified").unwrap();
                deliver(receiver, &drain(sender)).unwrap();
                let mut verified = [0; 8];
                receiver.reader().read_exact(&mut verified).unwrap();
                assert_eq!(&verified, b"verified");

                sender
                    .writer()
                    .write_all(b"never expose unauthenticated CBC plaintext")
                    .unwrap();
                let valid = drain(sender);
                assert_eq!(valid[0], 23); // TLS application-data record.
                assert_eq!(
                    valid.len(),
                    5 + usize::from(u16::from_be_bytes([valid[3], valid[4]]))
                );
                let mut damaged = valid.clone();
                let position = match corrupt {
                    0 => 5,                 // Explicit IV: changes plaintext while preserving record length.
                    1 => 5 + 16,            // First ciphertext block.
                    _ => damaged.len() - 1, // Final ciphertext/padding block.
                };
                damaged[position] ^= 0x80;
                let error = deliver(receiver, &damaged).unwrap_err();
                assert!(
                    matches!(error, Error::DecryptError),
                    "{suite:?}, server={from_server}, mutation={corrupt}: {error:?}"
                );
                assert_no_plaintext(receiver);

                // Retry the original valid record at the SAME sequence number:
                // rejection cannot merely be explained by a sequence mismatch.
                assert_eq!(deliver(receiver, &valid).unwrap_err(), error);
                assert_eq!(receiver.process_new_packets().unwrap_err(), error);
                assert_no_plaintext(receiver);

                sender
                    .writer()
                    .write_all(b"valid later record must also stay hidden")
                    .unwrap();
                assert_eq!(deliver(receiver, &drain(sender)).unwrap_err(), error);
                assert_no_plaintext(receiver);
            }
        }
    }
}
