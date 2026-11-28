//! Real TLS 1.3 handshakes for the opt-in Firefox FFDHE prerequisite.
//! This deliberately does not claim to implement the whole Firefox profile.
use std::{
    io::{Read, Write},
    sync::Arc,
};

use aerobox_crypto::ffdhe::{FFDHE2048, FFDHE3072};
use rustls::{
    ClientConfig, ClientConnection, Connection, Error, NamedGroup, ProtocolVersion, RootCertStore,
    ServerConfig, ServerConnection,
    crypto::SupportedKxGroup,
    pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
    server::WebPkiClientVerifier,
    time_provider::TimeProvider,
};

const LEAF: &[u8] = include_bytes!("fixtures/p521-cert.der");
const CA: &[u8] = include_bytes!("fixtures/p521-ca.der");
const KEY: &[u8] = include_bytes!("fixtures/p521-key.der");
const HRR_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

#[derive(Debug)]
struct FixtureTime;
impl TimeProvider for FixtureTime {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(std::time::Duration::from_secs(
            1_893_456_000,
        )))
    }
}

fn pair(
    group: &'static dyn SupportedKxGroup,
    retry: bool,
    mutual: bool,
    wrong_root: bool,
    name: &'static str,
) -> (Connection, Connection) {
    let mut client_crypto = aerobox_crypto::provider();
    client_crypto
        .cipher_suites
        .retain(|suite| u16::from(suite.suite()) == 0x1301);
    client_crypto
        .kx_groups
        .extend([&FFDHE2048 as &dyn SupportedKxGroup, &FFDHE3072]);
    let mut server_crypto = client_crypto.clone();
    server_crypto.kx_groups = vec![group];
    let client_crypto = Arc::new(client_crypto);
    let server_crypto = Arc::new(server_crypto);
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(CA)).unwrap();
    let roots = Arc::new(roots);
    let client_roots = if wrong_root {
        let mut bad = RootCertStore::empty();
        bad.add(CertificateDer::from(
            include_bytes!("fixtures/rsa-cert.der").as_slice(),
        ))
        .unwrap();
        Arc::new(bad)
    } else {
        roots.clone()
    };
    let client_builder = ClientConfig::builder_with_provider(client_crypto)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(client_roots);
    let mut client = if mutual {
        client_builder
            .with_client_auth_cert(
                vec![CertificateDer::from(LEAF)],
                PrivatePkcs8KeyDer::from(KEY.to_vec()).into(),
            )
            .unwrap()
    } else {
        client_builder.with_no_client_auth()
    };
    client.initial_key_share_groups = vec![if retry {
        NamedGroup::X25519
    } else {
        group.name()
    }];
    client.alpn_protocols = vec![b"h2".to_vec()];
    client.time_provider = Arc::new(FixtureTime);
    client.resumption = rustls::client::Resumption::disabled();
    client.cert_compressors.clear();
    client.cert_decompressors.clear();
    let server_builder = ServerConfig::builder_with_provider(server_crypto.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap();
    let server_builder = if mutual {
        server_builder.with_client_cert_verifier(
            WebPkiClientVerifier::builder_with_provider(roots, server_crypto)
                .build()
                .unwrap(),
        )
    } else {
        server_builder.with_no_client_auth()
    };
    let mut server = server_builder
        .with_single_cert(
            vec![CertificateDer::from(LEAF)],
            PrivatePkcs8KeyDer::from(KEY.to_vec()).into(),
        )
        .unwrap();
    server.alpn_protocols = vec![b"h2".to_vec()];
    server.time_provider = Arc::new(FixtureTime);
    server.send_tls13_tickets = 0;
    server.cert_compressors.clear();
    server.cert_decompressors.clear();
    (
        Connection::Client(
            ClientConnection::new(Arc::new(client), ServerName::try_from(name).unwrap()).unwrap(),
        ),
        Connection::Server(ServerConnection::new(Arc::new(server)).unwrap()),
    )
}

fn drain(connection: &mut Connection) -> Vec<u8> {
    let mut bytes = vec![];
    while connection.wants_write() {
        assert!(connection.write_tls(&mut bytes).unwrap() > 0);
    }
    bytes
}

fn feed(connection: &mut Connection, bytes: &[u8]) -> Result<(), Error> {
    for fragment in bytes.chunks(137) {
        let mut input = fragment;
        while !input.is_empty() {
            assert!(connection.read_tls(&mut input).unwrap() > 0);
            connection.process_new_packets()?;
        }
    }
    Ok(())
}

fn plaintext_handshakes(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut input = bytes;
    let mut handshake_bytes = vec![];
    while !input.is_empty() {
        assert!(input.len() >= 5);
        let length = u16::from_be_bytes(input[3..5].try_into().unwrap()) as usize;
        assert!(input.len() >= 5 + length);
        if input[0] == 22 {
            handshake_bytes.extend_from_slice(&input[5..5 + length]);
        }
        input = &input[5 + length..];
    }
    let mut output = vec![];
    let mut input = handshake_bytes.as_slice();
    while !input.is_empty() {
        assert!(input.len() >= 4);
        let length =
            (usize::from(input[1]) << 16) | (usize::from(input[2]) << 8) | usize::from(input[3]);
        output.push(input[..4 + length].to_vec());
        input = &input[4 + length..];
    }
    output
}

#[derive(Default)]
struct Witness {
    client_hellos: Vec<Vec<u8>>,
    retries: usize,
}

fn handshake(client: &mut Connection, server: &mut Connection) -> Result<Witness, Error> {
    let mut witness = Witness::default();
    for _ in 0..16 {
        let outbound = drain(client);
        witness.client_hellos.extend(
            plaintext_handshakes(&outbound)
                .into_iter()
                .filter(|message| message[0] == 1),
        );
        feed(server, &outbound)?;
        let inbound = drain(server);
        for message in plaintext_handshakes(&inbound) {
            if message[0] == 2 && message[6..38] == HRR_RANDOM {
                witness.retries += 1;
            }
        }
        feed(client, &inbound)?;
        if !client.is_handshaking()
            && !server.is_handshaking()
            && !client.wants_write()
            && !server.wants_write()
        {
            return Ok(witness);
        }
    }
    panic!("handshake stalled")
}

fn extensions(hello: &[u8]) -> Vec<(u16, Vec<u8>)> {
    assert_eq!(hello[0], 1);
    let mut pos = 39 + usize::from(hello[38]);
    let suites = u16::from_be_bytes(hello[pos..pos + 2].try_into().unwrap()) as usize;
    pos += 2 + suites;
    pos += 1 + usize::from(hello[pos]);
    let length = u16::from_be_bytes(hello[pos..pos + 2].try_into().unwrap()) as usize;
    pos += 2;
    assert_eq!(pos + length, hello.len());
    let mut output = vec![];
    while pos < hello.len() {
        let kind = u16::from_be_bytes(hello[pos..pos + 2].try_into().unwrap());
        let length = u16::from_be_bytes(hello[pos + 2..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        output.push((kind, hello[pos..pos + length].to_vec()));
        pos += length;
    }
    output
}

fn shares(hello: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let bytes = extensions(hello)
        .into_iter()
        .find(|(kind, _)| *kind == 51)
        .unwrap()
        .1;
    assert_eq!(
        u16::from_be_bytes(bytes[..2].try_into().unwrap()) as usize,
        bytes.len() - 2
    );
    let mut pos = 2;
    let mut shares = vec![];
    while pos < bytes.len() {
        let kind = u16::from_be_bytes(bytes[pos..pos + 2].try_into().unwrap());
        let length = u16::from_be_bytes(bytes[pos + 2..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        shares.push((kind, bytes[pos..pos + length].to_vec()));
        pos += length;
    }
    shares
}

fn transfer_application(from: &mut Connection, to: &mut Connection, salt: u8) {
    let data: Vec<_> = (0..65_537)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(salt))
        .collect();
    let mut received = vec![];
    for part in data.chunks(4093) {
        from.writer().write_all(part).unwrap();
        feed(to, &drain(from)).unwrap();
        let mut output = vec![0; part.len()];
        to.reader().read_exact(&mut output).unwrap();
        received.extend_from_slice(&output);
    }
    assert_eq!(received, data);
}

#[test]
fn tls13_direct_and_hrr_complete_authenticated_mutual_and_one_way_transfers() {
    for group in [&FFDHE2048 as &dyn SupportedKxGroup, &FFDHE3072] {
        for retry in [false, true] {
            for mutual in [false, true] {
                let (mut client, mut server) = pair(group, retry, mutual, false, "localhost");
                let witness = handshake(&mut client, &mut server).unwrap();
                assert_eq!(witness.retries, usize::from(retry));
                assert_eq!(witness.client_hellos.len(), 1 + usize::from(retry));
                let last = witness.client_hellos.last().unwrap();
                let selected_shares = shares(last);
                assert_eq!(selected_shares.len(), 1);
                assert_eq!(selected_shares[0].0, u16::from(group.name()));
                assert_eq!(
                    selected_shares[0].1.len(),
                    group.ffdhe_group().unwrap().p.len()
                );
                if retry {
                    assert_eq!(
                        shares(&witness.client_hellos[0])[0].0,
                        u16::from(NamedGroup::X25519)
                    );
                    assert_eq!(&witness.client_hellos[0][6..38], &last[6..38]);
                    let session_len = usize::from(last[38]);
                    assert_eq!(
                        &witness.client_hellos[0][38..39 + session_len],
                        &last[38..39 + session_len]
                    );
                }
                for connection in [&client, &server] {
                    assert_eq!(
                        connection.protocol_version(),
                        Some(ProtocolVersion::TLSv1_3)
                    );
                    assert_eq!(
                        u16::from(connection.negotiated_cipher_suite().unwrap().suite()),
                        0x1301
                    );
                    assert_eq!(
                        connection.negotiated_key_exchange_group().unwrap().name(),
                        group.name()
                    );
                    assert_eq!(connection.alpn_protocol(), Some(b"h2".as_slice()));
                }
                assert_eq!(client.peer_certificates().unwrap()[0].as_ref(), LEAF);
                assert_eq!(server.peer_certificates().is_some(), mutual);
                if mutual {
                    assert_eq!(server.peer_certificates().unwrap()[0].as_ref(), LEAF);
                }
                let label = b"AeroBox FFDHE independent transcript";
                let context = Some(b"full-width shared secret".as_slice());
                let left = client
                    .export_keying_material([0u8; 32], label, context)
                    .unwrap();
                let right = server
                    .export_keying_material([0u8; 32], label, context)
                    .unwrap();
                assert_eq!(left, right);
                assert_ne!(left, [0; 32]);
                transfer_application(&mut client, &mut server, 7);
                transfer_application(&mut server, &mut client, 91);
                client.send_close_notify();
                server.send_close_notify();
                feed(&mut server, &drain(&mut client)).unwrap();
                feed(&mut client, &drain(&mut server)).unwrap();
                assert_eq!(client.reader().read(&mut [0u8; 1]).unwrap(), 0);
                assert_eq!(server.reader().read(&mut [0u8; 1]).unwrap(), 0);
            }
        }
    }
}

fn vector16(bytes: &[u8]) -> Vec<u8> {
    let mut result = u16::try_from(bytes.len()).unwrap().to_be_bytes().to_vec();
    result.extend_from_slice(bytes);
    result
}

fn server_hello(client_hello: &[u8], group: NamedGroup, key: Option<&[u8]>) -> Vec<u8> {
    let session = &client_hello[39..39 + usize::from(client_hello[38])];
    let mut body = vec![3, 3];
    body.extend_from_slice(if key.is_some() {
        &[0x42; 32]
    } else {
        &HRR_RANDOM
    });
    body.push(session.len() as u8);
    body.extend_from_slice(session);
    body.extend_from_slice(&[0x13, 0x01, 0]);
    let mut extensions = vec![0, 43, 0, 2, 3, 4];
    let mut share = u16::from(group).to_be_bytes().to_vec();
    if let Some(key) = key {
        share.extend_from_slice(&vector16(key));
    }
    extensions.extend_from_slice(&[0, 51]);
    extensions.extend_from_slice(&vector16(&share));
    body.extend_from_slice(&vector16(&extensions));
    let mut message = vec![
        2,
        (body.len() >> 16) as u8,
        (body.len() >> 8) as u8,
        body.len() as u8,
    ];
    message.extend_from_slice(&body);
    let mut record = vec![22, 3, 3];
    record.extend_from_slice(&vector16(&message));
    record
}

#[test]
fn tls13_malformed_or_wrong_group_server_shares_fail_before_finished() {
    for group in [&FFDHE2048 as &dyn SupportedKxGroup, &FFDHE3072] {
        let p = group.ffdhe_group().unwrap().p;
        let mut p_minus_one = p.to_vec();
        *p_minus_one.last_mut().unwrap() -= 1;
        for (kind, value) in [
            (group.name(), vec![0; p.len()]),
            (group.name(), p_minus_one),
            (group.name(), vec![2; p.len() - 1]),
            (NamedGroup::FFDHE4096, vec![2; p.len()]),
        ] {
            let (mut client, _) = pair(group, false, false, false, "localhost");
            let hello = plaintext_handshakes(&drain(&mut client)).remove(0);
            let malformed = server_hello(&hello, kind, Some(&value));
            let error = feed(&mut client, &malformed).unwrap_err();
            assert_eq!(
                error,
                Error::PeerMisbehaved(if kind == group.name() {
                    rustls::PeerMisbehaved::InvalidKeyShare
                } else {
                    rustls::PeerMisbehaved::WrongGroupForKeyShare
                }),
            );
            assert!(client.is_handshaking());
            assert!(
                client
                    .export_keying_material([0u8; 32], b"not authenticated", None)
                    .is_err()
            );
            assert!(
                client
                    .writer()
                    .write(b"must not be accepted after fatal error")
                    .is_err()
            );
            assert_eq!(client.process_new_packets().unwrap_err(), error);
        }
    }
}

#[test]
fn tls13_retries_reject_unadvertised_already_offered_and_repeated_groups() {
    for group in [&FFDHE2048 as &dyn SupportedKxGroup, &FFDHE3072] {
        for selected in [NamedGroup::FFDHE4096, NamedGroup::X25519] {
            let (mut client, _) = pair(group, true, false, false, "localhost");
            let hello = plaintext_handshakes(&drain(&mut client)).remove(0);
            assert!(feed(&mut client, &server_hello(&hello, selected, None)).is_err());
        }
        let (mut client, _) = pair(group, true, false, false, "localhost");
        let first = plaintext_handshakes(&drain(&mut client)).remove(0);
        let retry = server_hello(&first, group.name(), None);
        feed(&mut client, &retry).unwrap();
        let second = plaintext_handshakes(&drain(&mut client)).remove(0);
        assert_eq!(shares(&second)[0].0, u16::from(group.name()));
        assert!(feed(&mut client, &retry).is_err());
    }
}

#[test]
fn ffdhe_does_not_bypass_identity_or_certificate_validation() {
    for group in [&FFDHE2048 as &dyn SupportedKxGroup, &FFDHE3072] {
        for (wrong_root, name) in [(false, "wrong.example"), (true, "localhost")] {
            let (mut client, mut server) = pair(group, true, true, wrong_root, name);
            assert!(matches!(
                handshake(&mut client, &mut server),
                Err(Error::InvalidCertificate(_))
            ));
            assert!(client.is_handshaking());
            assert!(
                client
                    .export_keying_material([0u8; 32], b"unauthenticated", None)
                    .is_err()
            );
        }
    }
}

#[test]
fn tls12_builder_cannot_select_the_tls13_only_ffdhe_implementation() {
    let mut provider = aerobox_crypto::provider();
    provider.kx_groups = vec![&FFDHE2048, &FFDHE3072];
    assert!(
        ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS12])
            .is_err()
    );
}
