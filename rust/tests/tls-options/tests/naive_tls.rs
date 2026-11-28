use aerobox_tls_options_check::{naive_config, tls::TlsClientOptions};
use base64::{Engine, engine::general_purpose::STANDARD};
use rustls::{
    ClientConfig, ClientConnection, Connection, Error, HandshakeKind, ServerConfig,
    ServerConnection,
};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

const CERT: &[u8] = include_bytes!("../../../crates/aerobox-crypto/tests/fixtures/ecdsa-cert.der");
const KEY: &[u8] = include_bytes!("../../../crates/aerobox-crypto/tests/fixtures/ecdsa-key.der");
const OTHER_CERT: &[u8] =
    include_bytes!("../../../crates/aerobox-crypto/tests/fixtures/rsa-cert.der");

fn options(certificate: &[u8]) -> TlsClientOptions {
    TlsClientOptions {
        root_certificates: vec![format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            STANDARD.encode(certificate)
        )],
        ..Default::default()
    }
}

fn take<'a>(bytes: &mut &'a [u8], count: usize) -> &'a [u8] {
    let (head, rest) = bytes.split_at(count);
    *bytes = rest;
    head
}
fn vector<'a>(bytes: &mut &'a [u8], width: usize) -> &'a [u8] {
    let size = take(bytes, width)
        .iter()
        .fold(0usize, |size, byte| (size << 8) | usize::from(*byte));
    take(bytes, size)
}
fn numbers(bytes: &[u8]) -> Vec<u16> {
    assert_eq!(bytes.len() % 2, 0);
    bytes
        .chunks_exact(2)
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
        .collect()
}
fn grease(id: u16) -> bool {
    id & 0x0f0f == 0x0a0a && id >> 8 == id & 0xff
}

#[test]
fn production_naive_hello_advertises_real_ciphers_groups_signatures_brotli_and_alps() {
    for aes_hardware in [true, false] {
        let mut config = naive_config(&options(CERT), false).unwrap();
        assert!(config.reverify_on_resume);
        assert!(!config.enable_early_data);
        config.client_hello_layout =
            Some(rustls::client::ClientHelloLayout::Naive150 { aes_hardware });
        let mut client =
            ClientConnection::new(Arc::new(config), "localhost".try_into().unwrap()).unwrap();
        let mut wire = Vec::new();
        client.write_tls(&mut wire).unwrap();
        let mut wire = wire.as_slice();
        assert_eq!(take(&mut wire, 3), [22, 3, 1]);
        let mut message = vector(&mut wire, 2);
        assert!(wire.is_empty());
        assert_eq!(take(&mut message, 1), [1]);
        let mut body = vector(&mut message, 3);
        assert!(message.is_empty());
        assert_eq!(take(&mut body, 2), [3, 3]);
        take(&mut body, 32);
        assert_eq!(vector(&mut body, 1).len(), 32);
        let suites = numbers(vector(&mut body, 2));
        assert!(grease(suites[0]));
        let expected = if aes_hardware {
            [
                0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
                0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
            ]
        } else {
            [
                0x1303, 0x1301, 0x1302, 0xcca9, 0xcca8, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc013,
                0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
            ]
        };
        assert_eq!(suites[1..], expected);
        assert_eq!(vector(&mut body, 1), [0]);
        let mut extensions = vector(&mut body, 2);
        assert!(body.is_empty());
        let mut fields = BTreeMap::new();
        while !extensions.is_empty() {
            let id = numbers(take(&mut extensions, 2))[0];
            let value = vector(&mut extensions, 2).to_vec();
            assert!(
                fields.insert(id, value).is_none(),
                "duplicate extension {id}"
            );
        }
        assert_eq!(fields.keys().filter(|id| grease(**id)).count(), 2);
        let groups = numbers(&fields[&10][2..]);
        assert!(grease(groups[0]));
        assert_eq!(groups[1..], [4588, 29, 23, 24]);
        assert_eq!(
            numbers(&fields[&13][2..]),
            [
                0x0904, 0x0905, 0x0906, 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806,
                0x0601
            ]
        );
        assert_eq!(fields[&27], [2, 0, 2]);
        assert_eq!(fields[&17613], [0, 3, 2, b'h', b'2']);
        assert_eq!(fields[&16], b"\0\x0c\x02h2\x08http/1.1");
        assert_eq!(
            numbers(&fields[&43][1..])
                .into_iter()
                .filter(|id| !grease(*id))
                .collect::<Vec<_>>(),
            [0x0304, 0x0303]
        );
        let mut shares = &fields[&51][2..];
        let mut actual = Vec::new();
        while !shares.is_empty() {
            let id = numbers(take(&mut shares, 2))[0];
            let key = vector(&mut shares, 2);
            actual.push((id, key.len()));
        }
        assert!(grease(actual[0].0));
        assert_eq!(actual[0].1, 1);
        assert_eq!(actual[1..], [(4588, 1216), (29, 32)]);
    }
}

fn server(version: &'static rustls::SupportedProtocolVersion) -> ServerConfig {
    let mut config = ServerConfig::builder_with_provider(Arc::new(aerobox_crypto::provider()))
        .with_protocol_versions(&[version])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CERT.into()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(KEY.to_vec()).into(),
        )
        .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
    config
}

fn pair(
    config: &Arc<ClientConfig>,
    server: &Arc<ServerConfig>,
    name: &str,
) -> (Connection, Connection) {
    (
        Connection::Client(
            ClientConnection::new(config.clone(), name.to_owned().try_into().unwrap()).unwrap(),
        ),
        Connection::Server(ServerConnection::new(server.clone()).unwrap()),
    )
}

fn transfer(from: &mut Connection, to: &mut Connection) -> Result<usize, Error> {
    let mut bytes = Vec::new();
    while from.wants_write() {
        assert!(from.write_tls(&mut bytes).unwrap() > 0);
    }
    for fragment in bytes.chunks(97) {
        let mut reader = fragment;
        while !reader.is_empty() {
            assert!(to.read_tls(&mut reader).unwrap() > 0);
            to.process_new_packets()?;
        }
    }
    Ok(bytes.len())
}

fn settle(client: &mut Connection, server: &mut Connection) -> Result<(), Error> {
    for _ in 0..30 {
        let sent = transfer(client, server)?;
        let received = transfer(server, client)?;
        if sent == 0 && received == 0 && !client.is_handshaking() && !server.is_handshaking() {
            return Ok(());
        }
    }
    panic!("Naive TLS handshake did not finish");
}

fn exchange(client: &mut Connection, server: &mut Connection) {
    client.writer().write_all(b"Naive client data").unwrap();
    transfer(client, server).unwrap();
    let mut bytes = [0; 17];
    server.reader().read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"Naive client data");
    server.writer().write_all(b"Naive server data").unwrap();
    transfer(server, client).unwrap();
    client.reader().read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"Naive server data");
    client.send_close_notify();
    transfer(client, server).unwrap();
    server.send_close_notify();
    transfer(server, client).unwrap();
    assert_eq!(client.reader().read(&mut [0]).unwrap(), 0);
    assert_eq!(server.reader().read(&mut [0]).unwrap(), 0);
}

#[test]
fn production_naive_tls12_and_tls13_authenticate_custom_roots_and_reject_wrong_names_and_roots() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        let server = Arc::new(server(version));
        let config = Arc::new(naive_config(&options(CERT), false).unwrap());
        let (mut client, mut peer) = pair(&config, &server, "localhost");
        settle(&mut client, &mut peer).unwrap();
        assert_eq!(client.protocol_version(), Some(version.version));
        assert_eq!(client.alpn_protocol(), Some(b"h2".as_slice()));
        exchange(&mut client, &mut peer);

        for (name, trust) in [("wrong.test", CERT), ("localhost", OTHER_CERT)] {
            let config = Arc::new(naive_config(&options(trust), false).unwrap());
            let (mut client, mut peer) = pair(&config, &server, name);
            let result = settle(&mut client, &mut peer);
            assert!(
                matches!(result, Err(Error::InvalidCertificate(_))),
                "{result:?}"
            );
        }
    }
}

#[derive(Debug)]
struct Clock(AtomicU64);
impl rustls::time_provider::TimeProvider for Clock {
    fn current_time(&self) -> Option<rustls::pki_types::UnixTime> {
        Some(rustls::pki_types::UnixTime::since_unix_epoch(
            Duration::from_secs(self.0.load(Ordering::SeqCst)),
        ))
    }
}

#[test]
fn production_naive_resumes_then_rejects_a_cached_certificate_after_it_expires() {
    let (_, certificate) = x509_parser::parse_x509_certificate(CERT).unwrap();
    let expires = u64::try_from(certificate.validity().not_after.timestamp()).unwrap();
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        let clock = Arc::new(Clock(AtomicU64::new(expires - 5)));
        let mut config = naive_config(&options(CERT), false).unwrap();
        config.time_provider = clock.clone();
        let config = Arc::new(config);
        let mut server = server(version);
        server.time_provider = Arc::new(Clock(AtomicU64::new(expires - 5)));
        let server = Arc::new(server);
        for expected in [HandshakeKind::Full, HandshakeKind::Resumed] {
            let (mut client, mut peer) = pair(&config, &server, "localhost");
            settle(&mut client, &mut peer).unwrap();
            assert_eq!(client.handshake_kind(), Some(expected));
            assert_eq!(peer.handshake_kind(), Some(expected));
            exchange(&mut client, &mut peer);
        }
        clock.0.fetch_add(10, Ordering::SeqCst);
        let (mut client, mut peer) = pair(&config, &server, "localhost");
        let result = settle(&mut client, &mut peer);
        assert_eq!(peer.handshake_kind(), Some(HandshakeKind::Resumed));
        assert!(
            matches!(
                result,
                Err(Error::InvalidCertificate(
                    rustls::CertificateError::Expired
                        | rustls::CertificateError::ExpiredContext { .. }
                ))
            ),
            "{result:?}"
        );
        assert!(client.peer_certificates().is_none());
        assert!(client.reader().read(&mut [0]).is_err());
    }
}

fn quic_pair(
    config: Arc<ClientConfig>,
    peer: Arc<ServerConfig>,
    name: &str,
) -> (rustls::quic::Connection, rustls::quic::Connection) {
    use rustls::quic::{ClientConnection, Connection, ServerConnection, Version};
    (
        Connection::Client(
            ClientConnection::new(
                config,
                Version::V1,
                name.to_owned().try_into().unwrap(),
                vec![1, 0],
            )
            .unwrap(),
        ),
        Connection::Server(ServerConnection::new(peer, Version::V1, vec![1, 0]).unwrap()),
    )
}

fn settle_quic(
    client: &mut rustls::quic::Connection,
    peer: &mut rustls::quic::Connection,
) -> Result<(), Error> {
    for _ in 0..32 {
        let mut sent = 0;
        for client_to_peer in [true, false] {
            let (from, to) = if client_to_peer {
                (&mut *client, &mut *peer)
            } else {
                (&mut *peer, &mut *client)
            };
            let mut bytes = Vec::new();
            let _ = from.write_hs(&mut bytes);
            sent += bytes.len();
            if !bytes.is_empty() {
                to.read_hs(&bytes)?;
            }
        }
        if sent == 0 && !client.is_handshaking() && !peer.is_handshaking() {
            return Ok(());
        }
    }
    panic!("Naive QUIC TLS handshake did not finish");
}

#[test]
fn production_naive_quic_authenticates_retries_and_resumes_without_bypassing_expiry() {
    let (_, certificate) = x509_parser::parse_x509_certificate(CERT).unwrap();
    let expires = u64::try_from(certificate.validity().not_after.timestamp()).unwrap();
    // P256 forces HRR because the first flight has only hybrid and X25519.
    for retry in [false, true] {
        for aes_hardware in [true, false] {
            let clock = Arc::new(Clock(AtomicU64::new(expires - 5)));
            let mut config = naive_config(&options(CERT), true).unwrap();
            config.time_provider = clock.clone();
            config.client_hello_layout =
                Some(rustls::client::ClientHelloLayout::Naive150Quic { aes_hardware });
            let config = Arc::new(config);
            let mut peer = server(&rustls::version::TLS13);
            peer.alpn_protocols = vec![b"h3".to_vec()];
            peer.time_provider = Arc::new(Clock(AtomicU64::new(expires - 5)));
            if retry {
                let mut provider = aerobox_crypto::provider();
                provider
                    .kx_groups
                    .retain(|g| g.name() == rustls::NamedGroup::secp256r1);
                peer = ServerConfig::builder_with_details(
                    Arc::new(provider),
                    peer.time_provider.clone(),
                )
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![CERT.into()],
                    rustls::pki_types::PrivatePkcs8KeyDer::from(KEY.to_vec()).into(),
                )
                .unwrap();
                peer.alpn_protocols = vec![b"h3".to_vec()];
            }
            let peer = Arc::new(peer);
            let first_kind = if retry {
                HandshakeKind::FullWithHelloRetryRequest
            } else {
                HandshakeKind::Full
            };
            for expected in [first_kind, HandshakeKind::Resumed] {
                let (mut client, mut remote) = quic_pair(config.clone(), peer.clone(), "localhost");
                settle_quic(&mut client, &mut remote).unwrap();
                assert_eq!(client.handshake_kind(), Some(expected));
                assert_eq!(client.alpn_protocol(), Some(b"h3".as_slice()));
                assert_eq!(
                    client.protocol_version(),
                    Some(rustls::ProtocolVersion::TLSv1_3)
                );
                assert_eq!(client.quic_transport_parameters(), Some([1, 0].as_slice()));
                assert!(client.zero_rtt_keys().is_none());
                assert_eq!(
                    client
                        .export_keying_material([0u8; 32], b"authenticated QUIC", None)
                        .unwrap(),
                    remote
                        .export_keying_material([0u8; 32], b"authenticated QUIC", None)
                        .unwrap()
                );
            }
            for (name, cert) in [("wrong.test", CERT), ("localhost", OTHER_CERT)] {
                let mut untrusted = naive_config(&options(cert), true).unwrap();
                untrusted.time_provider = clock.clone();
                let (mut client, mut remote) = quic_pair(Arc::new(untrusted), peer.clone(), name);
                assert!(matches!(
                    settle_quic(&mut client, &mut remote),
                    Err(Error::InvalidCertificate(_))
                ));
                assert!(client.peer_certificates().is_none());
            }
            clock.0.fetch_add(10, Ordering::SeqCst);
            let (mut client, mut remote) = quic_pair(config, peer, "localhost");
            assert!(matches!(
                settle_quic(&mut client, &mut remote),
                Err(Error::InvalidCertificate(
                    rustls::CertificateError::Expired
                        | rustls::CertificateError::ExpiredContext { .. }
                ))
            ));
            assert_eq!(remote.handshake_kind(), Some(HandshakeKind::Resumed));
            assert!(client.peer_certificates().is_none());
        }
    }
}
