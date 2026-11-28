//! Preserve ordinary TLS1.2 provider behavior and test old record splitting
//! through rustls's public integration-test interface.
use rustls::{
    ClientConfig, ClientConnection, Connection, ContentType, HandshakeKind, ProtocolVersion,
    RootCertStore, ServerConfig, ServerConnection, SignatureScheme, SupportedCipherSuite,
    Tls12CipherSuite,
    crypto::CipherSuiteCommon,
    internal::msgs::{base::Payload, fragmenter::MessageFragmenter, message::PlainMessage},
    pki_types::{CertificateDer, PrivatePkcs8KeyDer, UnixTime},
    time_provider::TimeProvider,
};
use std::{
    io::{Cursor, Read, Write},
    sync::Arc,
    time::Duration,
};

// Tls12CipherSuite::sign is a set: a future or unrecognized first entry must
// not prevent selecting an implemented scheme later in the set. This provider
// deliberately does not enable legacy TLS or use the Android11 layout.
static EXTENDED_RSA_SUITE: Tls12CipherSuite = Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: aerobox_crypto::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            .common
            .suite,
        hash_provider: aerobox_crypto::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            .common
            .hash_provider,
        confidentiality_limit: aerobox_crypto::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            .common
            .confidentiality_limit,
    },
    prf_provider: aerobox_crypto::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.prf_provider,
    kx: aerobox_crypto::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.kx,
    sign: &[
        SignatureScheme::Unknown(0x0909),
        SignatureScheme::RSA_PSS_SHA256,
    ],
    aead_alg: aerobox_crypto::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.aead_alg,
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

fn transfer(from: &mut Connection, to: &mut Connection) -> bool {
    let mut bytes = Vec::new();
    while from.wants_write() {
        assert!(from.write_tls(&mut bytes).unwrap() > 0);
    }
    if bytes.is_empty() {
        return false;
    }
    let mut input = Cursor::new(bytes.as_slice());
    while input.position() < bytes.len() as u64 {
        assert!(to.read_tls(&mut input).unwrap() > 0);
        to.process_new_packets().unwrap();
    }
    true
}

#[test]
fn ordinary_tls12_accepts_known_signature_after_unknown_suite_entry() {
    let suite = SupportedCipherSuite::Tls12(&EXTENDED_RSA_SUITE);
    let mut provider = aerobox_crypto::provider();
    provider.cipher_suites = vec![suite];
    let provider = Arc::new(provider);
    let certificate = CertificateDer::from(include_bytes!("fixtures/rsa-cert.der").as_slice());
    let mut roots = RootCertStore::empty();
    roots.add(certificate.clone()).unwrap();
    let mut client = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.time_provider = Arc::new(FixtureTime);
    let mut server = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate],
            PrivatePkcs8KeyDer::from(include_bytes!("fixtures/rsa-key.der").as_slice()).into(),
        )
        .unwrap();
    server.time_provider = Arc::new(FixtureTime);
    let mut client = Connection::Client(
        ClientConnection::new(Arc::new(client), "localhost".try_into().unwrap()).unwrap(),
    );
    let mut server = Connection::Server(ServerConnection::new(Arc::new(server)).unwrap());
    let mut complete = false;
    for _ in 0..16 {
        let sent = transfer(&mut client, &mut server);
        let received = transfer(&mut server, &mut client);
        if !client.is_handshaking() && !server.is_handshaking() && !sent && !received {
            complete = true;
            break;
        }
    }
    assert!(complete, "ordinary TLS1.2 handshake did not complete");
    for connection in [&client, &server] {
        assert_eq!(
            connection.protocol_version(),
            Some(ProtocolVersion::TLSv1_2)
        );
        assert_eq!(connection.negotiated_cipher_suite(), Some(suite));
        assert_eq!(connection.handshake_kind(), Some(HandshakeKind::Full));
    }
    assert_eq!(client.peer_certificates().unwrap().len(), 1);
    client.writer().write_all(b"ordinary client bytes").unwrap();
    assert!(transfer(&mut client, &mut server));
    let mut received = [0; 21];
    server.reader().read_exact(&mut received).unwrap();
    assert_eq!(&received, b"ordinary client bytes");
    server.writer().write_all(b"ordinary server bytes").unwrap();
    assert!(transfer(&mut server, &mut client));
    client.reader().read_exact(&mut received).unwrap();
    assert_eq!(&received, b"ordinary server bytes");
}

#[test]
fn public_fragmenter_default_preserves_cbc_tls10_splitting_at_all_boundaries() {
    // The public fragmenter's default is the conservative CBC policy. Record
    // owners override it only for an actually negotiated RC4 suite; 360/RC4 live
    // tests cover that internal selection and the unchanged CBC path.
    for (configured, maximum) in [(None, 16384usize), (Some(32), 27), (Some(1024), 1019)] {
        let mut fragmenter = MessageFragmenter::default();
        fragmenter.set_max_fragment_size(configured).unwrap();
        for length in [0, 1, 2, maximum - 1, maximum, maximum + 1, maximum * 2 + 1] {
            let data: Vec<_> = (0..length).map(|i| (i % 251) as u8).collect();
            for version in [
                ProtocolVersion::TLSv1_0,
                ProtocolVersion::TLSv1_1,
                ProtocolVersion::TLSv1_2,
            ] {
                for typ in [ContentType::ApplicationData, ContentType::Handshake] {
                    let message = PlainMessage {
                        typ,
                        version,
                        payload: Payload::new(data.clone()),
                    };
                    let mut lengths = Vec::new();
                    let mut rebuilt = Vec::new();
                    for fragment in fragmenter.fragment_message(&message) {
                        assert_eq!(fragment.typ, typ);
                        assert_eq!(fragment.version, version);
                        assert!((1..=maximum).contains(&fragment.payload.len()));
                        lengths.push(fragment.payload.len());
                        fragment.payload.copy_to_vec(&mut rebuilt);
                    }
                    assert_eq!(rebuilt, data, "{typ:?}/{version:?}/{length}");
                    let split = version == ProtocolVersion::TLSv1_0
                        && typ == ContentType::ApplicationData
                        && length > 1;
                    if length == 0 {
                        assert!(lengths.is_empty());
                    } else if split {
                        assert_eq!(lengths[0], 1);
                        assert_eq!(lengths.len(), 1 + (length - 1).div_ceil(maximum));
                        assert_eq!(lengths[1], (length - 1).min(maximum));
                    } else {
                        assert_eq!(lengths[0], length.min(maximum));
                        assert_eq!(lengths.len(), length.div_ceil(maximum));
                    }
                }
            }
        }
    }
}
