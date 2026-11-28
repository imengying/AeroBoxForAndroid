use std::{
    io::{Cursor, Read, Write},
    sync::Arc,
};

use aerobox_crypto::{
    TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256, provider,
};
use rustls::{
    ClientConfig, ClientConnection, Connection, RootCertStore, ServerConfig, ServerConnection,
    SupportedCipherSuite, SupportedProtocolVersion,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
    quic::{self, KeyChange, Keys},
    time_provider::TimeProvider,
};

#[derive(Debug)]
struct FixtureTime;

#[path = "provider/rsa8192.rs"]
mod rsa8192;

#[test]
fn p521_go_signatures_verify_and_reject_modified_inputs() {
    use rustls::pki_types::alg_id;
    let crypto = provider();
    let public = include_bytes!("fixtures/p521-public.sec1");
    let message = b"AeroBox independent Go P-521 fixture";
    for (algorithm, signature) in [
        (
            alg_id::ECDSA_SHA256,
            include_bytes!("fixtures/p521-signature-sha256.der").as_slice(),
        ),
        (
            alg_id::ECDSA_SHA384,
            include_bytes!("fixtures/p521-signature-sha384.der").as_slice(),
        ),
        (
            alg_id::ECDSA_SHA512,
            include_bytes!("fixtures/p521-signature-sha512.der").as_slice(),
        ),
    ] {
        let verifier = crypto
            .signature_verification_algorithms
            .all
            .iter()
            .find(|v| {
                v.public_key_alg_id() == alg_id::ECDSA_P521 && v.signature_alg_id() == algorithm
            })
            .unwrap();
        verifier
            .verify_signature(public, message, signature)
            .unwrap();
        assert!(
            verifier
                .verify_signature(public, b"modified message", signature)
                .is_err()
        );
        assert!(
            verifier
                .verify_signature(public, message, &signature[..signature.len() - 1])
                .is_err()
        );
        let mut bad_key = *public;
        bad_key[1] ^= 0x80;
        assert!(
            verifier
                .verify_signature(&bad_key, message, signature)
                .is_err()
        );
        let mut bad_signature = signature.to_vec();
        *bad_signature.last_mut().unwrap() ^= 1;
        assert!(
            verifier
                .verify_signature(public, message, &bad_signature)
                .is_err()
        );
    }
}

#[test]
fn p521_certificate_chains_mutual_authentication_and_key_exchange_work_in_tls12_and_tls13() {
    use rustls::{NamedGroup, pki_types::PrivateSec1KeyDer, server::WebPkiClientVerifier};
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for leaf in [
            include_bytes!("fixtures/p521-cert-sha256.der").as_slice(),
            include_bytes!("fixtures/p521-cert-sha384.der").as_slice(),
            include_bytes!("fixtures/p521-cert.der").as_slice(),
        ] {
            for sec1 in [false, true] {
                let mut crypto = provider();
                crypto
                    .kx_groups
                    .retain(|group| group.name() == NamedGroup::secp521r1);
                let crypto = Arc::new(crypto);
                let mut roots = RootCertStore::empty();
                roots
                    .add(CertificateDer::from(
                        include_bytes!("fixtures/p521-ca.der").to_vec(),
                    ))
                    .unwrap();
                let roots = Arc::new(roots);
                let key = || {
                    if sec1 {
                        PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(
                            include_bytes!("fixtures/p521-key-sec1.der").to_vec(),
                        ))
                    } else {
                        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                            include_bytes!("fixtures/p521-key.der").to_vec(),
                        ))
                    }
                };
                let cert = || vec![CertificateDer::from(leaf.to_vec())];
                let mut client = ClientConfig::builder_with_provider(crypto.clone())
                    .with_protocol_versions(&[version])
                    .unwrap()
                    .with_root_certificates(roots.clone())
                    .with_client_auth_cert(cert(), key())
                    .unwrap();
                client.time_provider = Arc::new(FixtureTime);
                let verifier = WebPkiClientVerifier::builder_with_provider(roots, crypto.clone())
                    .build()
                    .unwrap();
                let mut server = ServerConfig::builder_with_provider(crypto)
                    .with_protocol_versions(&[version])
                    .unwrap()
                    .with_client_cert_verifier(verifier)
                    .with_single_cert(cert(), key())
                    .unwrap();
                server.time_provider = Arc::new(FixtureTime);
                let mut client = Connection::Client(
                    ClientConnection::new(
                        Arc::new(client),
                        ServerName::try_from("localhost").unwrap(),
                    )
                    .unwrap(),
                );
                let mut server =
                    Connection::Server(ServerConnection::new(Arc::new(server)).unwrap());
                handshake(&mut client, &mut server).unwrap();
                assert!(client.peer_certificates().is_some());
                assert!(server.peer_certificates().is_some());
                assert_eq!(
                    client.negotiated_key_exchange_group().unwrap().name(),
                    NamedGroup::secp521r1
                );
                client.writer().write_all(b"P-521 mutual TLS").unwrap();
                transfer(&mut client, &mut server).unwrap();
                let mut output = [0; 16];
                server.reader().read_exact(&mut output).unwrap();
                assert_eq!(&output, b"P-521 mutual TLS");
            }
        }
    }
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        include_bytes!("fixtures/p521-key.der").to_vec(),
    ));
    let certificate = CertificateDer::from(include_bytes!("fixtures/ecdsa-cert.der").to_vec());
    assert!(
        ServerConfig::builder_with_provider(Arc::new(provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![certificate], key)
            .is_err()
    );
}

#[test]
fn p521_ecdh_matches_independent_go_vector() {
    use p521::pkcs8::DecodePrivateKey;
    let local = p521::SecretKey::from_pkcs8_der(include_bytes!("fixtures/p521-key.der")).unwrap();
    let peer =
        p521::PublicKey::from_sec1_bytes(include_bytes!("fixtures/p521-ecdh-peer.sec1")).unwrap();
    let shared = p521::ecdh::diffie_hellman(local.to_nonzero_scalar(), peer.as_affine());
    assert_eq!(
        shared.raw_secret_bytes().as_slice(),
        include_bytes!("fixtures/p521-ecdh-secret.bin")
    );
}

#[test]
fn mismatched_certificate_and_private_key_are_rejected() {
    let cert = CertificateDer::from(include_bytes!("fixtures/ecdsa-cert.der").to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        include_bytes!("fixtures/rsa-key.der").to_vec(),
    ));
    let result = ServerConfig::builder_with_provider(Arc::new(provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key);
    assert!(matches!(result, Err(rustls::Error::InconsistentKeys(_))));
}

impl TimeProvider for FixtureTime {
    fn current_time(&self) -> Option<UnixTime> {
        // Fixtures cover 2026..2126. A fixed time keeps the tests deterministic.
        Some(UnixTime::since_unix_epoch(std::time::Duration::from_secs(
            1_893_456_000,
        )))
    }
}

fn configs(
    suite: SupportedCipherSuite,
    version: &'static SupportedProtocolVersion,
    rsa: bool,
) -> (ClientConfig, ServerConfig) {
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
    let mut crypto = provider();
    crypto.cipher_suites = vec![suite];
    let crypto = Arc::new(crypto);
    let mut roots = RootCertStore::empty();
    roots.add(cert.clone()).unwrap();
    let mut client = ClientConfig::builder_with_provider(crypto.clone())
        .with_protocol_versions(&[version])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.time_provider = Arc::new(FixtureTime);
    let mut server = ServerConfig::builder_with_provider(crypto)
        .with_protocol_versions(&[version])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    client.alpn_protocols = vec![b"h3".to_vec()];
    server.alpn_protocols = vec![b"h3".to_vec()];
    client.enable_secret_extraction = true;
    server.enable_secret_extraction = true;
    (client, server)
}

fn transfer(from: &mut Connection, to: &mut Connection) -> Result<bool, rustls::Error> {
    let mut bytes = Vec::new();
    while from.wants_write() {
        from.write_tls(&mut bytes).unwrap();
    }
    if bytes.is_empty() {
        return Ok(false);
    }
    let mut bytes = Cursor::new(bytes);
    while bytes.position() < bytes.get_ref().len() as u64 {
        to.read_tls(&mut bytes).unwrap();
        to.process_new_packets()?;
    }
    Ok(true)
}

fn handshake(client: &mut Connection, server: &mut Connection) -> Result<(), rustls::Error> {
    for _ in 0..32 {
        let client_progress = transfer(client, server)?;
        let server_progress = transfer(server, client)?;
        if !client.is_handshaking()
            && !server.is_handshaking()
            && !client_progress
            && !server_progress
        {
            return Ok(());
        }
    }
    panic!("handshake stalled");
}

#[test]
fn tls12_and_tls13_transfer_data_for_every_advertised_suite() {
    for suite in provider().cipher_suites {
        for rsa in [false, true] {
            let version = match suite {
                SupportedCipherSuite::Tls12(suite) => {
                    let is_rsa = suite
                        .sign
                        .iter()
                        .any(|scheme| matches!(scheme, rustls::SignatureScheme::RSA_PSS_SHA256));
                    if is_rsa != rsa {
                        continue;
                    }
                    &rustls::version::TLS12
                }
                SupportedCipherSuite::Tls13(_) => &rustls::version::TLS13,
            };
            let (client, server) = configs(suite, version, rsa);
            let mut client = Connection::Client(
                ClientConnection::new(Arc::new(client), ServerName::try_from("localhost").unwrap())
                    .unwrap(),
            );
            let mut server = Connection::Server(ServerConnection::new(Arc::new(server)).unwrap());
            handshake(&mut client, &mut server)
                .unwrap_or_else(|error| panic!("{suite:?}, RSA={rsa}: {error:?}"));
            assert_eq!(client.negotiated_cipher_suite(), Some(suite));
            let payload: Vec<_> = (0..40_000).map(|index| (index % 251) as u8).collect();
            let mut received = vec![0; payload.len()];
            // Drain plaintext between batches, as a real application does;
            // rustls deliberately caps unconsumed received plaintext.
            for (plain, received) in payload.chunks(16_000).zip(received.chunks_mut(16_000)) {
                client.writer().write_all(plain).unwrap();
                transfer(&mut client, &mut server).unwrap();
                server.reader().read_exact(received).unwrap();
            }
            assert_eq!(received, payload);
            server.writer().write_all(b"response").unwrap();
            transfer(&mut server, &mut client).unwrap();
            let mut received = [0; 8];
            client.reader().read_exact(&mut received).unwrap();
            assert_eq!(&received, b"response");
            let client_secrets = client.dangerous_extract_secrets().unwrap();
            let server_secrets = server.dangerous_extract_secrets().unwrap();
            matching_secrets(suite, client_secrets.tx.1, server_secrets.rx.1);
            matching_secrets(suite, server_secrets.tx.1, client_secrets.rx.1);
        }
    }
}

fn matching_secrets(
    suite: SupportedCipherSuite,
    sender: rustls::ConnectionTrafficSecrets,
    receiver: rustls::ConnectionTrafficSecrets,
) {
    use rustls::{CipherSuite as Suite, ConnectionTrafficSecrets as Secrets};
    let expected_len = match suite.suite() {
        Suite::TLS13_AES_128_GCM_SHA256
        | Suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        | Suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => 16,
        _ => 32,
    };
    let (a, ai, b, bi) = match (sender, receiver) {
        (Secrets::Aes128Gcm { key: a, iv: ai }, Secrets::Aes128Gcm { key: b, iv: bi }) => {
            assert_eq!(expected_len, 16);
            (a, ai, b, bi)
        }
        (Secrets::Aes256Gcm { key: a, iv: ai }, Secrets::Aes256Gcm { key: b, iv: bi }) => {
            assert_eq!(expected_len, 32);
            (a, ai, b, bi)
        }
        (
            Secrets::Chacha20Poly1305 { key: a, iv: ai },
            Secrets::Chacha20Poly1305 { key: b, iv: bi },
        ) => {
            assert!(matches!(
                suite.suite(),
                Suite::TLS13_CHACHA20_POLY1305_SHA256
                    | Suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
                    | Suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            ));
            (a, ai, b, bi)
        }
        _ => panic!("traffic-secret algorithms disagree"),
    };
    assert_eq!(a.as_ref().len(), expected_len);
    assert_eq!(a.as_ref(), b.as_ref());
    assert_eq!(ai.as_ref(), bi.as_ref());
}

#[test]
fn certificate_hostname_verification_is_enforced() {
    let suite = SupportedCipherSuite::Tls13(&TLS13_AES_128_GCM_SHA256);
    let (client, server) = configs(suite, &rustls::version::TLS13, false);
    let mut client = Connection::Client(
        ClientConnection::new(
            Arc::new(client),
            ServerName::try_from("wrong.example").unwrap(),
        )
        .unwrap(),
    );
    let mut server = Connection::Server(ServerConnection::new(Arc::new(server)).unwrap());
    assert!(matches!(
        handshake(&mut client, &mut server),
        Err(rustls::Error::InvalidCertificate(_))
    ));
}

fn capture_key(change: Option<KeyChange>, result: &mut Option<(Keys, quic::Secrets)>) {
    if let Some(KeyChange::OneRtt { keys, next }) = change {
        *result = Some((keys, next));
    }
}

fn protected_payload(local: &dyn quic::PacketKey, remote: &dyn quic::PacketKey, number: u64) {
    let plain = b"QUIC application bytes";
    let header = b"authenticated header";
    let mut payload = plain.to_vec();
    let tag = local
        .encrypt_in_place(number, header, &mut payload)
        .unwrap();
    payload.extend_from_slice(tag.as_ref());
    assert_eq!(
        remote
            .decrypt_in_place(number, header, &mut payload)
            .unwrap(),
        plain
    );
}

#[test]
fn quic_tls_handshake_packet_protection_and_key_update_for_all_suites() {
    for suite in [
        &TLS13_AES_128_GCM_SHA256,
        &TLS13_AES_256_GCM_SHA384,
        &TLS13_CHACHA20_POLY1305_SHA256,
    ] {
        let (client, server) = configs(
            SupportedCipherSuite::Tls13(suite),
            &rustls::version::TLS13,
            false,
        );
        let mut client = quic::ClientConnection::new(
            Arc::new(client),
            quic::Version::V1,
            ServerName::try_from("localhost").unwrap(),
            vec![1, 2, 3],
        )
        .unwrap();
        let mut server =
            quic::ServerConnection::new(Arc::new(server), quic::Version::V1, vec![4, 5, 6])
                .unwrap();
        let mut client_keys = None;
        let mut server_keys = None;
        for _ in 0..32 {
            let mut bytes = Vec::new();
            capture_key(client.write_hs(&mut bytes), &mut client_keys);
            if !bytes.is_empty() {
                server.read_hs(&bytes).unwrap();
            }
            let mut bytes = Vec::new();
            capture_key(server.write_hs(&mut bytes), &mut server_keys);
            if !bytes.is_empty() {
                client.read_hs(&bytes).unwrap();
            }
            if !client.is_handshaking()
                && !server.is_handshaking()
                && client_keys.is_some()
                && server_keys.is_some()
            {
                break;
            }
        }
        assert!(!client.is_handshaking());
        assert!(!server.is_handshaking());
        assert_eq!(
            client.quic_transport_parameters(),
            Some([4, 5, 6].as_slice())
        );
        assert_eq!(
            server.quic_transport_parameters(),
            Some([1, 2, 3].as_slice())
        );
        let (client_keys, mut client_secrets) = client_keys.expect("client 1-RTT keys");
        let (server_keys, mut server_secrets) = server_keys.expect("server 1-RTT keys");
        protected_payload(&*client_keys.local.packet, &*server_keys.remote.packet, 42);
        protected_payload(&*server_keys.local.packet, &*client_keys.remote.packet, 43);
        let client_updated = client_secrets.next_packet_keys();
        let server_updated = server_secrets.next_packet_keys();
        protected_payload(&*client_updated.local, &*server_updated.remote, 44);
        protected_payload(&*server_updated.local, &*client_updated.remote, 45);
    }
}

fn hex(value: &str) -> Vec<u8> {
    let bytes: String = value.chars().filter(|c| !c.is_whitespace()).collect();
    assert_eq!(bytes.len() % 2, 0);
    (0..bytes.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&bytes[index..index + 2], 16).unwrap())
        .collect()
}

#[test]
fn rfc9001_server_initial_packet_matches_known_bytes() {
    let suite = TLS13_AES_128_GCM_SHA256.quic_suite().unwrap();
    let keys = suite.keys(
        &hex("8394c8f03e515708"),
        rustls::Side::Server,
        quic::Version::V1,
    );
    let mut header = hex("c1000000010008f067a5502a4262b50040750001");
    let mut payload = hex(
        "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf73988cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c940d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00020304",
    );
    let tag = keys
        .local
        .packet
        .encrypt_in_place(1, &header, &mut payload)
        .unwrap();
    payload.extend_from_slice(tag.as_ref());
    let mut first = header[0];
    keys.local
        .header
        .encrypt_in_place(&payload[2..18], &mut first, &mut header[18..])
        .unwrap();
    header[0] = first;
    header.extend_from_slice(&payload);
    assert_eq!(
        header,
        hex(
            "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc42158407dd074ee"
        )
    );
}

#[test]
fn rfc9001_chacha_short_packet_matches_known_bytes() {
    use rustls::crypto::cipher::{AeadKey, Iv};
    let algorithm = TLS13_CHACHA20_POLY1305_SHA256.quic.unwrap();
    let key = algorithm.packet_key(
        AeadKey::from(
            <[u8; 32]>::try_from(hex(
                "c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8",
            ))
            .unwrap(),
        ),
        Iv::from(<[u8; 12]>::try_from(hex("e0459b3474bdd0e44a41c144")).unwrap()),
    );
    let hp = algorithm.header_protection_key(AeadKey::from(
        <[u8; 32]>::try_from(hex(
            "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4",
        ))
        .unwrap(),
    ));
    let mut header = hex("4200bff4");
    let mut payload = vec![1];
    let tag = key
        .encrypt_in_place(654_360_564, &header, &mut payload)
        .unwrap();
    payload.extend_from_slice(tag.as_ref());
    let mut first = header[0];
    hp.encrypt_in_place(&payload[1..17], &mut first, &mut header[1..])
        .unwrap();
    header[0] = first;
    header.extend_from_slice(&payload);
    assert_eq!(header, hex("4cfe4189655e5cd55c41f69080575d7999c25a5bfb"));
    let mut number = header[1..4].to_vec();
    hp.decrypt_in_place(&payload[1..17], &mut first, &mut number)
        .unwrap();
    assert_eq!(first, 0x42);
    assert_eq!(number, hex("00bff4"));
    assert_eq!(
        key.decrypt_in_place(654_360_564, &hex("4200bff4"), &mut payload)
            .unwrap(),
        &[1]
    );
}

#[test]
fn truncated_packets_and_invalid_header_inputs_are_rejected_without_mutation() {
    let keys = TLS13_AES_128_GCM_SHA256.quic_suite().unwrap().keys(
        &[1, 2, 3],
        rustls::Side::Client,
        quic::Version::V1,
    );
    for length in 0..16 {
        assert!(
            keys.local
                .packet
                .decrypt_in_place(0, &[], &mut vec![0; length])
                .is_err()
        );
    }
    let mut first = 0xc3;
    let mut number = [1, 2, 3, 4];
    assert!(
        keys.local
            .header
            .encrypt_in_place(&[0; 15], &mut first, &mut number)
            .is_err()
    );
    assert_eq!(first, 0xc3);
    assert_eq!(number, [1, 2, 3, 4]);
    assert!(
        keys.local
            .header
            .encrypt_in_place(&[0; 16], &mut first, &mut number[..2])
            .is_err()
    );
    assert_eq!(first, 0xc3);
    assert_eq!(number, [1, 2, 3, 4]);
}

#[test]
fn packet_authentication_covers_header_payload_and_packet_number() {
    for suite in [
        &TLS13_AES_128_GCM_SHA256,
        &TLS13_AES_256_GCM_SHA384,
        &TLS13_CHACHA20_POLY1305_SHA256,
    ] {
        let keys =
            suite
                .quic_suite()
                .unwrap()
                .keys(&[1, 2, 3], rustls::Side::Client, quic::Version::V1);
        let mut payload = b"secret".to_vec();
        let tag = keys
            .local
            .packet
            .encrypt_in_place(7, b"header", &mut payload)
            .unwrap();
        payload.extend_from_slice(tag.as_ref());
        assert!(
            keys.local
                .packet
                .decrypt_in_place(8, b"header", &mut payload.clone())
                .is_err()
        );
        assert!(
            keys.local
                .packet
                .decrypt_in_place(7, b"altered", &mut payload.clone())
                .is_err()
        );
        payload[0] ^= 1;
        assert!(
            keys.local
                .packet
                .decrypt_in_place(7, b"header", &mut payload)
                .is_err()
        );

        let mut payload = b"multipath".to_vec();
        let tag = keys
            .local
            .packet
            .encrypt_in_place_for_path(123, 8, b"header", &mut payload)
            .unwrap();
        payload.extend_from_slice(tag.as_ref());
        assert!(
            keys.local
                .packet
                .decrypt_in_place_for_path(124, 8, b"header", &mut payload.clone())
                .is_err()
        );
        assert_eq!(
            keys.local
                .packet
                .decrypt_in_place_for_path(123, 8, b"header", &mut payload)
                .unwrap(),
            b"multipath"
        );
    }
}

#[test]
fn header_protection_preserves_flags_and_unused_number_bytes() {
    for suite in [
        &TLS13_AES_128_GCM_SHA256,
        &TLS13_AES_256_GCM_SHA384,
        &TLS13_CHACHA20_POLY1305_SHA256,
    ] {
        let keys =
            suite
                .quic_suite()
                .unwrap()
                .keys(&[1, 2, 3], rustls::Side::Client, quic::Version::V1);
        for original in [0x40, 0x41, 0x42, 0x43, 0xc0, 0xc1, 0xc2, 0xc3] {
            let mut first = original;
            let mut number = [1, 2, 3, 4];
            let length = usize::from(original & 3) + 1;
            keys.local
                .header
                .encrypt_in_place(&[42; 16], &mut first, &mut number)
                .unwrap();
            let unmasked = if original & 0x80 != 0 { 0xf0 } else { 0xe0 };
            assert_eq!(first & unmasked, original & unmasked);
            assert_eq!(&number[length..], &[1, 2, 3, 4][length..]);
            keys.local
                .header
                .decrypt_in_place(&[42; 16], &mut first, &mut number)
                .unwrap();
            assert_eq!(first, original);
            assert_eq!(number, [1, 2, 3, 4]);
        }
    }
}

#[test]
fn chacha_header_protection_accepts_the_maximum_block_counter() {
    use rustls::crypto::cipher::AeadKey;
    let hp = TLS13_CHACHA20_POLY1305_SHA256
        .quic
        .unwrap()
        .header_protection_key(AeadKey::from([0; 32]));
    let mut sample = [0; 16];
    sample[..4].fill(0xff);
    let mut first = 0x43;
    let mut number = [0; 4];
    hp.encrypt_in_place(&sample, &mut first, &mut number)
        .unwrap();
    // Independent OpenSSL ChaCha20 output for zero key/nonce and counter
    // 0xffffffff begins ace4cd09e2. No OpenSSL dependency is used by the test.
    assert_eq!(first, 0x4f);
    assert_eq!(number, [0xe4, 0xcd, 0x09, 0xe2]);
    hp.decrypt_in_place(&sample, &mut first, &mut number)
        .unwrap();
    assert_eq!(first, 0x43);
    assert_eq!(number, [0; 4]);
}

#[test]
fn key_exchange_groups_agree_and_reject_invalid_or_noncontributory_shares() {
    for group in provider().kx_groups {
        let alice = group.start().unwrap();
        let bob = group.start().unwrap();
        let alice_public = alice.pub_key().to_vec();
        let bob_public = bob.pub_key().to_vec();
        let alice_secret = alice.complete(&bob_public).unwrap();
        let bob_secret = bob.complete(&alice_public).unwrap();
        assert_eq!(alice_secret.secret_bytes(), bob_secret.secret_bytes());
        assert!(alice_secret.secret_bytes().iter().any(|&byte| byte != 0));
        for invalid in [&[][..], &[0; 31], &[0; 32], &[0; 65], &[0; 97]] {
            assert!(group.start().unwrap().complete(invalid).is_err());
        }
        if group.name() == rustls::NamedGroup::X25519 {
            let mut small_order = [0; 32];
            small_order[0] = 1;
            assert!(group.start().unwrap().complete(&small_order).is_err());
        } else {
            let coordinate_len = (alice_public.len() - 1) / 2;
            let mut compressed = vec![2 | (alice_public.last().unwrap() & 1)];
            compressed.extend_from_slice(&alice_public[1..1 + coordinate_len]);
            assert!(group.start().unwrap().complete(&compressed).is_err());
        }
    }
}

#[test]
fn truncated_tls12_chacha_records_return_errors_without_panicking() {
    use rustls::crypto::cipher::{AeadKey, InboundOpaqueMessage};
    let algorithm = aerobox_crypto::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256.aead_alg;
    let mut decrypt = algorithm.decrypter(AeadKey::from([0; 32]), &[0; 12]);
    for length in 0..32 {
        let mut payload = vec![0; length];
        let record = InboundOpaqueMessage::new(
            rustls::ContentType::ApplicationData,
            rustls::ProtocolVersion::TLSv1_2,
            &mut payload,
        );
        assert!(decrypt.decrypt(record, 0).is_err());
    }
}
