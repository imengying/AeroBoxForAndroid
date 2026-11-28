use std::{net::SocketAddr, sync::Arc, time::Duration};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

fn certificate() -> CertificateDer<'static> {
    CertificateDer::from(include_bytes!("../../../tests/fixtures/ecdsa-cert.der").to_vec())
}

fn key() -> PrivateKeyDer<'static> {
    PrivatePkcs8KeyDer::from(include_bytes!("../../../tests/fixtures/ecdsa-key.der").to_vec())
        .into()
}

#[test]
fn default_quinn_and_dns_builders_use_rustcrypto() {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate()).unwrap();
    quinn::ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
    quinn::ServerConfig::with_single_cert(vec![certificate()], key()).unwrap();
    let _resolver_options = hickory_resolver::config::ResolverOpts::default();
    let dns = hickory_net::tls::client_config().unwrap();
    assert_eq!(dns.crypto_provider().cipher_suites.len(), 9);
    assert!(
        dns.crypto_provider()
            .cipher_suites
            .iter()
            .filter_map(|suite| suite.tls13())
            .all(|suite| suite.quic.is_some())
    );
}

#[test]
fn handshake_tokens_and_reset_hmac_reject_tampering() {
    use quinn::crypto::{HandshakeTokenKey, HmacKey};
    let key = aerobox_primitives::hkdf::Salt::new(aerobox_primitives::hkdf::HKDF_SHA256, &[])
        .extract(&[7; 64]);
    let token_key = key.aead_from_hkdf(&[8; 32]);
    let mut token = b"address validation token".to_vec();
    token_key.seal(&mut token, b"peer address").unwrap();
    assert!(
        token_key
            .open(&mut token.clone(), b"wrong address")
            .is_err()
    );
    assert!(
        key.aead_from_hkdf(&[9; 32])
            .open(&mut token.clone(), b"peer address")
            .is_err()
    );
    assert_eq!(
        token_key.open(&mut token, b"peer address").unwrap(),
        b"address validation token"
    );
    let hmac = aerobox_primitives::hmac::Key::new(aerobox_primitives::hmac::HMAC_SHA256, &[10; 32]);
    let mut signature = [0; 32];
    HmacKey::sign(&hmac, b"connection id", &mut signature);
    HmacKey::verify(&hmac, b"connection id", &signature).unwrap();
    signature[0] ^= 1;
    assert!(HmacKey::verify(&hmac, b"connection id", &signature).is_err());
}

#[test]
fn retry_integrity_tag_matches_rfc9001() {
    use quinn::crypto::ServerConfig;
    let config = rustls::ServerConfig::builder_with_provider(aerobox_crypto::shared_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![certificate()], key())
        .unwrap();
    let config = quinn::crypto::rustls::QuicServerConfig::try_from(config).unwrap();
    let cid = quinn::ConnectionId::new(&[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]);
    let packet = [
        0xff, 0, 0, 0, 1, 0, 8, 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5, b't', b'o', b'k',
        b'e', b'n',
    ];
    assert_eq!(
        config.retry_tag(1, &cid, &packet),
        [
            0x04, 0xa2, 0x65, 0xba, 0x2e, 0xff, 0x4d, 0x82, 0x90, 0x58, 0xfb, 0x3f, 0x0f, 0x24,
            0x96, 0xba
        ]
    );
}

#[tokio::test(flavor = "current_thread")]
async fn quinn_udp_retry_stream_datagram_and_key_update_for_all_suites() {
    tokio::time::timeout(Duration::from_secs(15), async {
        for suite in [
            &aerobox_crypto::TLS13_AES_128_GCM_SHA256,
            &aerobox_crypto::TLS13_AES_256_GCM_SHA384,
            &aerobox_crypto::TLS13_CHACHA20_POLY1305_SHA256,
        ] {
            let mut provider = aerobox_crypto::provider();
            // Pin the negotiated 1-RTT suite; Initial protection is selected
            // separately below because QUIC requires AES-128 there.
            provider.cipher_suites = vec![rustls::SupportedCipherSuite::Tls13(suite)];
            let provider = Arc::new(provider);
            let mut server_crypto = rustls::ServerConfig::builder_with_provider(provider.clone())
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![certificate()], key())
                .unwrap();
            server_crypto.ignore_client_order = true;
            let server_config = quinn::ServerConfig::with_crypto(Arc::new(
                quinn::crypto::rustls::QuicServerConfig::with_initial(
                    Arc::new(server_crypto),
                    aerobox_crypto::TLS13_AES_128_GCM_SHA256
                        .quic_suite()
                        .unwrap(),
                )
                .unwrap(),
            ));
            let server = quinn::Endpoint::server(
                server_config,
                "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            )
            .unwrap();
            let server_address = server.local_addr().unwrap();
            let server_task = tokio::spawn(async move {
                let incoming = server.accept().await.unwrap();
                assert!(!incoming.remote_address_validated());
                incoming.retry().unwrap();
                let incoming = server.accept().await.unwrap();
                assert!(incoming.remote_address_validated());
                let connection = incoming.await.unwrap();
                let (mut send, mut recv) = connection.accept_bi().await.unwrap();
                let bytes = recv.read_to_end(100_000).await.unwrap();
                send.write_all(&bytes).await.unwrap();
                send.finish().unwrap();
                let datagram = connection.read_datagram().await.unwrap();
                assert_eq!(datagram.as_ref(), b"datagram");
                connection.send_datagram(datagram).unwrap();
                connection.closed().await;
                server.wait_idle().await;
            });
            let mut roots = rustls::RootCertStore::empty();
            roots.add(certificate()).unwrap();
            let client_crypto = rustls::ClientConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
            let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            client.set_default_client_config(quinn::ClientConfig::new(Arc::new(
                quinn::crypto::rustls::QuicClientConfig::with_initial(
                    Arc::new(client_crypto),
                    aerobox_crypto::TLS13_AES_128_GCM_SHA256
                        .quic_suite()
                        .unwrap(),
                )
                .unwrap(),
            )));
            let connection = client
                .connect(server_address, "localhost")
                .unwrap()
                .await
                .unwrap();
            connection.force_key_update();
            let (mut send, mut recv) = connection.open_bi().await.unwrap();
            let bytes: Vec<_> = (0..65_000).map(|index| (index % 251) as u8).collect();
            send.write_all(&bytes).await.unwrap();
            send.finish().unwrap();
            assert_eq!(recv.read_to_end(100_000).await.unwrap(), bytes);
            connection
                .send_datagram(b"datagram".to_vec().into())
                .unwrap();
            assert_eq!(
                connection.read_datagram().await.unwrap().as_ref(),
                b"datagram"
            );
            connection.close(0u32.into(), b"done");
            server_task.await.unwrap();
            client.wait_idle().await;
        }
    })
    .await
    .expect("QUIC local validation timed out");
}
