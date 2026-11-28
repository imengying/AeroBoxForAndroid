use super::*;

#[test]
fn go_rsa8192_signatures_verify_and_reject_modified_inputs() {
    use rustls::pki_types::alg_id;
    let crypto = provider();
    let public = include_bytes!("../fixtures/rsa8192/public.der");
    let message = include_bytes!("../fixtures/rsa8192/message.bin");
    for (algorithm, signature) in [
        (
            alg_id::RSA_PKCS1_SHA256,
            include_bytes!("../fixtures/rsa8192/pkcs1-sha256.sig").as_slice(),
        ),
        (
            alg_id::RSA_PKCS1_SHA384,
            include_bytes!("../fixtures/rsa8192/pkcs1-sha384.sig").as_slice(),
        ),
        (
            alg_id::RSA_PKCS1_SHA512,
            include_bytes!("../fixtures/rsa8192/pkcs1-sha512.sig").as_slice(),
        ),
        (
            alg_id::RSA_PSS_SHA256,
            include_bytes!("../fixtures/rsa8192/pss-sha256.sig").as_slice(),
        ),
        (
            alg_id::RSA_PSS_SHA384,
            include_bytes!("../fixtures/rsa8192/pss-sha384.sig").as_slice(),
        ),
        (
            alg_id::RSA_PSS_SHA512,
            include_bytes!("../fixtures/rsa8192/pss-sha512.sig").as_slice(),
        ),
    ] {
        let verifier = crypto
            .signature_verification_algorithms
            .all
            .iter()
            .find(|v| {
                v.public_key_alg_id() == alg_id::RSA_ENCRYPTION && v.signature_alg_id() == algorithm
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
        let mut bad_key = public.to_vec();
        bad_key[100] ^= 0x80;
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
fn rsa8192_certificate_keys_support_tls12_and_tls13_mutual_authentication() {
    use rustls::server::WebPkiClientVerifier;
    let cert = || {
        vec![
            include_bytes!("../fixtures/rsa8192/leaf.der")
                .as_slice()
                .into(),
        ]
    };
    let key =
        || PrivatePkcs8KeyDer::from(include_bytes!("../fixtures/rsa8192/key.der").to_vec()).into();
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        let crypto = Arc::new(provider());
        let mut roots = RootCertStore::empty();
        roots
            .add(
                include_bytes!("../fixtures/rsa8192/ca.der")
                    .as_slice()
                    .into(),
            )
            .unwrap();
        let roots = Arc::new(roots);
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
                ServerName::try_from("rsa8192.aerobox.test").unwrap(),
            )
            .unwrap(),
        );
        let mut server = Connection::Server(ServerConnection::new(Arc::new(server)).unwrap());
        handshake(&mut client, &mut server).unwrap();
        assert_eq!(client.protocol_version(), Some(version.version));
        assert!(client.peer_certificates().is_some());
        assert!(server.peer_certificates().is_some());
        client.writer().write_all(b"8192 mutual TLS").unwrap();
        transfer(&mut client, &mut server).unwrap();
        let mut output = [0; 15];
        server.reader().read_exact(&mut output).unwrap();
        assert_eq!(&output, b"8192 mutual TLS");
    }
}
