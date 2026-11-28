//! A standard-library Go server independently checks TLS1.2 CBC key-block
//! layout, records, Finished, ticket resumption and clean TLS shutdown.
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
#[path = "../../../vendor/shoes/src/crypto/rustcrypto_kx.rs"]
mod production_hybrid;

struct Peer {
    child: Child,
    directory: PathBuf,
}
impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

#[test]
#[ignore = "requires AEROBOX_CBC_PEER built from tests/fixtures/cbc-peer/main.go"]
fn each_cbc_suite_interoperates_with_independent_go_and_resumes() {
    for suite in aerobox_crypto::legacy_cbc::suites()
        .into_iter()
        .filter(|s| matches!(u16::from(s.suite()), 0xc013 | 0xc014))
    {
        exercise(suite, false, false, false, false);
        exercise(suite, true, false, false, false);
    }
}

#[test]
#[ignore = "requires AEROBOX_CBC_PEER built from tests/fixtures/cbc-peer/main.go"]
fn static_rsa_suites_interoperate_with_ocsp_client_auth_and_resumption() {
    for suite in aerobox_crypto::legacy_rsa::suites() {
        for (staple, mutual) in [(false, false), (true, false), (false, true), (true, true)] {
            exercise(suite, staple, mutual, false, false);
        }
        exercise(suite, true, false, true, false);
    }
}

#[test]
#[ignore = "requires AEROBOX_CBC_PEER built from tests/fixtures/cbc-peer/main.go"]
fn rsa8192_static_transport_and_ecdhe_signatures_interoperate_and_resume() {
    for suite in aerobox_crypto::legacy_rsa::suites().into_iter().chain([
        rustls::SupportedCipherSuite::Tls12(
            &aerobox_crypto::legacy_cbc::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        ),
        rustls::SupportedCipherSuite::Tls12(
            &aerobox_crypto::legacy_cbc::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        ),
    ]) {
        exercise(suite, true, false, false, true);
    }
}

fn exercise(
    suite: rustls::SupportedCipherSuite,
    staple: bool,
    mutual: bool,
    bad_usage: bool,
    rsa8192: bool,
) {
    let program = std::env::var_os("AEROBOX_CBC_PEER").expect("AEROBOX_CBC_PEER is required");
    let id = u16::from(suite.suite());
    let directory = std::env::temp_dir().join(format!(
        "aerobox-cbc-{}-{id}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let child = Command::new(&program)
        .arg(&directory)
        .arg(id.to_string())
        .env("AEROBOX_TLS_STAPLE", if staple { "1" } else { "0" })
        .env("AEROBOX_TLS_MUTUAL", if mutual { "1" } else { "0" })
        .env("AEROBOX_RSA_BAD_USAGE", if bad_usage { "1" } else { "" })
        .env(
            "AEROBOX_RSA_CERT_DIR",
            if rsa8192 {
                concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/rsa8192")
            } else {
                ""
            },
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut peer = Peer { child, directory };
    let mut stdout = BufReader::new(peer.child.stdout.take().unwrap());
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let ready: serde_json::Value = serde_json::from_str(&line).unwrap();
    let port = u16::try_from(ready["port"].as_u64().unwrap()).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(
            std::fs::read(peer.directory.join("root.der")).unwrap(),
        ))
        .unwrap();
    let mut provider = aerobox_crypto::provider();
    // Offer TLS 1.3 too, so selecting a static RSA TLS 1.2 suite cannot
    // accidentally retain the speculative TLS 1.3 key exchange state.
    provider
        .cipher_suites
        .extend(aerobox_crypto::legacy_cbc::suites());
    provider
        .cipher_suites
        .extend(aerobox_crypto::legacy_rsa::suites());
    provider.kx_groups.insert(
        0,
        production_hybrid::group(rustls::NamedGroup::X25519MLKEM768),
    );
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots);
    let mut config = if mutual {
        builder
            .with_client_auth_cert(
                vec![include_bytes!("fixtures/rsa-cert.der").as_slice().into()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(
                    include_bytes!("fixtures/rsa-key.der").to_vec(),
                )
                .into(),
            )
            .unwrap()
    } else {
        builder.with_no_client_auth()
    };
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config.application_settings = Some(
        rustls::client::ApplicationSettings::new(
            rustls::client::ApplicationSettingsCodepoint::Chrome,
            vec![(b"h2".to_vec(), vec![])],
        )
        .unwrap(),
    );
    config.initial_key_share_groups = vec![
        rustls::NamedGroup::X25519MLKEM768,
        rustls::NamedGroup::X25519,
    ];
    config.client_hello_layout = Some(rustls::client::ClientHelloLayout::Chrome133);
    config.max_fragment_size = if staple { None } else { Some(1024) };
    let config = Arc::new(config);
    for iteration in 0..2 {
        let socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(15)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(15)))
            .unwrap();
        let name = if rsa8192 {
            "rsa8192.aerobox.test"
        } else {
            "cbc.aerobox.test"
        };
        let client =
            rustls::ClientConnection::new(config.clone(), name.try_into().unwrap()).unwrap();
        let mut stream = rustls::StreamOwned::new(client, socket);
        let mut header = [0; 3];
        if bad_usage {
            let error = stream.read_exact(&mut header).unwrap_err();
            assert!(error.to_string().contains("keyEncipherment"), "{error}");
            assert_eq!(header, [0; 3]);
            return;
        }
        stream.read_exact(&mut header).unwrap();
        assert_eq!(&header[..2], &id.to_be_bytes());
        assert_eq!(header[2], iteration, "Go resumption for {suite:?}");
        assert_eq!(stream.conn.negotiated_cipher_suite().unwrap(), suite);
        if aerobox_crypto::legacy_rsa::suites().contains(&suite) {
            assert!(stream.conn.negotiated_key_exchange_group().is_none());
        }
        assert_eq!(
            stream.conn.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_2)
        );
        for length in [1, 12, 17, 16384, 65537] {
            let payload: Vec<u8> = (0..length).map(|i| (i % 251) as u8).collect();
            stream.write_all(&payload).unwrap();
            stream.flush().unwrap();
            let mut received = vec![0; length];
            stream.read_exact(&mut received).unwrap();
            assert_eq!(received, payload);
        }
        stream.conn.send_close_notify();
        stream.flush().unwrap();
        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty());
    }
}

#[test]
#[ignore = "requires AEROBOX_CBC_PEER with AEAD fixture support"]
fn all_chrome_tls12_aead_suites_resume_with_scts_and_client_auth() {
    for suite in aerobox_crypto::provider()
        .cipher_suites
        .into_iter()
        .filter(|suite| suite.tls13().is_none())
    {
        for mutual in [false, true] {
            exercise(suite, true, mutual, false, false);
        }
    }
}
