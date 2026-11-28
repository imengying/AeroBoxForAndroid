//! Independent Go PKI fixtures and OpenSSL TLS server, used only in tests.
use aerobox_crypto::mldsa;
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme,
    client::{WebPkiServerVerifier, danger::ServerCertVerifier},
    crypto::{CryptoProvider, WebPkiSupportedAlgorithms},
    internal::msgs::codec::Codec,
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};

fn fixtures() -> PathBuf {
    let path = PathBuf::from(
        std::env::var_os("AEROBOX_MLDSA_FIXTURES")
            .expect("AEROBOX_MLDSA_FIXTURES must point to independently generated fixtures"),
    );
    assert!(path.is_absolute() && path.join("manifest.json").is_file());
    path
}

fn cases() -> Vec<(u16, PathBuf)> {
    let root = fixtures();
    [44, 65, 87]
        .into_iter()
        .flat_map(|parameters| {
            let root = root.clone();
            ["classical-ca-pq-leaf", "pq-ca-classical-leaf", "pq-chain"]
                .into_iter()
                .map(move |kind| (parameters, root.join(format!("ML-DSA-{parameters}-{kind}"))))
        })
        .collect()
}

fn certificate(directory: &Path, name: &str) -> CertificateDer<'static> {
    std::fs::read(directory.join(format!("{name}.der")))
        .unwrap()
        .into()
}

fn provider() -> CryptoProvider {
    // Explicit test-only composition. This does not change any production
    // provider, existing browser profile, signature policy or global default.
    static ALGORITHMS: OnceLock<WebPkiSupportedAlgorithms> = OnceLock::new();
    let mut provider = aerobox_crypto::provider();
    provider.signature_verification_algorithms = *ALGORITHMS.get_or_init(|| {
        let ordinary = aerobox_crypto::provider().signature_verification_algorithms;
        let mut all = ordinary.all.to_vec();
        all.extend_from_slice(mldsa::ALGORITHMS.all);
        let mut mapping = mldsa::ALGORITHMS.mapping.to_vec();
        mapping.extend_from_slice(ordinary.mapping);
        WebPkiSupportedAlgorithms {
            all: Box::leak(all.into_boxed_slice()),
            mapping: Box::leak(mapping.into_boxed_slice()),
        }
    });
    provider
}

fn roots(directory: &Path) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.add(certificate(directory, "root")).unwrap();
    roots
}

fn time() -> UnixTime {
    UnixTime::since_unix_epoch(Duration::from_secs(1_798_761_600))
}

#[test]
#[ignore = "requires fixed independent Go ML-DSA certificate corpus"]
fn independent_mldsa_certificate_chains_preserve_authentication_checks() {
    let name = ServerName::try_from("mldsa.aerobox.test").unwrap();
    let wrong_name = ServerName::try_from("wrong.aerobox.test").unwrap();
    for (_, directory) in cases() {
        let verifier = WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots(&directory)),
            Arc::new(provider()),
        )
        .build()
        .unwrap();
        let leaf = certificate(&directory, "leaf");
        let intermediates = [certificate(&directory, "intermediate")];
        verifier
            .verify_server_cert(&leaf, &intermediates, &name, &[], time())
            .unwrap_or_else(|error| panic!("{}: {error:?}", directory.display()));
        assert!(
            verifier
                .verify_server_cert(&leaf, &intermediates, &wrong_name, &[], time())
                .is_err()
        );
        assert!(
            verifier
                .verify_server_cert(
                    &certificate(&directory, "client-only"),
                    &intermediates,
                    &name,
                    &[],
                    time()
                )
                .is_err()
        );
        for seconds in [0, 2_200_000_000] {
            assert!(
                verifier
                    .verify_server_cert(
                        &leaf,
                        &intermediates,
                        &name,
                        &[],
                        UnixTime::since_unix_epoch(Duration::from_secs(seconds))
                    )
                    .is_err()
            );
        }
        let mut broken = leaf.to_vec();
        *broken.last_mut().unwrap() ^= 1;
        assert!(
            verifier
                .verify_server_cert(&broken.into(), &intermediates, &name, &[], time())
                .is_err()
        );
        let mut broken = intermediates[0].to_vec();
        *broken.last_mut().unwrap() ^= 1;
        assert!(
            verifier
                .verify_server_cert(&leaf, &[broken.into()], &name, &[], time())
                .is_err()
        );
        assert!(
            verifier
                .verify_server_cert(&leaf, &[], &name, &[], time())
                .is_err()
        );
    }
}

#[test]
#[ignore = "requires fixed independent Go ML-DSA certificate corpus"]
fn ordinary_provider_rejects_mldsa_issuer_signatures() {
    let name = ServerName::try_from("mldsa.aerobox.test").unwrap();
    for (_, directory) in cases().into_iter().filter(|(_, directory)| {
        !directory
            .file_name()
            .unwrap()
            .to_string_lossy()
            .contains("classical-ca-pq-leaf")
    }) {
        let verifier = WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots(&directory)),
            Arc::new(aerobox_crypto::provider()),
        )
        .build()
        .unwrap();
        assert!(
            verifier
                .verify_server_cert(
                    &certificate(&directory, "leaf"),
                    &[certificate(&directory, "intermediate")],
                    &name,
                    &[],
                    time()
                )
                .is_err()
        );
    }
}

#[test]
#[ignore = "requires independently signed strict-DER ML-DSA fixtures"]
fn valid_cryptography_does_not_allow_null_ml_dsa_algorithm_parameters() {
    let name = ServerName::try_from("mldsa.aerobox.test").unwrap();
    let mut issuer_cases = 0;
    let mut leaf_cases = 0;
    for (parameters, directory) in cases() {
        let verifier = WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots(&directory)),
            Arc::new(provider()),
        )
        .build()
        .unwrap();
        let intermediates = [certificate(&directory, "intermediate")];
        if directory.join("signature-null.der").exists() {
            // Go independently re-signed the modified TBS and verified its
            // signature. This checks the algorithm policy, not corrupted data.
            assert!(
                verifier
                    .verify_server_cert(
                        &certificate(&directory, "signature-null"),
                        &intermediates,
                        &name,
                        &[],
                        time()
                    )
                    .is_err()
            );
            issuer_cases += 1;
        }
        if directory.join("spki-null.der").exists() {
            let message = std::fs::read(directory.join("cv-message.bin")).unwrap();
            let signature = std::fs::read(directory.join("cv-signature.bin")).unwrap();
            let scheme = match parameters {
                44 => SignatureScheme::ML_DSA_44,
                65 => SignatureScheme::ML_DSA_65,
                87 => SignatureScheme::ML_DSA_87,
                _ => unreachable!(),
            };
            let mut encoded = u16::from(scheme).to_be_bytes().to_vec();
            encoded.extend_from_slice(&u16::try_from(signature.len()).unwrap().to_be_bytes());
            encoded.extend_from_slice(&signature);
            let signature = DigitallySignedStruct::read_bytes(&encoded).unwrap();
            verifier
                .verify_tls13_signature(&message, &certificate(&directory, "leaf"), &signature)
                .unwrap();
            assert!(
                verifier
                    .verify_tls13_signature(
                        &message,
                        &certificate(&directory, "spki-null"),
                        &signature
                    )
                    .is_err()
            );
            let mut wrong_role = message.clone();
            wrong_role[64] ^= 1;
            assert!(
                verifier
                    .verify_tls13_signature(
                        &wrong_role,
                        &certificate(&directory, "leaf"),
                        &signature
                    )
                    .is_err()
            );
            leaf_cases += 1;
        }
    }
    assert_eq!((issuer_cases, leaf_cases), (3, 6));
}

#[derive(Debug)]
struct FixtureTime;
impl rustls::time_provider::TimeProvider for FixtureTime {
    fn current_time(&self) -> Option<UnixTime> {
        Some(time())
    }
}

struct Peer(Child);
impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn connect(port: u16, peer: &mut Peer) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = peer.0.try_wait().unwrap() {
            panic!("OpenSSL exited before accept: {status}");
        }
        match TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)) {
            Ok(socket) => return socket,
            Err(error) if Instant::now() >= deadline => panic!("OpenSSL did not listen: {error}"),
            Err(_) => std::thread::sleep(Duration::from_millis(10)),
        }
    }
}

#[test]
#[ignore = "requires independent fixture corpus and OpenSSL 3.5+ reference executable"]
fn tls13_mldsa_and_mixed_chains_interoperate_with_independent_openssl() {
    let openssl = std::env::var_os("AEROBOX_OPENSSL_REFERENCE")
        .expect("explicit reference executable required");
    for (parameters, directory) in cases() {
        let mut suites = vec![(0x1301, "TLS_AES_128_GCM_SHA256")];
        if parameters == 65 && directory.ends_with("ML-DSA-65-pq-chain") {
            suites.extend([
                (0x1302, "TLS_AES_256_GCM_SHA384"),
                (0x1303, "TLS_CHACHA20_POLY1305_SHA256"),
            ]);
        }
        for (suite, suite_name) in suites {
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
            let port = listener.local_addr().unwrap().port();
            drop(listener);
            let log =
                std::fs::File::create(directory.join(format!("openssl-{suite:04x}.log"))).unwrap();
            let mut peer = Peer(
                Command::new(&openssl)
                    .args([
                        "s_server",
                        "-quiet",
                        "-rev",
                        "-naccept",
                        "1",
                        "-accept",
                        &format!("127.0.0.1:{port}"),
                        "-tls1_3",
                        "-ciphersuites",
                        suite_name,
                        "-sigalgs",
                        &format!("mldsa{parameters}:ecdsa_secp256r1_sha256"),
                        "-alpn",
                        "h2",
                        "-num_tickets",
                        "0",
                        "-cert",
                        "leaf.pem",
                        "-cert_chain",
                        "intermediate.pem",
                        "-key",
                        "leaf-key.pem",
                    ])
                    .current_dir(&directory)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(log)
                    .spawn()
                    .unwrap(),
            );
            let mut socket = connect(port, &mut peer);
            socket
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut crypto = provider();
            crypto
                .cipher_suites
                .retain(|candidate| u16::from(candidate.suite()) == suite);
            let mut config = ClientConfig::builder_with_provider(Arc::new(crypto))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_root_certificates(roots(&directory))
                .with_no_client_auth();
            config.time_provider = Arc::new(FixtureTime);
            config.alpn_protocols = vec![b"h2".to_vec()];
            let mut connection = ClientConnection::new(
                Arc::new(config),
                ServerName::try_from("mldsa.aerobox.test").unwrap(),
            )
            .unwrap();
            while connection.is_handshaking() {
                connection.complete_io(&mut socket).unwrap_or_else(|error| {
                    panic!("{} {suite_name}: {error:?}", directory.display())
                });
            }
            assert_eq!(connection.alpn_protocol(), Some(b"h2".as_slice()));
            assert_eq!(
                u16::from(connection.negotiated_cipher_suite().unwrap().suite()),
                suite
            );
            let mut stream = rustls::Stream::new(&mut connection, &mut socket);
            let line: Vec<u8> = (0..1023)
                .map(|i| b'A' + (i % 26) as u8)
                .chain([b'\n'])
                .collect();
            let mut reversed = line[..1023].to_vec();
            reversed.reverse();
            reversed.push(b'\n');
            // Round trips keep pipe/socket buffers bounded and cross many TLS
            // record boundaries. Total application bytes are exactly 65,537.
            for _ in 0..64 {
                stream.write_all(&line).unwrap();
                stream.flush().unwrap();
                let mut response = vec![0; line.len()];
                stream.read_exact(&mut response).unwrap();
                assert_eq!(response, reversed);
            }
            stream.write_all(b"\n").unwrap();
            stream.flush().unwrap();
            let mut newline = [0];
            stream.read_exact(&mut newline).unwrap();
            assert_eq!(newline, [b'\n']);
            connection.send_close_notify();
            while connection.wants_write() {
                connection.write_tls(&mut socket).unwrap();
            }
            let mut closed = rustls::Stream::new(&mut connection, &mut socket);
            assert_eq!(closed.read(&mut newline).unwrap(), 0);
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if let Some(status) = peer.0.try_wait().unwrap() {
                    assert!(status.success());
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "OpenSSL did not exit after authenticated closure"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            let expected = match parameters {
                44 => SignatureScheme::ML_DSA_44,
                65 => SignatureScheme::ML_DSA_65,
                87 => SignatureScheme::ML_DSA_87,
                _ => unreachable!(),
            };
            assert!(
                provider()
                    .signature_verification_algorithms
                    .supported_schemes()
                    .contains(&expected)
            );
        }
    }
}
