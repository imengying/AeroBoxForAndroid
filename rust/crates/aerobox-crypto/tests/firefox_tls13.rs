//! Complete Firefox120 TLS1.3 exchanges against independent Go primitives.
#[path = "support/firefox.rs"]
mod firefox;

use rustls::{
    CertificateError, ClientConfig, ClientConnection, Error, PeerMisbehaved, ProtocolVersion,
    client::ClientHelloLayout,
};
use sha2::{Digest, Sha256};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
    process::{Child, ChildStdout, Command, Stdio},
    sync::Arc,
    time::Duration,
};

const PAYLOAD: usize = 65537;
const RSA_CERT: &[u8] = include_bytes!("fixtures/rsa-cert.der");
const RSA_KEY: &[u8] = include_bytes!("fixtures/rsa-key.der");
const WRONG_ROOT: &[u8] = include_bytes!("fixtures/p521-ca.der");
const EXPORTER_LABEL: &[u8] = b"aerobox android browser tls13 exporter";
const EXPORTER_CONTEXT: &[u8] = b"\0android\0tls13\0";

#[derive(Debug)]
struct FixtureTime;
impl rustls::time_provider::TimeProvider for FixtureTime {
    fn current_time(&self) -> Option<rustls::pki_types::UnixTime> {
        Some(rustls::pki_types::UnixTime::since_unix_epoch(
            Duration::from_secs(1893456000),
        ))
    }
}

struct Peer(Child);
impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn read_report(output: &mut BufReader<ChildStdout>) -> serde_json::Value {
    let mut line = String::new();
    output.by_ref().take(65537).read_line(&mut line).unwrap();
    assert!(!line.is_empty() && line.len() <= 65536 && line.ends_with('\n'));
    serde_json::from_str(&line).unwrap()
}

fn start(args: &[String]) -> (Peer, BufReader<ChildStdout>, serde_json::Value) {
    let mut peer = Peer(
        Command::new(std::env::var_os("AEROBOX_TLS_PROFILE_PEER").expect("independent Go peer"))
            .args([
                "-android-browser-exchange",
                "-alps=0",
                "-brotli=false",
                "-expect-shares=29,23",
                "-fixtures",
                concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures"),
            ])
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let mut output = BufReader::new(peer.0.stdout.take().unwrap());
    let ready = read_report(&mut output);
    assert_eq!(ready["phase"], "ready", "{ready}");
    (peer, output, ready)
}

fn socket(ready: &serde_json::Value) -> TcpStream {
    let port = u16::try_from(ready["port"].as_u64().unwrap()).unwrap();
    let socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    socket
}

fn decode(text: &str) -> Vec<u8> {
    assert!(!text.is_empty() && text.len() <= 65536 && text.len() % 2 == 0);
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn config(profile: ClientHelloLayout, tls13_only: bool) -> ClientConfig {
    assert_eq!(profile, ClientHelloLayout::Firefox120);
    let mut config = firefox::config(false, tls13_only);
    config.time_provider = Arc::new(FixtureTime);
    config
}

fn set_mutual_auth(config: &mut ClientConfig, ready: &serde_json::Value) {
    // The disposable clientAuth certificate uses the existing fixture key.
    // Go validates its purpose/time/signature then pins its exact DER and proof.
    let certificate = decode(ready["client_certificate_der_hex"].as_str().unwrap());
    let key = rustls::sign::CertifiedKey::from_der(
        vec![certificate.into()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(RSA_KEY.to_vec()).into(),
        &aerobox_crypto::provider(),
    )
    .unwrap();
    config.client_auth_cert_resolver = Arc::new(rustls::sign::SingleCertAndKey::from(key));
    config.max_fragment_size = Some(512);
}

fn exercise(
    profile: ClientHelloLayout,
    tls13_only: bool,
    group: u16,
    compressed: bool,
    mutual: bool,
    cookie: bool,
) {
    eprintln!(
        "Android {profile:?} TLS13-only={tls13_only} group={group} zlib={compressed} mutual={mutual} cookie={cookie}"
    );
    let mut args = vec![format!("-group={group}")];
    if compressed {
        args.push("-zlib".into());
    }
    if mutual {
        args.push("-mutual".into());
    }
    if cookie {
        args.push("-cookie-retry".into());
    }
    let (mut peer, mut output, ready) = start(&args);
    let mut config = config(profile, tls13_only);
    if mutual {
        set_mutual_auth(&mut config, &ready);
    }
    let conn = ClientConnection::new(Arc::new(config), "localhost".try_into().unwrap()).unwrap();
    let mut stream = rustls::StreamOwned::new(conn, socket(&ready));
    let sent: Vec<u8> = (0..PAYLOAD).map(|i| ((i * 17 + 3) % 251) as u8).collect();
    stream.write_all(&sent).unwrap();
    stream.flush().unwrap();
    let mut response = vec![0; 36 + PAYLOAD];
    stream.read_exact(&mut response).unwrap();
    assert_eq!(&response[..4], b"AB13");
    assert_eq!(
        stream.conn.protocol_version(),
        Some(ProtocolVersion::TLSv1_3)
    );
    assert_eq!(
        u16::from(stream.conn.negotiated_cipher_suite().unwrap().suite()),
        0x1301
    );
    assert_eq!(
        u16::from(stream.conn.negotiated_key_exchange_group().unwrap().name()),
        group
    );
    assert_eq!(
        stream.conn.handshake_kind(),
        Some(if ![29, 23].contains(&group) || cookie {
            rustls::HandshakeKind::FullWithHelloRetryRequest
        } else {
            rustls::HandshakeKind::Full
        })
    );
    assert_eq!(stream.conn.alpn_protocol(), Some(b"h2".as_slice()));
    assert_eq!(stream.conn.peer_application_settings(), None);
    assert_eq!(
        stream.conn.peer_certificates().unwrap()[0].as_ref(),
        RSA_CERT
    );
    let exporter = stream
        .conn
        .export_keying_material(vec![0; 32], EXPORTER_LABEL, Some(EXPORTER_CONTEXT))
        .unwrap();
    assert_eq!(&response[4..36], exporter.as_slice());
    for (i, byte) in response[36..].iter().enumerate() {
        assert_eq!(*byte, ((i * 29 + 7) % 251) as u8, "payload byte {i}");
    }
    stream.conn.send_close_notify();
    stream.flush().unwrap();
    assert_eq!(stream.read(&mut [0; 1]).unwrap(), 0);
    assert!(stream.conn.process_new_packets().unwrap().peer_has_closed());
    let report = read_report(&mut output);
    assert_eq!(report["phase"], "complete", "{report}");
    let result = &report["result"];
    assert_eq!(result["group"], group);
    assert_eq!(result["hello_retry"], ![29, 23].contains(&group) || cookie);
    assert_eq!(result["compressed"], compressed);
    assert_eq!(
        result["compression_algorithm"].as_u64().unwrap_or(0),
        if compressed { 1 } else { 0 }
    );
    assert_eq!(
        result["client_verified_chain"].as_bool().unwrap_or(false),
        mutual
    );
    assert_eq!(result["bytes"], PAYLOAD);
    assert_eq!(result["exporter"], hex(&exporter));
    assert_eq!(result["client_sha256"], hex(&Sha256::digest(&sent)));
    assert_eq!(
        result["server_sha256"],
        hex(&Sha256::digest(&response[36..]))
    );
    assert_eq!(result["close_notify"], true);
    assert_eq!(result["resumed"], false);
    assert_eq!(result["alps"], 0);
    assert!(peer.0.wait().unwrap().success());
}

#[test]
#[ignore = "requires extended AEROBOX_TLS_PROFILE_PEER"]
fn firefox_authenticates_both_initial_shares_all_hrr_groups_mtls_and_duplex_data() {
    for tls13_only in [false, true] {
        for group in [29, 23, 24, 25, 256, 257] {
            for mutual in [false, true] {
                exercise(
                    ClientHelloLayout::Firefox120,
                    tls13_only,
                    group,
                    false,
                    mutual,
                    false,
                );
            }
        }
        exercise(
            ClientHelloLayout::Firefox120,
            tls13_only,
            29,
            false,
            true,
            true,
        );
        exercise(
            ClientHelloLayout::Firefox120,
            tls13_only,
            23,
            false,
            true,
            true,
        );
    }
}

#[derive(Clone, Copy, Debug)]
enum Failure {
    UnofferedCompression,
    Finished,
    Signature,
    WrongName,
    WrongRoot,
}

fn reject(profile: ClientHelloLayout, tls13_only: bool, args: &[&str], expected: Failure) {
    eprintln!("Android {profile:?} TLS13-only={tls13_only} rejects {expected:?}: {args:?}");
    let args: Vec<String> = args.iter().map(|value| (*value).to_owned()).collect();
    let (_peer, _output, ready) = start(&args);
    let mut config = config(profile, tls13_only);
    if matches!(expected, Failure::WrongRoot) {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(WRONG_ROOT.into()).unwrap();
        let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(aerobox_crypto::firefox::provider()),
        )
        .build()
        .unwrap();
        config.dangerous().set_certificate_verifier(Arc::new(
            aerobox_crypto::delegated_credentials::Verifier::new(verifier),
        ));
    }
    let name = if matches!(expected, Failure::WrongName) {
        "unrelated.test"
    } else {
        "localhost"
    };
    let mut client = ClientConnection::new(Arc::new(config), name.try_into().unwrap()).unwrap();
    let mut socket = socket(&ready);
    let failure = loop {
        while client.wants_write() {
            client.write_tls(&mut socket).unwrap();
        }
        assert!(
            client.is_handshaking(),
            "rejected handshake unexpectedly completed"
        );
        assert!(client.read_tls(&mut (&mut socket).take(137)).unwrap() > 0);
        match client.process_new_packets() {
            Ok(_) => assert_eq!(client.peer_application_settings(), None),
            Err(error) => break error,
        }
    };
    let correct = match expected {
        Failure::UnofferedCompression => matches!(
            failure,
            Error::PeerMisbehaved(PeerMisbehaved::SelectedUnofferedCertCompression)
                | Error::InappropriateHandshakeMessage {
                    got_type: rustls::HandshakeType::CompressedCertificate,
                    ..
                }
        ),
        Failure::Finished => matches!(failure, Error::DecryptError),
        Failure::Signature => matches!(
            &failure,
            Error::General(message)
                if message == "legacy CertificateVerify is not permitted by delegated credential opt-in"
        ),
        Failure::WrongName => matches!(
            failure,
            Error::InvalidCertificate(
                CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. }
            )
        ),
        Failure::WrongRoot => matches!(
            failure,
            Error::InvalidCertificate(CertificateError::UnknownIssuer)
        ),
    };
    assert!(correct, "expected {expected:?}, got {failure:?}");
    assert_eq!(client.process_new_packets().unwrap_err(), failure);
    assert!(client.reader().read(&mut [0; 1]).is_err());
    assert!(
        client
            .export_keying_material(vec![0; 32], EXPORTER_LABEL, Some(EXPORTER_CONTEXT))
            .is_err()
    );
}

#[test]
#[ignore = "requires extended AEROBOX_TLS_PROFILE_PEER"]
fn firefox_rejects_unoffered_compression_bad_finished_tls13_sha1_and_wrong_identity() {
    for tls13_only in [false, true] {
        let profile = ClientHelloLayout::Firefox120;
        for compression in ["-zlib", "-brotli=true"] {
            reject(
                profile,
                tls13_only,
                &[compression, "-skip-compression-check"],
                Failure::UnofferedCompression,
            );
        }
        reject(
            profile,
            tls13_only,
            &["-bad-finished", "-group=257"],
            Failure::Finished,
        );
        for scheme in [
            "-sha1-certificate-verify=rsa",
            "-sha1-certificate-verify=ecdsa",
        ] {
            reject(profile, tls13_only, &[scheme], Failure::Signature);
        }
        reject(profile, tls13_only, &[], Failure::WrongName);
        reject(profile, tls13_only, &[], Failure::WrongRoot);
    }
}
