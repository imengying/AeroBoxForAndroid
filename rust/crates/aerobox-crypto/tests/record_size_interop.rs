//! RFC8449 client record-size negotiation against an independent strict Go peer.

use rustls::{ClientConfig, ClientConnection, Error, NamedGroup, PeerMisbehaved, ProtocolVersion};
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

fn config(group: u16, retry: bool) -> ClientConfig {
    use rustls::crypto::SupportedKxGroup;
    let selected: &'static dyn SupportedKxGroup = match group {
        29 => aerobox_crypto::provider()
            .kx_groups
            .into_iter()
            .find(|g| g.name() == NamedGroup::X25519)
            .unwrap(),
        256 => &aerobox_crypto::ffdhe::FFDHE2048,
        257 => &aerobox_crypto::ffdhe::FFDHE3072,
        _ => panic!("invalid test group"),
    };
    let mut provider = aerobox_crypto::provider();
    provider
        .kx_groups
        .retain(|g| g.name() == NamedGroup::X25519);
    if group != 29 {
        provider.kx_groups.push(selected);
    }
    provider
        .cipher_suites
        .retain(|suite| u16::from(suite.suite()) == 0x1301);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(RSA_CERT.into()).unwrap();
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.initial_key_share_groups = vec![if retry {
        NamedGroup::X25519
    } else {
        selected.name()
    }];
    config.advertise_record_size_limit = true;
    config.alpn_protocols = vec![b"h2".to_vec()];
    config.resumption = rustls::client::Resumption::disabled();
    config.time_provider = Arc::new(FixtureTime);
    config.cert_compressors.clear();
    config.cert_decompressors.clear();
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
    group: u16,
    limit: u16,
    mode: &str,
    mutual: bool,
    key_update: bool,
    fragment: Option<usize>,
    padding: usize,
) {
    let retry = group != 29;
    eprintln!(
        "RSL group={group} limit={limit} mode={mode} mutual={mutual} update={key_update} fragment={fragment:?}"
    );
    let mut args = vec![
        format!("-group={group}"),
        "-expect-shares=29".into(),
        format!("-record-size-limit={limit}"),
        format!("-record-size-mode={mode}"),
        format!("-record-size-padding={padding}"),
    ];
    if mutual {
        args.push("-mutual".into());
    }
    if key_update {
        args.push("-record-size-key-update".into());
    }
    let (mut peer, mut output, ready) = start(&args);
    let mut config = config(group, retry);
    if mutual {
        set_mutual_auth(&mut config, &ready);
    }
    config.max_fragment_size = fragment;
    let mut conn =
        ClientConnection::new(Arc::new(config), "localhost".try_into().unwrap()).unwrap();
    let mut transport = socket(&ready);
    while conn.is_handshaking() {
        conn.complete_io(&mut transport).unwrap();
    }
    let mut stream = rustls::StreamOwned::new(conn, transport);
    let sent: Vec<u8> = (0..PAYLOAD).map(|i| ((i * 17 + 3) % 251) as u8).collect();
    if key_update {
        stream.write_all(&sent[..1024]).unwrap();
        stream.flush().unwrap();
        stream.conn.refresh_traffic_keys().unwrap();
        stream.write_all(&sent[1024..]).unwrap();
    } else {
        stream.write_all(&sent).unwrap();
    }
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
        Some(if retry {
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
    assert_eq!(result["hello_retry"], retry);
    assert_eq!(result["compressed"], false);
    assert_eq!(result["compression_algorithm"].as_u64().unwrap_or(0), 0);
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
    let stats = &result["record_size"];
    let negotiated = mode != "omit";
    assert_eq!(stats["offered"], 16385);
    assert_eq!(stats["selected"], limit);
    assert_eq!(stats["negotiated"], negotiated);
    let effective = if negotiated {
        usize::from(limit)
    } else {
        16385
    };
    let content_limit = effective - 1;
    let expected_max = fragment.map_or(content_limit, |size| (size - 5).min(content_limit)) + 1;
    assert_eq!(stats["max_application_inner"], expected_max);
    let handshake_max = stats["max_handshake_inner"].as_u64().unwrap() as usize;
    assert!(handshake_max > 0 && handshake_max <= effective);
    assert!(stats["handshake_records"].as_u64().unwrap() > 0);
    if mutual && limit == 64 && negotiated {
        assert!(stats["handshake_records"].as_u64().unwrap() > 10);
    }
    assert_eq!(stats["close_records"], 1);
    assert_eq!(stats["max_close_inner"], 3);
    assert_eq!(stats["server_padding"], padding);
    assert_eq!(stats["max_server_inner"], 16385);
    if key_update {
        assert_eq!(stats["client_key_updates"], 1);
        assert_eq!(stats["server_key_updates"], 2);
        assert_eq!(stats["max_after_key_update_inner"], expected_max);
    } else {
        assert_eq!(stats["client_key_updates"], 0);
        assert_eq!(stats["server_key_updates"], 0);
    }
    assert!(peer.0.wait().unwrap().success());
}

#[test]
#[ignore = "requires AEROBOX_TLS_PROFILE_PEER with the explicit record-size test overlay"]
fn record_size_limits_cover_handshake_mtls_application_hrr_and_both_key_update_directions() {
    for group in [29, 256] {
        for limit in [64, 512, 16385] {
            for mutual in [false, true] {
                exercise(group, limit, "normal", mutual, true, None, 17);
            }
        }
    }
    // The user's local cap can be smaller than the peer's negotiated limit.
    exercise(29, 64, "normal", true, true, Some(37), 0);
    exercise(257, 64, "normal", true, true, None, 1024);
    exercise(29, 64, "normal", false, false, None, 0);
    // A server that ignores the offer must not silently force the peer cap.
    exercise(29, 64, "omit", true, true, None, 0);
    exercise(256, 64, "omit", false, false, None, 0);
}

#[derive(Clone, Copy, Debug)]
enum Failure {
    Value,
    DuplicateOrLength,
    ServerHello,
    Retry,
    Unsolicited,
    Oversized,
}

fn reject(limit: u16, mode: &str, expected: Failure) {
    let group = if mode == "hrr" { 256 } else { 29 };
    let args = vec![
        format!("-group={group}"),
        "-expect-shares=29".into(),
        format!("-record-size-limit={limit}"),
        format!("-record-size-mode={mode}"),
    ];
    let (_peer, _output, ready) = start(&args);
    let mut config = config(group, group != 29);
    if matches!(expected, Failure::Unsolicited) {
        config.advertise_record_size_limit = false;
    }
    let mut client =
        ClientConnection::new(Arc::new(config), "localhost".try_into().unwrap()).unwrap();
    let mut socket = socket(&ready);
    let mut failure = None;
    for _ in 0..64 {
        while client.wants_write() {
            assert!(client.write_tls(&mut socket).unwrap() > 0);
        }
        assert!(
            client.read_tls(&mut socket).unwrap() > 0,
            "peer closed before client rejected {mode}"
        );
        match client.process_new_packets() {
            Ok(_) => {
                if !matches!(expected, Failure::Oversized) {
                    assert!(client.is_handshaking(), "accepted invalid negotiation");
                }
            }
            Err(error) => {
                failure = Some(error);
                break;
            }
        }
    }
    let failure = failure.expect("bounded reference did not reach rejection");
    let correct = match expected {
        Failure::Value => {
            matches!(&failure,Error::General(message) if message=="invalid peer record_size_limit")
        }
        Failure::DuplicateOrLength => matches!(failure, Error::InvalidMessage(_)),
        Failure::ServerHello => matches!(
            failure,
            Error::PeerMisbehaved(PeerMisbehaved::UnexpectedCleartextExtension)
        ),
        Failure::Retry => matches!(
            failure,
            Error::InvalidMessage(rustls::InvalidMessage::UnknownHelloRetryRequestExtension)
        ),
        Failure::Unsolicited => matches!(
            failure,
            Error::PeerMisbehaved(PeerMisbehaved::UnsolicitedEncryptedExtension)
        ),
        Failure::Oversized => matches!(failure, Error::PeerSentOversizedRecord),
    };
    assert!(
        correct,
        "mode={mode} limit={limit}: wrong failure {failure:?}"
    );
    assert_eq!(client.process_new_packets().unwrap_err(), failure);
    assert!(
        client
            .writer()
            .write(b"no write after invalid limit or overflow")
            .is_err()
    );
    assert!(
        client
            .export_keying_material([0u8; 32], EXPORTER_LABEL, Some(EXPORTER_CONTEXT))
            .is_err()
    );
}

#[test]
#[ignore = "requires AEROBOX_TLS_PROFILE_PEER with the explicit record-size test overlay"]
fn record_size_limits_reject_invalid_negotiation_and_authenticated_inner_overflow() {
    for limit in [0, 1, 63, 16386, u16::MAX] {
        reject(limit, "normal", Failure::Value);
    }
    for mode in ["duplicate", "malformed"] {
        reject(64, mode, Failure::DuplicateOrLength);
    }
    reject(64, "serverhello", Failure::ServerHello);
    reject(64, "hrr", Failure::Retry);
    reject(64, "unsolicited", Failure::Unsolicited);
    for mode in ["oversize-content", "oversize-padding"] {
        reject(64, mode, Failure::Oversized);
    }
}

#[test]
fn record_size_setting_remains_explicit_and_rejects_incompatible_early_data_or_extraction() {
    let roots = rustls::RootCertStore::empty();
    let ordinary = ClientConfig::builder_with_provider(Arc::new(aerobox_crypto::provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    assert!(!ordinary.advertise_record_size_limit);
    for extraction in [false, true] {
        let mut options = config(29, false);
        options.enable_secret_extraction = extraction;
        options.enable_early_data = !extraction;
        assert!(ClientConnection::new(Arc::new(options), "localhost".try_into().unwrap()).is_err());
    }
}
