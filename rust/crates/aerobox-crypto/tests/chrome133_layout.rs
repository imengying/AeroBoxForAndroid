use rustls::{
    ClientConfig, ClientConnection, RootCertStore,
    client::{ApplicationSettings, ApplicationSettingsCodepoint as Codepoint},
    pki_types::UnixTime,
    time_provider::TimeProvider,
};

// Use the production hybrid primitive, with independent keys retained by rustls.
#[path = "../../../vendor/shoes/src/crypto/rustcrypto_kx.rs"]
mod production_hybrid;
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
    process::{Child, Command, Stdio},
    sync::Arc,
    time::Duration,
};

#[derive(Debug)]
struct FixtureTime;
impl TimeProvider for FixtureTime {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(Duration::from_secs(1893456000)))
    }
}
struct Peer(Child);
impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn peer(args: &[String]) -> (Peer, TcpStream) {
    let program = std::env::var_os("AEROBOX_TLS_PROFILE_PEER").expect("AEROBOX_TLS_PROFILE_PEER");
    let mut child = Command::new(program)
        .args(args)
        .args([
            "-fixtures",
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures"),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let ready: serde_json::Value = serde_json::from_str(&line).unwrap();
    let socket = TcpStream::connect(("127.0.0.1", ready["port"].as_u64().unwrap() as u16)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    (Peer(child), socket)
}
fn config(codepoint: Option<Codepoint>, local: Vec<u8>) -> ClientConfig {
    assert_eq!(codepoint, Some(Codepoint::Chrome));
    let mut roots = RootCertStore::empty();
    roots
        .add(include_bytes!("fixtures/rsa-cert.der").as_slice().into())
        .unwrap();
    let mut provider = aerobox_crypto::provider();
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
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.time_provider = Arc::new(FixtureTime);
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config.application_settings =
        Some(ApplicationSettings::new(Codepoint::Chrome, vec![(b"h2".to_vec(), local)]).unwrap());
    config.initial_key_share_groups = vec![
        rustls::NamedGroup::X25519MLKEM768,
        rustls::NamedGroup::X25519,
    ];
    config.client_hello_layout = Some(rustls::client::ClientHelloLayout::Chrome133);
    config
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn exercise(
    codepoint: Option<Codepoint>,
    args: Vec<String>,
    local: Vec<u8>,
    remote: Option<&[u8]>,
    reject: bool,
) {
    let (_peer, mut socket) = peer(&args);
    let mut cfg = config(codepoint, local);
    if args.iter().any(|arg| arg == "-mutual") {
        let certified = rustls::sign::CertifiedKey::from_der(
            vec![include_bytes!("fixtures/rsa-cert.der").as_slice().into()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(
                include_bytes!("fixtures/rsa-key.der").to_vec(),
            )
            .into(),
            &aerobox_crypto::provider(),
        )
        .unwrap();
        cfg.client_auth_cert_resolver = Arc::new(rustls::sign::SingleCertAndKey::from(certified));
    }
    let mut client = ClientConnection::new(Arc::new(cfg), "localhost".try_into().unwrap()).unwrap();
    assert_eq!(client.peer_application_settings(), None);
    let mut failure = None;
    while client.is_handshaking() {
        while client.wants_write() {
            client.write_tls(&mut socket).unwrap();
        }
        // Exercise fragmented input and ensure settings stay private until Finished.
        let n = client.read_tls(&mut (&mut socket).take(128)).unwrap();
        assert!(n > 0, "peer closed during handshake");
        if let Err(error) = client.process_new_packets() {
            failure = Some(error);
            break;
        }
        if client.is_handshaking() {
            assert_eq!(client.peer_application_settings(), None);
        }
    }
    if reject {
        let failure = failure.expect("malformed handshake accepted");
        assert_eq!(client.peer_application_settings(), None);
        assert_eq!(client.process_new_packets().unwrap_err(), failure);
        assert!(client.reader().read(&mut [0u8; 1]).is_err());
        return;
    }
    assert!(failure.is_none(), "handshake error: {failure:?}");
    assert_eq!(client.peer_application_settings(), remote);
    assert_eq!(client.alpn_protocol(), Some(b"h2".as_slice()));
    let mut stream = rustls::StreamOwned::new(client, socket);
    for len in [1, 16384, 65537] {
        let sent: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        stream.write_all(&sent).unwrap();
        stream.flush().unwrap();
        let mut received = vec![0; len];
        stream.read_exact(&mut received).unwrap();
        assert_eq!(received, sent);
    }
    stream.conn.send_close_notify();
    stream.flush().unwrap();
    assert_eq!(stream.read(&mut [0; 1]).unwrap(), 0);
}

#[test]
#[ignore = "requires independently built AEROBOX_TLS_PROFILE_PEER"]
fn chrome_layout_tickets_and_early_data_interoperate() {
    for codepoint in [Codepoint::Chrome] {
        let id = if codepoint == Codepoint::Legacy {
            17513
        } else {
            17613
        };
        for mode in ["accept", "reject", "changed", "server_changed"] {
            let remote = b"authenticated cached settings";
            let (_peer, socket) = peer(&[
                format!("-alps={id}"),
                format!(
                    "-early={}",
                    if mode == "reject" { "reject" } else { "accept" }
                ),
                "-server-settings".into(),
                hex(remote),
                "-any-client-settings".into(),
                format!("-rotate-server-settings={}", mode == "server_changed"),
            ]);
            let address = socket.peer_addr().unwrap();
            let mut first_socket = Some(socket);
            let mut cfg = config(Some(codepoint), b"first settings".to_vec());
            cfg.enable_early_data = true;
            let mut expected_remote = remote.to_vec();
            for iteration in 0..3 {
                if mode == "changed" && iteration == 1 {
                    cfg.application_settings = Some(
                        ApplicationSettings::new(
                            codepoint,
                            vec![(b"h2".to_vec(), b"changed settings".to_vec())],
                        )
                        .unwrap(),
                    );
                }
                let mut socket = first_socket.take().unwrap_or_else(|| {
                    let socket = TcpStream::connect(address).unwrap();
                    socket
                        .set_read_timeout(Some(Duration::from_secs(15)))
                        .unwrap();
                    socket
                        .set_write_timeout(Some(Duration::from_secs(15)))
                        .unwrap();
                    socket
                });
                let mut client =
                    ClientConnection::new(Arc::new(cfg.clone()), "localhost".try_into().unwrap())
                        .unwrap();
                let should_offer = iteration > 0 && !(mode == "changed" && iteration == 1);
                let payload = b"early data is delivered once";
                let offered = if let Some(mut early) = client.early_data() {
                    early.write_all(payload).unwrap();
                    true
                } else {
                    false
                };
                assert_eq!(offered, should_offer, "{codepoint:?}/{mode}/{iteration}");
                assert_eq!(
                    client.peer_application_settings(),
                    if should_offer {
                        Some(expected_remote.as_slice())
                    } else {
                        None
                    }
                );
                while client.is_handshaking() {
                    client.complete_io(&mut socket).unwrap();
                }
                assert_eq!(
                    client.handshake_kind(),
                    Some(if iteration > 0 {
                        rustls::HandshakeKind::Resumed
                    } else {
                        rustls::HandshakeKind::Full
                    })
                );
                if mode == "server_changed" && iteration > 0 {
                    expected_remote.extend_from_slice(b" next");
                }
                assert_eq!(
                    client.peer_application_settings(),
                    Some(expected_remote.as_slice())
                );
                let accepted = client.is_early_data_accepted();
                assert_eq!(
                    accepted,
                    should_offer && mode != "reject" && mode != "server_changed"
                );
                let mut stream = rustls::StreamOwned::new(client, socket);
                if !accepted {
                    stream.write_all(payload).unwrap();
                }
                stream.flush().unwrap();
                let mut got = vec![0; payload.len()];
                stream.read_exact(&mut got).unwrap();
                assert_eq!(got, payload);
                assert!(stream.conn.tls13_tickets_received() > 0);
                stream.conn.send_close_notify();
                stream.flush().unwrap();
                assert_eq!(stream.read(&mut [0; 1]).unwrap(), 0);
            }
        }
    }
}

#[test]
#[ignore = "requires independently built AEROBOX_TLS_PROFILE_PEER"]
fn reality_ed25519_exception_never_applies_to_ordinary_browser_tls() {
    for browser in [false, true] {
        let (_peer, mut socket) = peer(&["-unadvertised-signature".into()]);
        let mut cfg = config(Some(Codepoint::Chrome), vec![]);
        if !browser {
            cfg.client_hello_layout = None;
        }
        let mut client =
            ClientConnection::new(Arc::new(cfg), "localhost".try_into().unwrap()).unwrap();
        let mut failure = None;
        while client.is_handshaking() {
            while client.wants_write() {
                client.write_tls(&mut socket).unwrap();
            }
            assert!(client.read_tls(&mut socket).unwrap() > 0);
            if let Err(error) = client.process_new_packets() {
                failure = Some(error);
                break;
            }
        }
        if browser {
            assert_eq!(
                failure,
                Some(rustls::Error::PeerMisbehaved(
                    rustls::PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme
                ))
            );
            assert!(client.peer_application_settings().is_none());
        } else {
            assert!(
                failure.is_none(),
                "the same CA-authenticated Ed25519 peer must succeed when advertised: {failure:?}"
            );
            let mut stream = rustls::Stream::new(&mut client, &mut socket);
            stream.write_all(b"verified").unwrap();
            stream.flush().unwrap();
            let mut reply = [0; 8];
            stream.read_exact(&mut reply).unwrap();
            assert_eq!(&reply, b"verified");
        }
    }
}

#[test]
#[ignore = "requires independently built AEROBOX_TLS_PROFILE_PEER"]
fn chrome_layout_tls13_groups_brotli_alps_authentication() {
    for group in [29, 23, 24, 4588] {
        for brotli in [false, true] {
            for alps in [0, 17613] {
                exercise(
                    Some(Codepoint::Chrome),
                    vec![
                        format!("-group={group}"),
                        format!("-brotli={brotli}"),
                        format!("-alps={alps}"),
                    ],
                    vec![],
                    if alps == 0 { None } else { Some(&[]) },
                    false,
                );
            }
        }
    }
    for option in ["-mutual", "-cookie-retry"] {
        exercise(
            Some(Codepoint::Chrome),
            vec![option.into()],
            vec![],
            Some(&[]),
            false,
        );
    }
    for option in [
        "-bad-finished",
        "-bad-certificate-length",
        "-force-retry",
        "-unadvertised-group",
    ] {
        exercise(
            Some(Codepoint::Chrome),
            vec![option.into()],
            vec![],
            None,
            true,
        );
    }
}

fn take<'a>(input: &mut &'a [u8], length: usize) -> &'a [u8] {
    let (head, tail) = input.split_at(length);
    *input = tail;
    head
}
fn vector<'a>(input: &mut &'a [u8], width: usize) -> &'a [u8] {
    let length = take(input, width)
        .iter()
        .fold(0, |n, b| (n << 8) + usize::from(*b));
    take(input, length)
}
fn u16s(bytes: &[u8]) -> Vec<u16> {
    assert_eq!(bytes.len() % 2, 0);
    bytes
        .chunks_exact(2)
        .map(|b| u16::from_be_bytes([b[0], b[1]]))
        .collect()
}
fn grease(n: u16) -> bool {
    n & 0x0f0f == 0x0a0a && n >> 8 == n & 255
}
fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn chrome_layout_matches_pinned_utls_capture_structure() {
    let captures: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/utls-reference/captures.json")).unwrap();
    let reference = captures
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["profile"] == "Chrome-133" && x["case"] == "default")
        .unwrap();
    let expected_ciphers: Vec<_> = reference["wire"]["ciphers"]
        .as_array()
        .unwrap()
        .iter()
        .skip(1)
        .map(|v| u16::from_str_radix(v.as_str().unwrap(), 16).unwrap())
        .collect();
    let mut orders = std::collections::BTreeSet::new();
    let mut randoms = std::collections::BTreeSet::new();
    let mut session_ids = std::collections::BTreeSet::new();
    for _ in 0..16 {
        let mut client = ClientConnection::new(
            Arc::new(config(Some(Codepoint::Chrome), vec![])),
            "android11.example".try_into().unwrap(),
        )
        .unwrap();
        let mut wire = vec![];
        client.write_tls(&mut wire).unwrap();
        let mut record = wire.as_slice();
        assert_eq!(take(&mut record, 3), [22, 3, 1]);
        let mut message = vector(&mut record, 2);
        assert!(record.is_empty());
        assert_eq!(take(&mut message, 1), [1]);
        let mut hello = vector(&mut message, 3);
        assert!(message.is_empty());
        assert_eq!(take(&mut hello, 2), [3, 3]);
        assert!(randoms.insert(take(&mut hello, 32).to_vec()));
        let session = vector(&mut hello, 1);
        assert_eq!(session.len(), 32);
        assert!(session_ids.insert(session.to_vec()));
        let ciphers = u16s(vector(&mut hello, 2));
        assert!(grease(ciphers[0]));
        assert_eq!(&ciphers[1..], &expected_ciphers);
        assert_eq!(vector(&mut hello, 1), [0]);
        let mut extensions = vector(&mut hello, 2);
        assert!(hello.is_empty());
        let mut parsed = std::collections::BTreeMap::new();
        let mut order = vec![];
        while !extensions.is_empty() {
            let id = u16s(take(&mut extensions, 2))[0];
            let body = vector(&mut extensions, 2);
            assert!(parsed.insert(id, body).is_none());
            order.push(id);
        }
        assert_eq!(order.len(), 18);
        assert!(grease(order[0]));
        assert!(grease(order[17]));
        assert_ne!(order[0], order[17]);
        assert!(parsed[&order[0]].is_empty());
        assert_eq!(parsed[&order[17]], [0]);
        let middle = &order[1..17];
        orders.insert(middle.to_vec());
        let mut expected: Vec<u16> = reference["wire"]["extensions"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|x| {
                let n = x["id"].as_u64().unwrap() as u16;
                (!grease(n)).then_some(n)
            })
            .collect();
        expected.sort();
        let mut actual = middle.to_vec();
        actual.sort();
        assert_eq!(actual, expected);
        for id in [0, 23, 65281, 11, 35, 16, 5, 13, 18, 45, 27, 17613] {
            let ext = reference["wire"]["extensions"]
                .as_array()
                .unwrap()
                .iter()
                .find(|x| x["id"] == id)
                .unwrap();
            assert_eq!(
                parsed[&(id as u16)],
                unhex(ext["hex"].as_str().unwrap()),
                "extension {id}"
            );
        }
        let groups = u16s(&parsed[&10][2..]);
        assert!(grease(groups[0]));
        assert_eq!(&groups[1..], [4588, 29, 23, 24]);
        let versions = u16s(&parsed[&43][1..]);
        assert!(grease(versions[0]));
        assert_eq!(&versions[1..], [772, 771]);
        let mut shares = &parsed[&51][2..];
        let mut keys = vec![];
        while !shares.is_empty() {
            let group = u16s(take(&mut shares, 2))[0];
            keys.push((group, vector(&mut shares, 2)));
        }
        assert_eq!(keys.len(), 3);
        assert_eq!(keys[0], (groups[0], &[0][..]));
        assert_eq!((keys[1].0, keys[1].1.len()), (4588, 1216));
        assert_eq!((keys[2].0, keys[2].1.len()), (29, 32));
        assert_ne!(&keys[1].1[1184..], keys[2].1);
        let mut ech = parsed[&65037];
        assert_eq!(take(&mut ech, 5), [0, 0, 1, 0, 1]);
        take(&mut ech, 1);
        let enc = vector(&mut ech, 2);
        assert_eq!(enc.len(), 32);
        assert_eq!(enc[31] & 128, 0);
        assert!([144, 176, 208, 240].contains(&vector(&mut ech, 2).len()));
        assert!(ech.is_empty());
    }
    assert!(
        orders.len() > 1,
        "extension permutation must vary between connections"
    );
}

#[test]
fn chrome_layout_rejects_incomplete_capabilities() {
    let valid = config(Some(Codepoint::Chrome), vec![]);
    for index in 0..5 {
        let mut cfg = valid.clone();
        match index {
            0 => cfg.initial_key_share_groups.clear(),
            1 => cfg.application_settings = None,
            2 => cfg.cert_decompressors.clear(),
            3 => cfg.alpn_protocols.clear(),
            _ => cfg.initial_key_share_groups.reverse(),
        }
        assert!(ClientConnection::new(Arc::new(cfg), "localhost".try_into().unwrap()).is_err());
    }
}

#[test]
#[ignore = "requires independently built AEROBOX_TLS_PROFILE_PEER with SCT cases"]
fn chrome_layout_sct_framing_is_bounded_and_authenticated() {
    for mode in ["valid", "empty", "empty-entry", "trailing"] {
        for compressed in [false, true] {
            exercise(
                Some(Codepoint::Chrome),
                vec![format!("-sct={mode}"), format!("-brotli={compressed}")],
                vec![],
                if mode == "valid" { Some(&[]) } else { None },
                mode != "valid",
            );
        }
    }
}
