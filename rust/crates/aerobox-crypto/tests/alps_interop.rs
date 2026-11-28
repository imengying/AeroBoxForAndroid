use rustls::{
    ClientConfig, ClientConnection, RootCertStore,
    client::{ApplicationSettings, ApplicationSettingsCodepoint as Codepoint},
    pki_types::UnixTime,
    time_provider::TimeProvider,
};

#[path = "support/edge_qq.rs"]
mod edge_qq;

#[test]
#[ignore = "requires independently built AEROBOX_TLS_PROFILE_PEER"]
fn edge_qq_tls13_authentication_brotli_alps_and_hello_retry() {
    use rustls::client::ClientHelloLayout;
    for profile in [ClientHelloLayout::Edge85, ClientHelloLayout::Qq11_1] {
        let alps = if profile == ClientHelloLayout::Qq11_1 {
            17513
        } else {
            0
        };
        for group in [29, 23, 24] {
            for compressed in [false, true] {
                exercise_with_config(
                    edge_qq::config(profile, false),
                    vec![
                        format!("-alps={alps}"),
                        format!("-group={group}"),
                        format!("-brotli={compressed}"),
                    ],
                    (alps != 0).then_some(b"".as_slice()),
                    false,
                );
            }
        }
        exercise_with_config(
            edge_qq::config(profile, true),
            vec![
                format!("-alps={alps}"),
                "-mutual".into(),
                "-group=24".into(),
            ],
            (alps != 0).then_some(b"".as_slice()),
            false,
        );
        // Vision retains the exact cover layout while enforcing TLS1.3.
        exercise_with_config(
            edge_qq::with_version_policy(profile, true, true),
            vec![
                format!("-alps={alps}"),
                "-mutual".into(),
                "-group=29".into(),
            ],
            (alps != 0).then_some(b"".as_slice()),
            false,
        );
        exercise_with_config(
            edge_qq::config(profile, false),
            vec![
                format!("-alps={alps}"),
                "-cookie-retry".into(),
                "-group=29".into(),
            ],
            (alps != 0).then_some(b"".as_slice()),
            false,
        );
        for fault in [
            "-bad-finished",
            "-bad-certificate-length",
            "-trailing-compressed-data",
        ] {
            exercise_with_config(
                edge_qq::config(profile, false),
                vec![format!("-alps={alps}"), fault.into()],
                None,
                true,
            );
        }
    }
    for fault in ["-both-alps", "-omit-alpn", "-selected-alpn=http/1.1"] {
        exercise_with_config(
            edge_qq::config(ClientHelloLayout::Qq11_1, false),
            vec!["-alps=17513".into(), fault.into()],
            None,
            true,
        );
    }
}

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
    let mut roots = RootCertStore::empty();
    roots
        .add(include_bytes!("fixtures/rsa-cert.der").as_slice().into())
        .unwrap();
    let mut config = ClientConfig::builder_with_provider(Arc::new(aerobox_crypto::provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.time_provider = Arc::new(FixtureTime);
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config.application_settings = codepoint.map(|codepoint| {
        ApplicationSettings::new(codepoint, vec![(b"h2".to_vec(), local)]).unwrap()
    });
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
    exercise_with_config(config(codepoint, local), args, remote, reject)
}

fn exercise_with_config(
    mut cfg: ClientConfig,
    args: Vec<String>,
    remote: Option<&[u8]>,
    reject: bool,
) {
    let (_peer, mut socket) = peer(&args);
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
    assert_eq!(
        client.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
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
fn alps_both_codepoints_brotli_and_hello_retry_interoperate() {
    let local = b"client chosen before handshake";
    let remote = b"independent server settings";
    for (codepoint, id) in [(Codepoint::Legacy, 17513), (Codepoint::Chrome, 17613)] {
        for group in [29, 23, 24] {
            for compressed in [false, true] {
                exercise(
                    Some(codepoint),
                    vec![
                        "-alps".into(),
                        id.to_string(),
                        "-group".into(),
                        group.to_string(),
                        format!("-brotli={compressed}"),
                        "-server-settings".into(),
                        hex(remote),
                        "-client-settings".into(),
                        hex(local),
                    ],
                    local.to_vec(),
                    Some(remote),
                    false,
                );
            }
        }
    }
    // Empty settings are negotiated, unlike a missing extension.
    for id in [17513, 17613] {
        exercise(
            Some(if id == 17513 {
                Codepoint::Legacy
            } else {
                Codepoint::Chrome
            }),
            vec![format!("-alps={id}"), "-mutual".into(), "-group=24".into()],
            vec![],
            Some(b""),
            false,
        );
    }
    exercise(Some(Codepoint::Chrome), vec![], vec![], Some(b""), false);
    for codepoint in [None, Some(Codepoint::Chrome)] {
        exercise(codepoint, vec!["-alps=0".into()], vec![], None, false);
    }
}

#[test]
#[ignore = "requires independently built AEROBOX_TLS_PROFILE_PEER"]
fn alps_rejects_invalid_selection_and_unauthenticated_settings() {
    for args in [
        vec!["-bad-certificate-length"],
        vec!["-bad-finished"],
        vec!["-omit-alpn"],
        vec!["-selected-alpn=http/1.1"],
        vec!["-alps=17513", "-skip-alps-check"],
        vec!["-both-alps"],
        vec!["-unsolicited-early-data"],
        vec!["-oversized-ee"],
        vec!["-certificate-length=65537"],
        vec!["-trailing-compressed-data"],
    ] {
        exercise(
            Some(Codepoint::Chrome),
            args.into_iter().map(str::to_owned).collect(),
            vec![],
            None,
            true,
        );
    }
    exercise(None, vec!["-skip-alps-check".into()], vec![], None, true);
}

#[test]
fn alps_rejects_invalid_local_configuration() {
    let cp = Codepoint::Chrome;
    assert!(ApplicationSettings::new(cp, vec![]).is_err());
    assert!(ApplicationSettings::new(cp, vec![(vec![], vec![])]).is_err());
    assert!(ApplicationSettings::new(cp, vec![(vec![1; 256], vec![])]).is_err());
    assert!(
        ApplicationSettings::new(cp, vec![(b"h2".to_vec(), vec![]), (b"h2".to_vec(), vec![])])
            .is_err()
    );
    assert!(ApplicationSettings::new(cp, vec![(b"h2".to_vec(), vec![0; 65532])]).is_err());
    let mut cfg = config(Some(cp), vec![]);
    cfg.alpn_protocols.clear();
    assert!(ClientConnection::new(Arc::new(cfg), "localhost".try_into().unwrap()).is_err());
    let mut protocols: Vec<_> = (0..256u16)
        .map(|i| {
            let mut name = vec![b'x'; 254];
            name[..2].copy_from_slice(&i.to_be_bytes());
            (name, vec![])
        })
        .collect();
    protocols.push((vec![b'z'; 252], vec![]));
    let mut cfg = config(None, vec![]);
    cfg.application_settings = Some(ApplicationSettings::new(cp, protocols).unwrap());
    // The ALPS list itself fits, but leaves insufficient space for the other extensions.
    assert!(ClientConnection::new(Arc::new(cfg), "localhost".try_into().unwrap()).is_err());
}

#[test]
fn alps_checks_ech_extension_lengths_before_encoding() {
    use rustls::client::EchGreaseConfig;
    let suite = aerobox_crypto::hpke::ALL_SUPPORTED_SUITES[0];
    let (public, _) = suite.generate_key_pair().unwrap();
    for count in [1, 240] {
        let mut roots = RootCertStore::empty();
        roots
            .add(include_bytes!("fixtures/rsa-cert.der").as_slice().into())
            .unwrap();
        let mut config = ClientConfig::builder_with_provider(Arc::new(aerobox_crypto::provider()))
            .with_ech(EchGreaseConfig::new(suite, public.clone()).into())
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec()];
        let protocols = (0..count as u16)
            .map(|i| {
                let mut name = vec![b'x'; 254];
                name[..2].copy_from_slice(&i.to_be_bytes());
                (name, vec![])
            })
            .collect();
        config.application_settings =
            Some(ApplicationSettings::new(Codepoint::Chrome, protocols).unwrap());
        // Both unprotected lists fit individually; the outer ClientHello must
        // also fit the ECH payload that copies the inner ALPS protocol list.
        let result = ClientConnection::new(Arc::new(config), "localhost".try_into().unwrap());
        assert_eq!(result.is_ok(), count == 1);
    }
}

#[test]
#[ignore = "requires independently built AEROBOX_TLS_PROFILE_PEER"]
fn alps_tickets_early_accept_reject_and_changed_settings_interoperate() {
    for codepoint in [Codepoint::Legacy, Codepoint::Chrome] {
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
fn alps_maximum_extension_sizes_cross_record_boundaries() {
    // Client EE contains just ALPS; the server also includes the 9-byte h2 ALPN extension.
    let local = vec![0xa5; 65531];
    let remote = vec![0x6c; 65522];
    exercise(
        Some(Codepoint::Chrome),
        vec![
            "-server-settings".into(),
            hex(&remote),
            "-client-settings".into(),
            hex(&local),
        ],
        local,
        Some(&remote),
        false,
    );
}

#[test]
#[ignore = "requires independently built AEROBOX_TLS_PROFILE_PEER"]
fn independently_ordered_key_shares_complete_and_retry() {
    use rustls::NamedGroup as G;
    for shares in [
        vec![G::X25519, G::secp256r1],
        vec![G::secp384r1, G::X25519, G::secp256r1],
        vec![G::X25519MLKEM768, G::X25519],
    ] {
        for group in [G::X25519, G::secp256r1, G::secp384r1, G::X25519MLKEM768] {
            for retry in ["auto", "cookie", "invalid"] {
                if retry != "auto" && !shares.contains(&group) {
                    continue;
                }
                let (_peer, socket) = peer(&[
                    format!("-group={}", u16::from(group)),
                    format!(
                        "-expect-shares={}",
                        shares
                            .iter()
                            .map(|g| u16::from(*g).to_string())
                            .collect::<Vec<_>>()
                            .join(",")
                    ),
                    format!("-cookie-retry={}", retry == "cookie"),
                    format!("-force-retry={}", retry == "invalid"),
                    "-tickets".into(),
                ]);
                let mut cfg = config(Some(Codepoint::Chrome), vec![]);
                let mut provider = cfg.crypto_provider().as_ref().clone();
                provider
                    .kx_groups
                    .insert(0, production_hybrid::group(G::X25519MLKEM768));
                let mut roots = RootCertStore::empty();
                roots
                    .add(include_bytes!("fixtures/rsa-cert.der").as_slice().into())
                    .unwrap();
                let base = ClientConfig::builder_with_provider(Arc::new(provider))
                    .with_safe_default_protocol_versions()
                    .unwrap()
                    .with_root_certificates(roots)
                    .with_no_client_auth();
                let settings = cfg.application_settings.take();
                cfg = base;
                cfg.alpn_protocols = vec![b"h2".to_vec()];
                cfg.application_settings = settings;
                cfg.time_provider = Arc::new(FixtureTime);
                cfg.initial_key_share_groups = shares.clone();
                let cfg = Arc::new(cfg);
                let address = socket.peer_addr().unwrap();
                let mut first_socket = Some(socket);
                for iteration in 0..2 {
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
                        ClientConnection::new(cfg.clone(), "localhost".try_into().unwrap())
                            .unwrap();
                    if retry == "invalid" {
                        assert!(client.complete_io(&mut socket).is_err());
                        assert!(client.process_new_packets().is_err());
                        break;
                    }
                    while client.is_handshaking() {
                        client.complete_io(&mut socket).unwrap();
                    }
                    assert_eq!(
                        client.negotiated_key_exchange_group().unwrap().name(),
                        group
                    );
                    assert_eq!(
                        client.handshake_kind(),
                        Some(if iteration > 0 {
                            rustls::HandshakeKind::Resumed
                        } else if retry == "auto" && shares.contains(&group) {
                            rustls::HandshakeKind::Full
                        } else {
                            rustls::HandshakeKind::FullWithHelloRetryRequest
                        })
                    );
                    let mut stream = rustls::StreamOwned::new(client, socket);
                    let sent = vec![42; 65537];
                    stream.write_all(&sent).unwrap();
                    stream.flush().unwrap();
                    let mut got = vec![0; sent.len()];
                    stream.read_exact(&mut got).unwrap();
                    assert_eq!(got, sent);
                    assert_eq!(stream.conn.tls13_tickets_received(), 1);
                    stream.conn.send_close_notify();
                    stream.flush().unwrap();
                    assert_eq!(stream.read(&mut [0; 1]).unwrap(), 0);
                }
            }
        }
    }
}

#[test]
fn initial_key_share_config_is_validated() {
    use rustls::NamedGroup as G;
    for groups in [
        vec![G::X25519; 2],
        vec![G::Unknown(0x1234)],
        vec![G::X25519; 9],
    ] {
        let mut cfg = config(None, vec![]);
        cfg.initial_key_share_groups = groups;
        assert!(ClientConnection::new(Arc::new(cfg), "localhost".try_into().unwrap()).is_err());
    }
}

#[test]
#[ignore = "requires independently built AEROBOX_TLS_PROFILE_PEER"]
fn mixed_tls10_through_tls13_offer_completes_tls13_alps_brotli_and_retry() {
    use rustls::{NamedGroup, ProtocolVersion};
    for group in [29, 23, 24] {
        for compressed in [false, true] {
            let mut provider = aerobox_crypto::provider();
            provider
                .cipher_suites
                .extend(aerobox_crypto::legacy_cbc::suites());
            provider
                .cipher_suites
                .extend(aerobox_crypto::legacy_rsa::suites());
            let mut roots = RootCertStore::empty();
            roots
                .add(include_bytes!("fixtures/rsa-cert.der").as_slice().into())
                .unwrap();
            let mut cfg = ClientConfig::builder_with_provider(Arc::new(provider))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
            cfg.time_provider = Arc::new(FixtureTime);
            cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            cfg.application_settings = Some(
                ApplicationSettings::new(
                    Codepoint::Legacy,
                    vec![(b"h2".to_vec(), b"local".to_vec())],
                )
                .unwrap(),
            );
            cfg.initial_key_share_groups = vec![NamedGroup::X25519, NamedGroup::secp256r1];
            cfg.enable_legacy_tls(
                &aerobox_crypto::legacy_provider::LEGACY_TLS,
                &[
                    ProtocolVersion::TLSv1_0,
                    ProtocolVersion::TLSv1_1,
                    ProtocolVersion::TLSv1_2,
                    ProtocolVersion::TLSv1_3,
                ],
            )
            .unwrap();
            exercise_with_config(
                cfg,
                vec![
                    "-alps=17513".into(),
                    format!("-group={group}"),
                    format!("-brotli={compressed}"),
                    "-client-settings=6c6f63616c".into(),
                    "-server-settings=72656d6f7465".into(),
                ],
                Some(b"remote"),
                false,
            );
        }
    }
}
