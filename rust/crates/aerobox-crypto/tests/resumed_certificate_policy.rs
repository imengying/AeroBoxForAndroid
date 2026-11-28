//! A real resumed TLS handshake must re-run explicitly requested certificate policy.
use rustls::{
    ClientConfig, ClientConnection, Connection, DigitallySignedStruct, Error, HandshakeKind,
    RootCertStore, ServerConfig, ServerConnection, SignatureScheme,
    client::{
        WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
    time_provider::TimeProvider,
};
use std::{
    io::{Cursor, Read, Write},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

#[derive(Debug)]
struct Clock(AtomicU64);
impl TimeProvider for Clock {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(Duration::from_secs(
            self.0.load(Ordering::SeqCst),
        )))
    }
}

#[derive(Debug)]
struct Policy {
    webpki: Arc<WebPkiServerVerifier>,
    calls: AtomicUsize,
    deny: AtomicBool,
}
impl ServerCertVerifier for Policy {
    fn verify_server_cert(
        &self,
        leaf: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        time: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(name.to_str(), "localhost");
        if self.deny.load(Ordering::SeqCst) {
            return Err(Error::General("current certificate policy denied".into()));
        }
        self.webpki
            .verify_server_cert(leaf, chain, name, ocsp, time)
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.webpki
            .verify_tls12_signature(message, certificate, signature)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.webpki
            .verify_tls13_signature(message, certificate, signature)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.webpki.supported_verify_schemes()
    }
}

fn configs(
    version: &'static rustls::SupportedProtocolVersion,
    reverify: bool,
) -> (
    Arc<ClientConfig>,
    Arc<ServerConfig>,
    Arc<Policy>,
    Arc<Clock>,
) {
    let certificate = include_bytes!("fixtures/ecdsa-cert.der");
    let (_, parsed) = x509_parser::parse_x509_certificate(certificate).unwrap();
    let expires = u64::try_from(parsed.validity().not_after.timestamp()).unwrap();
    let clock = Arc::new(Clock(AtomicU64::new(expires - 5)));
    let provider = Arc::new(aerobox_crypto::provider());
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(certificate.as_slice()))
        .unwrap();
    let policy = Arc::new(Policy {
        webpki: WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
            .build()
            .unwrap(),
        calls: AtomicUsize::new(0),
        deny: AtomicBool::new(false),
    });
    let mut client = ClientConfig::builder_with_details(provider.clone(), clock.clone())
        .with_protocol_versions(&[version])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(policy.clone())
        .with_no_client_auth();
    client.reverify_on_resume = reverify;
    let mut server = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[version])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(certificate.as_slice())],
            PrivatePkcs8KeyDer::from(include_bytes!("fixtures/ecdsa-key.der").to_vec()).into(),
        )
        .unwrap();
    // Client expiry advances only ten seconds, keeping the cached TLS ticket
    // within its lifetime. The server retains the original issuance clock.
    server.time_provider = Arc::new(Clock(AtomicU64::new(expires - 5)));
    (Arc::new(client), Arc::new(server), policy, clock)
}

fn pair(client: &Arc<ClientConfig>, server: &Arc<ServerConfig>) -> (Connection, Connection) {
    (
        Connection::Client(
            ClientConnection::new(client.clone(), "localhost".try_into().unwrap()).unwrap(),
        ),
        Connection::Server(ServerConnection::new(server.clone()).unwrap()),
    )
}

fn transfer(from: &mut Connection, to: &mut Connection) -> Result<usize, Error> {
    let mut data = Vec::new();
    while from.wants_write() {
        assert!(from.write_tls(&mut data).unwrap() > 0);
    }
    for part in data.chunks(97) {
        let mut input = Cursor::new(part);
        while input.position() < part.len() as u64 {
            assert!(to.read_tls(&mut input).unwrap() > 0);
            to.process_new_packets()?;
        }
    }
    Ok(data.len())
}

fn settle(client: &mut Connection, server: &mut Connection) -> Result<(), Error> {
    for _ in 0..40 {
        let sent = transfer(client, server)?;
        let received = transfer(server, client)?;
        if sent == 0 && received == 0 && !client.is_handshaking() && !server.is_handshaking() {
            return Ok(());
        }
    }
    panic!("handshake did not settle");
}

fn exchange(client: &mut Connection, server: &mut Connection) {
    client
        .writer()
        .write_all(b"authenticated client data")
        .unwrap();
    transfer(client, server).unwrap();
    let mut data = vec![0; 25];
    server.reader().read_exact(&mut data).unwrap();
    assert_eq!(data, b"authenticated client data");
    server
        .writer()
        .write_all(b"authenticated server data")
        .unwrap();
    transfer(server, client).unwrap();
    client.reader().read_exact(&mut data).unwrap();
    assert_eq!(data, b"authenticated server data");
    client.send_close_notify();
    transfer(client, server).unwrap();
    server.send_close_notify();
    transfer(server, client).unwrap();
    assert_eq!(client.reader().read(&mut [0]).unwrap(), 0);
    assert_eq!(server.reader().read(&mut [0]).unwrap(), 0);
}

#[test]
fn requested_policy_revalidates_still_live_tls12_and_tls13_sessions() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for reverify in [false, true] {
            let (config, server_config, policy, clock) = configs(version, reverify);
            for (index, kind) in [HandshakeKind::Full, HandshakeKind::Resumed]
                .into_iter()
                .enumerate()
            {
                let (mut client, mut server) = pair(&config, &server_config);
                settle(&mut client, &mut server).unwrap();
                assert_eq!(client.handshake_kind(), Some(kind));
                assert_eq!(server.handshake_kind(), Some(kind));
                assert_eq!(
                    policy.calls.load(Ordering::SeqCst),
                    if reverify { index + 1 } else { 1 }
                );
                exchange(&mut client, &mut server);
            }
            clock.0.fetch_add(10, Ordering::SeqCst);
            let (mut client, mut server) = pair(&config, &server_config);
            let result = settle(&mut client, &mut server);
            assert_eq!(server.handshake_kind(), Some(HandshakeKind::Resumed));
            if reverify {
                assert!(
                    matches!(result, Err(Error::InvalidCertificate(_))),
                    "{result:?}"
                );
                assert_eq!(policy.calls.load(Ordering::SeqCst), 3);
                assert!(client.peer_certificates().is_none());
                assert!(client.reader().read(&mut [0]).is_err());
            } else {
                result.unwrap();
                assert_eq!(policy.calls.load(Ordering::SeqCst), 1);
                exchange(&mut client, &mut server);
            }
        }
    }
}

#[test]
fn current_custom_certificate_policy_can_reject_a_resumed_session() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        let (config, server_config, policy, _) = configs(version, true);
        let (mut client, mut server) = pair(&config, &server_config);
        settle(&mut client, &mut server).unwrap();
        exchange(&mut client, &mut server);
        policy.deny.store(true, Ordering::SeqCst);
        let (mut client, mut server) = pair(&config, &server_config);
        assert_eq!(
            settle(&mut client, &mut server).unwrap_err(),
            Error::General("current certificate policy denied".into())
        );
        assert_eq!(policy.calls.load(Ordering::SeqCst), 2);
        assert_eq!(server.handshake_kind(), Some(HandshakeKind::Resumed));
        assert!(client.peer_certificates().is_none());
    }
}

#[test]
fn early_data_cannot_precede_explicit_resumed_certificate_policy() {
    let (config, _, _, _) = configs(&rustls::version::TLS13, true);
    let mut config = (*config).clone();
    config.enable_early_data = true;
    assert!(
        matches!(ClientConnection::new(Arc::new(config), "localhost".try_into().unwrap()),
        Err(Error::General(message)) if message == "resumed certificate revalidation requires early data disabled")
    );
}
