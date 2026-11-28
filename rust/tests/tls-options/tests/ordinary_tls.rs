use aerobox_tls_options_check::{
    tls::{TlsClientOptions, TlsVersion},
    try_create_client_config_with_options,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use rustls::{ClientConfig, ClientConnection, ProtocolVersion};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
    process::{Child, Command, Stdio},
    sync::Arc,
    time::Duration,
};

const RSA_CERT: &[u8] =
    include_bytes!("../../../crates/aerobox-crypto/tests/fixtures/rsa-cert.der");
const RSA_KEY: &[u8] = include_bytes!("../../../crates/aerobox-crypto/tests/fixtures/rsa-key.der");
const EC_CERT: &[u8] =
    include_bytes!("../../../crates/aerobox-crypto/tests/fixtures/ecdsa-cert.der");
const EC_KEY: &[u8] = include_bytes!("../../../crates/aerobox-crypto/tests/fixtures/ecdsa-key.der");
const PAYLOAD: usize = 16385;

fn pem(label: &str, der: &[u8]) -> String {
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        STANDARD.encode(der)
    )
}

fn pin(der: &[u8]) -> String {
    let (_, certificate) = x509_parser::parse_x509_certificate(der).unwrap();
    STANDARD.encode(aerobox_primitives::digest::digest(
        &aerobox_primitives::digest::SHA256,
        certificate.public_key().raw,
    ))
}

fn client(
    options: &TlsClientOptions,
    verify: bool,
    tls13_only: bool,
) -> std::io::Result<ClientConfig> {
    try_create_client_config_with_options(
        verify,
        vec![],
        vec![],
        true,
        None,
        tls13_only,
        &Default::default(),
        options,
    )
}

fn options(min: TlsVersion, max: Option<TlsVersion>) -> TlsClientOptions {
    TlsClientOptions {
        min_version: Some(min),
        max_version: max,
        root_certificates: vec![pem("CERTIFICATE", RSA_CERT), pem("CERTIFICATE", EC_CERT)],
        ..Default::default()
    }
}

fn hello(config: ClientConfig) -> (u16, Vec<u16>, Vec<(u16, Vec<u8>)>) {
    assert!(
        config.client_hello_layout.is_none(),
        "ordinary TLS must not select a browser"
    );
    assert!(config.application_settings.is_none());
    assert!(!config.enable_tls12_renegotiation);
    let mut client =
        ClientConnection::new(Arc::new(config), "localhost".try_into().unwrap()).unwrap();
    let mut bytes = Vec::new();
    client.write_tls(&mut bytes).unwrap();
    assert_eq!(bytes[0], 22);
    assert_eq!(bytes[5], 1);
    let body = &bytes[9..];
    let version = u16::from_be_bytes([body[0], body[1]]);
    let mut offset = 35 + usize::from(body[34]);
    let cipher_length = usize::from(u16::from_be_bytes([body[offset], body[offset + 1]]));
    offset += 2;
    let suites = body[offset..offset + cipher_length]
        .chunks_exact(2)
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
        .collect();
    offset += cipher_length;
    offset += 1 + usize::from(body[offset]);
    let extension_length = usize::from(u16::from_be_bytes([body[offset], body[offset + 1]]));
    offset += 2;
    let end = offset + extension_length;
    let mut extensions = Vec::new();
    while offset < end {
        let kind = u16::from_be_bytes([body[offset], body[offset + 1]]);
        let length = usize::from(u16::from_be_bytes([body[offset + 2], body[offset + 3]]));
        offset += 4;
        extensions.push((kind, body[offset..offset + length].to_vec()));
        offset += length;
    }
    assert_eq!(offset, end);
    (version, suites, extensions)
}

#[test]
fn default_offer_stays_modern_and_explicit_old_bounds_have_no_browser_layout() {
    let (_, suites, extensions) = hello(client(&TlsClientOptions::default(), true, false).unwrap());
    assert_eq!(
        extensions.iter().find(|(kind, _)| *kind == 43).unwrap().1,
        [4, 3, 4, 3, 3]
    );
    assert!(
        !suites
            .iter()
            .any(|suite| matches!(*suite, 0xc009 | 0xc00a | 0xc013 | 0xc014))
    );

    for (min, max, version) in [
        (TlsVersion::V10, TlsVersion::V10, 0x0301),
        (TlsVersion::V11, TlsVersion::V11, 0x0302),
        (TlsVersion::V10, TlsVersion::V11, 0x0302),
    ] {
        let (actual, suites, extensions) =
            hello(client(&options(min, Some(max)), true, false).unwrap());
        assert_eq!(actual, version);
        assert!(
            !extensions
                .iter()
                .any(|(kind, _)| matches!(*kind, 43 | 51 | 17513 | 17613))
        );
        assert_eq!(suites, [0xc013, 0xc014, 0xc009, 0xc00a, 0x00ff]);
    }
    let (_, _, extensions) = hello(client(&options(TlsVersion::V11, None), true, false).unwrap());
    assert_eq!(
        extensions.iter().find(|(kind, _)| *kind == 43).unwrap().1,
        [6, 3, 4, 3, 3, 3, 2]
    );
}

#[test]
fn version_and_cipher_conflicts_fail_without_weakening_tls13_only_transports() {
    for json in [
        r#"{"max_version":"1.0"}"#,
        r#"{"max_version":"1.1"}"#,
        r#"{"min_version":"1.1","max_version":"1.0"}"#,
        r#"{"min_version":"1.3","max_version":"1.2"}"#,
        r#"{"min_version":"1.0","max_version":"1.1","cipher_suites":["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]}"#,
        r#"{"min_version":"1.1","max_version":"1.1","cipher_suites":["TLS_AES_128_GCM_SHA256"]}"#,
        r#"{"max_version":"1.2","cipher_suites":["TLS_AES_128_GCM_SHA256"]}"#,
    ] {
        let options = serde_json::from_str(json).unwrap();
        assert!(client(&options, false, false).is_err(), "accepted {json}");
    }
    assert!(client(&options(TlsVersion::V10, Some(TlsVersion::V11)), true, true).is_err());
    let (_, _, extensions) = hello(client(&options(TlsVersion::V10, None), true, true).unwrap());
    assert_eq!(
        extensions.iter().find(|(kind, _)| *kind == 43).unwrap().1,
        [2, 3, 4]
    );
}

fn handshake(
    config: ClientConfig,
    version: &'static rustls::SupportedProtocolVersion,
) -> ClientConnection {
    let server_config =
        rustls::ServerConfig::builder_with_provider(Arc::new(aerobox_crypto::provider()))
            .with_protocol_versions(&[version])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![EC_CERT.into()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(EC_KEY.to_vec()).into(),
            )
            .unwrap();
    let mut server = rustls::ServerConnection::new(Arc::new(server_config)).unwrap();
    let mut client =
        ClientConnection::new(Arc::new(config), "localhost".try_into().unwrap()).unwrap();
    for _ in 0..12 {
        let mut bytes = Vec::new();
        client.write_tls(&mut bytes).unwrap();
        server.read_tls(&mut bytes.as_slice()).unwrap();
        server.process_new_packets().unwrap();
        bytes.clear();
        server.write_tls(&mut bytes).unwrap();
        client.read_tls(&mut bytes.as_slice()).unwrap();
        client.process_new_packets().unwrap();
        if !client.is_handshaking() && !server.is_handshaking() {
            return client;
        }
    }
    panic!("modern handshake did not complete");
}

#[test]
fn ordinary_cipher_list_controls_tls12_without_removing_tls13() {
    for min in [TlsVersion::V10, TlsVersion::V12] {
        let mut policy = options(min, None);
        policy.cipher_suites = vec!["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".into()];
        for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
            let connection = handshake(client(&policy, true, false).unwrap(), version);
            assert_eq!(connection.protocol_version(), Some(version.version));
        }
        // Go accepts TLS 1.3 names here but does not restrict TLS 1.3 to them.
        policy.cipher_suites = vec!["TLS_AES_256_GCM_SHA384".into()];
        let connection = handshake(
            client(&policy, true, false).unwrap(),
            &rustls::version::TLS13,
        );
        assert_eq!(
            connection.negotiated_cipher_suite().unwrap().suite(),
            rustls::CipherSuite::TLS13_AES_128_GCM_SHA256
        );
    }
}

struct Peer(Child);
impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn peer(
    version: &str,
    suite: u16,
    mutual: &str,
) -> (
    Peer,
    BufReader<std::process::ChildStdout>,
    serde_json::Value,
) {
    let mut child = Command::new(
        std::env::var_os("AEROBOX_ANDROID11_PEER").expect("independent Go peer required"),
    )
    .args([
        "--version",
        version,
        "--suite",
        &format!("0x{suite:04x}"),
        "--mutual",
        mutual,
        "--bytes",
        &PAYLOAD.to_string(),
        "--fixtures",
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../crates/aerobox-crypto/tests/fixtures"
        ),
    ])
    .stdout(Stdio::piped())
    .stderr(Stdio::inherit())
    .spawn()
    .unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    output.read_line(&mut line).unwrap();
    let ready: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(ready["phase"], "ready", "{ready}");
    (Peer(child), output, ready)
}

fn socket(ready: &serde_json::Value) -> TcpStream {
    let socket = TcpStream::connect((
        "127.0.0.1",
        u16::try_from(ready["port"].as_u64().unwrap()).unwrap(),
    ))
    .unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    socket
}

#[test]
#[ignore = "requires AEROBOX_ANDROID11_PEER built from tests/reference/android11-peer"]
fn ordinary_old_tls_authenticates_transfers_and_honors_client_certificates() {
    for (version, suite, mutual, explicit, mixed) in [
        ("1.0", 0xc013, "none", false, false),
        ("1.1", 0xc009, "none", false, false),
        ("1.0", 0xc014, "rsa", true, false),
        ("1.1", 0xc00a, "ecdsa", true, false),
        ("1.0", 0xc013, "rsa", true, true),
        ("1.1", 0xc009, "ecdsa", false, true),
    ] {
        let (mut peer, mut output, ready) = peer(version, suite, mutual);
        let (version_option, expected) = if version == "1.0" {
            (TlsVersion::V10, ProtocolVersion::TLSv1_0)
        } else {
            (TlsVersion::V11, ProtocolVersion::TLSv1_1)
        };
        let mut policy = options(version_option, (!mixed).then_some(version_option));
        if explicit {
            policy.cipher_suites = vec![rustls::CipherSuite::from(suite).as_str().unwrap().into()];
        }
        policy.certificate_public_key_sha256 = vec![pin(if matches!(suite, 0xc009 | 0xc00a) {
            EC_CERT
        } else {
            RSA_CERT
        })];
        let credentials = if mutual == "none" {
            None
        } else {
            let hex = ready["client_certificate_der_hex"].as_str().unwrap();
            let der: Vec<_> = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect();
            Some((
                pem(
                    "PRIVATE KEY",
                    if mutual == "rsa" { RSA_KEY } else { EC_KEY },
                )
                .into_bytes(),
                pem("CERTIFICATE", &der).into_bytes(),
            ))
        };
        let config = try_create_client_config_with_options(
            true,
            vec![],
            vec![],
            true,
            credentials,
            false,
            &Default::default(),
            &policy,
        )
        .unwrap();
        assert!(config.client_hello_layout.is_none());
        let connection =
            ClientConnection::new(Arc::new(config), "localhost".try_into().unwrap()).unwrap();
        let mut stream = rustls::StreamOwned::new(connection, socket(&ready));
        let sent: Vec<_> = (0..PAYLOAD).map(|i| ((i * 17 + 3) % 251) as u8).collect();
        stream.write_all(&sent).unwrap();
        stream.flush().unwrap();
        let mut response = vec![0; 36 + PAYLOAD];
        stream.read_exact(&mut response).unwrap();
        assert_eq!(&response[..4], b"AB11");
        assert_eq!(stream.conn.protocol_version(), Some(expected));
        assert_eq!(
            u16::from(stream.conn.negotiated_cipher_suite().unwrap().suite()),
            suite
        );
        let exporter = stream
            .conn
            .export_keying_material(
                vec![0; 32],
                b"aerobox android11 exporter",
                Some(b"\0android11\0"),
            )
            .unwrap();
        assert_eq!(&response[4..36], exporter);
        for (i, byte) in response[36..].iter().enumerate() {
            assert_eq!(*byte, ((i * 29 + 7) % 251) as u8);
        }
        stream.conn.send_close_notify();
        stream.flush().unwrap();
        assert_eq!(stream.read_to_end(&mut Vec::new()).unwrap(), 0);
        let mut line = String::new();
        output.read_line(&mut line).unwrap();
        let report: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(report["phase"], "complete", "{report}");
        assert_eq!(
            report["client_certificates"],
            if mutual == "none" { 0 } else { 1 }
        );
        assert_eq!(report["close_notify_received"], true);
        assert!(peer.0.wait().unwrap().success());
    }
}

#[test]
#[ignore = "requires AEROBOX_ANDROID11_PEER built from tests/reference/android11-peer"]
fn ordinary_old_tls_rejects_default_versions_wrong_name_root_and_pin() {
    for failure in ["default-version", "name", "root", "pin"] {
        let (_peer, _output, ready) = peer("1.1", 0xc013, "none");
        let mut policy = options(TlsVersion::V11, Some(TlsVersion::V11));
        let mut name = "localhost";
        let mut verify = true;
        match failure {
            "default-version" => {
                policy.min_version = None;
                policy.max_version = None;
            }
            "name" => name = "wrong.test",
            "root" => policy.root_certificates = vec![pem("CERTIFICATE", EC_CERT)],
            "pin" => {
                verify = false;
                policy.certificate_public_key_sha256 = vec![pin(EC_CERT)];
            }
            _ => unreachable!(),
        }
        let config = client(&policy, verify, false).unwrap();
        let mut connection =
            ClientConnection::new(Arc::new(config), name.try_into().unwrap()).unwrap();
        let error = connection
            .complete_io(&mut socket(&ready))
            .expect_err(failure);
        let error = error
            .get_ref()
            .and_then(|error| error.downcast_ref::<rustls::Error>())
            .unwrap_or_else(|| {
                panic!("{failure} must fail TLS validation, not transport I/O: {error}")
            });
        match failure {
            "default-version" => assert!(
                matches!(
                    error,
                    rustls::Error::AlertReceived(rustls::AlertDescription::ProtocolVersion)
                ),
                "{error:?}"
            ),
            "name" | "root" => assert!(
                matches!(error, rustls::Error::InvalidCertificate(_)),
                "{failure}: {error:?}"
            ),
            "pin" => assert!(
                matches!(error, rustls::Error::General(message) if message == "TLS certificate public key pin mismatch"),
                "{error:?}"
            ),
            _ => unreachable!(),
        }
    }
}
