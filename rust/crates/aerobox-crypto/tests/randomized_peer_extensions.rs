//! Strict advertised Certificate extensions against the independent Go peer.
#[path = "support/randomized.rs"]
mod randomized;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, Error, InvalidMessage};
use sha2::{Digest, Sha256};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
    process::{Child, ChildStdout, Command, Stdio},
    sync::{Arc, Mutex},
    time::Duration,
};

const CERT: &[u8] = include_bytes!("fixtures/rsa-cert.der");
const LABEL: &[u8] = b"aerobox android browser tls13 exporter";
const CONTEXT: &[u8] = b"\0android\0tls13\0";
#[derive(Debug)]
struct Time;
impl rustls::time_provider::TimeProvider for Time {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(Duration::from_secs(1893456000)))
    }
}
#[derive(Debug)]
struct Observe {
    inner: Arc<dyn ServerCertVerifier>,
    ocsp: Arc<Mutex<Vec<u8>>>,
}
impl ServerCertVerifier for Observe {
    fn verify_server_cert(
        &self,
        cert: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let verified = self
            .inner
            .verify_server_cert(cert, chain, name, ocsp, now)?;
        *self.ocsp.lock().unwrap() = ocsp.to_vec();
        Ok(verified)
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        sig: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, sig)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        sig: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, sig)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}
fn configuration(plan: &serde_json::Value, only: bool) -> (ClientConfig, Arc<Mutex<Vec<u8>>>) {
    let mut cfg = randomized::config(plan, only).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CERT.into()).unwrap();
    let inner = rustls::client::WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        cfg.crypto_provider().clone(),
    )
    .build()
    .unwrap();
    let observed = Arc::new(Mutex::new(vec![]));
    cfg.dangerous().set_certificate_verifier(Arc::new(Observe {
        inner,
        ocsp: observed.clone(),
    }));
    cfg.time_provider = Arc::new(Time);
    (cfg, observed)
}
struct Peer(Child);
impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn report(out: &mut BufReader<ChildStdout>) -> serde_json::Value {
    let mut line = String::new();
    out.by_ref().take(65537).read_line(&mut line).unwrap();
    assert!(!line.is_empty() && line.len() <= 65536 && line.ends_with('\n'));
    serde_json::from_str(&line).unwrap()
}
fn start(extra: &[&str]) -> (Peer, BufReader<ChildStdout>, TcpStream) {
    let mut peer = Peer(
        Command::new(std::env::var_os("AEROBOX_TLS_PROFILE_PEER").expect("independent Go peer"))
            .args([
                "-android-browser-exchange",
                "-brotli=false",
                "-alps=0",
                "-fixtures",
                concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures"),
            ])
            .args(extra)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let mut out = BufReader::new(peer.0.stdout.take().unwrap());
    let ready = report(&mut out);
    assert_eq!(ready["phase"], "ready");
    let socket = TcpStream::connect((
        "127.0.0.1",
        u16::try_from(ready["port"].as_u64().unwrap()).unwrap(),
    ))
    .unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    (peer, out, socket)
}
#[test]
#[ignore = "requires AEROBOX_TLS_PROFILE_PEER with unsolicited Certificate extension flags"]
fn unadvertised_sct_and_ocsp_are_rejected_as_unknown_certificate_extensions() {
    let rows: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("fixtures/randomized-plans.json")).unwrap();
    let plan = &rows[1]["plan"];
    let exts = randomized::ids(plan, "extensions");
    assert!(exts.contains(&16) && !exts.contains(&18) && !exts.contains(&5));
    for only in [false, true] {
        for flag in ["-unsolicited-sct", "-unsolicited-ocsp"] {
            let (mut peer, mut out, mut socket) = start(&[flag]);
            let (cfg, observed) = configuration(plan, only);
            let mut client =
                ClientConnection::new(Arc::new(cfg), "localhost".try_into().unwrap()).unwrap();
            let error = loop {
                while client.wants_write() {
                    client.write_tls(&mut socket).unwrap();
                }
                assert!(
                    client.read_tls(&mut socket).unwrap() > 0,
                    "peer closed before malformed Certificate"
                );
                match client.process_new_packets() {
                    Err(e) => break e,
                    Ok(_) => assert!(client.is_handshaking(), "accepted unsolicited extension"),
                }
            };
            assert_eq!(
                error,
                Error::InvalidMessage(InvalidMessage::UnknownCertificateExtension),
                "{flag}"
            );
            assert_eq!(client.process_new_packets().unwrap_err(), error);
            assert!(
                observed.lock().unwrap().is_empty(),
                "unadvertised extension reached verified certificate callback"
            );
            let _ = client.write_tls(&mut socket);
            let _ = socket.shutdown(std::net::Shutdown::Both);
            let result = report(&mut out);
            assert_eq!(result["phase"], "error");
            assert!(!peer.0.wait().unwrap().success());
        }
    }
}
#[test]
#[ignore = "requires AEROBOX_TLS_PROFILE_PEER with signed OCSP support"]
fn advertised_sct_and_ocsp_complete_chain_finished_exporter_data_and_close() {
    let plan = randomized::plan();
    let exts = randomized::ids(&plan, "extensions");
    assert!(exts.contains(&18) && exts.contains(&5));
    for only in [false, true] {
        let (mut peer, mut out, socket) = start(&["-alps=17513", "-sct=valid", "-ocsp"]);
        let (cfg, observed) = configuration(&plan, only);
        let client = ClientConnection::new(Arc::new(cfg), "localhost".try_into().unwrap()).unwrap();
        let mut stream = rustls::StreamOwned::new(client, socket);
        let sent: Vec<_> = (0..65537).map(|i| ((i * 17 + 3) % 251) as u8).collect();
        stream.write_all(&sent).unwrap();
        stream.flush().unwrap();
        let mut response = vec![0; 36 + 65537];
        stream.read_exact(&mut response).unwrap();
        assert_eq!(&response[..4], b"AB13");
        assert_eq!(stream.conn.peer_certificates().unwrap()[0].as_ref(), CERT);
        assert_eq!(stream.conn.alpn_protocol(), Some(b"h2".as_slice()));
        assert_eq!(stream.conn.peer_application_settings(), Some([].as_slice()));
        let ocsp = observed.lock().unwrap();
        assert!(
            ocsp.len() > 128 && ocsp.len() < 4096 && ocsp[0] == 0x30,
            "expected signed DER OCSP fixture"
        );
        drop(ocsp);
        let exporter = stream
            .conn
            .export_keying_material([0; 32], LABEL, Some(CONTEXT))
            .unwrap();
        assert_eq!(&response[4..36], exporter);
        assert!(
            response[36..]
                .iter()
                .enumerate()
                .all(|(i, b)| *b == ((i * 29 + 7) % 251) as u8)
        );
        stream.conn.send_close_notify();
        stream.flush().unwrap();
        assert_eq!(stream.read(&mut [0]).unwrap(), 0);
        assert!(stream.conn.process_new_packets().unwrap().peer_has_closed());
        let result = report(&mut out);
        assert_eq!(result["phase"], "complete");
        let result = &result["result"];
        assert_eq!(result["exporter"], randomized::hex(&exporter));
        assert_eq!(
            result["client_sha256"],
            randomized::hex(&Sha256::digest(&sent))
        );
        assert_eq!(
            result["server_sha256"],
            randomized::hex(&Sha256::digest(&response[36..]))
        );
        assert_eq!(result["close_notify"], true);
        assert_eq!(result["bytes"], 65537);
        assert!(peer.0.wait().unwrap().success());
    }
}
