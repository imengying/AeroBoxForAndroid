use rustls::{
    ClientConfig, ClientConnection, HandshakeKind, RootCertStore,
    client::{
        ApplicationSettings, ApplicationSettingsCodepoint, ClientHelloLayout, EchConfig,
        EchRejectionHandler, EchStatus,
    },
    pki_types::{CertificateDer, EchConfigListBytes, pem::PemObject},
};
use std::{
    collections::BTreeMap,
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

#[path = "../../../vendor/shoes/src/crypto/rustcrypto_kx.rs"]
mod production_hybrid;

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Peer {
    child: Child,
    dir: PathBuf,
    port: u16,
}
impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
impl Peer {
    fn new(mode: &str, group: u16, tickets: bool) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "aerobox-chrome-ech-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir).unwrap();
        let mut child =
            Command::new(std::env::var_os("AEROBOX_ECH_PEER").expect("AEROBOX_ECH_PEER"))
                .args(["tcp", mode])
                .env("AEROBOX_PEER_CERT_DIR", &dir)
                .env("AEROBOX_ECH_CERT_ALGORITHM", "p256")
                .env("AEROBOX_ECH_ALPN", "h2")
                .env("AEROBOX_ECH_CURVE", group.to_string())
                .env("AEROBOX_ECH_TICKETS", if tickets { "1" } else { "0" })
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        Self {
            child,
            dir,
            port: line.trim().parse().unwrap(),
        }
    }
    fn ech(&self) -> EchConfig {
        // The existing reference fixture uses the original sing-box PEM label.
        let pem = std::fs::read_to_string(self.dir.join("initial-config.pem"))
            .unwrap()
            .replace("ECH CONFIGS", "ECHCONFIG");
        EchConfig::new(
            EchConfigListBytes::from_pem_slice(pem.as_bytes()).unwrap(),
            aerobox_crypto::hpke::ALL_SUPPORTED_SUITES,
        )
        .unwrap()
    }
    fn config(&self) -> ClientConfig {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from_pem_file(self.dir.join("ca.pem")).unwrap())
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
            .with_ech(self.ech().into())
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        config.application_settings = Some(
            ApplicationSettings::new(
                ApplicationSettingsCodepoint::Chrome,
                vec![(b"h2".to_vec(), vec![])],
            )
            .unwrap(),
        );
        config.initial_key_share_groups = vec![
            rustls::NamedGroup::X25519MLKEM768,
            rustls::NamedGroup::X25519,
        ];
        config.client_hello_layout = Some(ClientHelloLayout::Chrome133);
        config
    }
    fn socket(&self) -> TcpStream {
        let socket = TcpStream::connect(("127.0.0.1", self.port)).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        socket
    }
    fn stats(&self) -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(self.dir.join("stats.json")).unwrap()).unwrap()
    }
}

#[derive(Debug, Default)]
struct Rejections(Mutex<Vec<Option<Vec<u8>>>>);
impl EchRejectionHandler for Rejections {
    fn rejected(&self, configs: Option<Vec<u8>>) {
        self.0.lock().unwrap().push(configs);
    }
}

fn take<'a>(bytes: &mut &'a [u8], n: usize) -> &'a [u8] {
    let (head, tail) = bytes.split_at(n);
    *bytes = tail;
    head
}
fn vector<'a>(bytes: &mut &'a [u8], width: usize) -> &'a [u8] {
    let n = take(bytes, width)
        .iter()
        .fold(0usize, |n, b| (n << 8) | usize::from(*b));
    take(bytes, n)
}
fn u16s(bytes: &[u8]) -> Vec<u16> {
    assert_eq!(bytes.len() % 2, 0);
    bytes
        .chunks_exact(2)
        .map(|x| u16::from_be_bytes([x[0], x[1]]))
        .collect()
}
fn grease(x: u16) -> bool {
    x & 0x0f0f == 0x0a0a && (x >> 8) == (x & 255)
}

fn assert_cover(hello: &[u8]) {
    let mut wire = hello;
    assert_eq!(take(&mut wire, 3), [22, 3, 1]);
    let mut message = vector(&mut wire, 2);
    assert!(wire.is_empty());
    assert_eq!(take(&mut message, 1), [1]);
    let mut body = vector(&mut message, 3);
    assert!(message.is_empty());
    assert_eq!(take(&mut body, 2), [3, 3]);
    take(&mut body, 32);
    assert_eq!(vector(&mut body, 1).len(), 32);
    let suites = u16s(vector(&mut body, 2));
    assert!(grease(suites[0]));
    assert_eq!(
        &suites[1..],
        [
            0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
            0x009c, 0x009d, 0x002f, 0x0035
        ]
    );
    assert_eq!(vector(&mut body, 1), [0]);
    let mut extensions = vector(&mut body, 2);
    assert!(body.is_empty());
    let mut order = vec![];
    let mut fields = BTreeMap::new();
    while !extensions.is_empty() {
        let typ = u16s(take(&mut extensions, 2))[0];
        let value = vector(&mut extensions, 2);
        assert!(fields.insert(typ, value).is_none());
        order.push(typ);
    }
    assert!(grease(order[0]));
    let last = if *order.last().unwrap() == 41 {
        order[order.len() - 2]
    } else {
        *order.last().unwrap()
    };
    assert!(grease(last));
    assert_ne!(order[0], last);
    assert!(fields[&order[0]].is_empty());
    assert_eq!(fields[&last], [0]);
    let mut versions = fields[&43];
    let versions = u16s(vector(&mut versions, 1));
    assert!(grease(versions[0]));
    assert_eq!(&versions[1..], [0x0304, 0x0303]);
    let mut names = fields[&0];
    let mut names = vector(&mut names, 2);
    assert_eq!(take(&mut names, 1), [0]);
    assert_eq!(vector(&mut names, 2), b"public.test");
    assert!(names.is_empty());
    assert!(
        !hello
            .windows(b"secret.test".len())
            .any(|x| x == b"secret.test")
    );
    let mut ech = fields[&65037];
    assert_eq!(take(&mut ech, 5), [0, 0, 1, 0, 1]);
    take(&mut ech, 1);
    assert_eq!(vector(&mut ech, 2).len(), 32);
    let payload = vector(&mut ech, 2);
    assert!(!payload.is_empty());
    assert_eq!((payload.len() - 16) % 32, 0);
    assert!(ech.is_empty());
    assert_eq!(fields[&27], [2, 0, 2]);
    assert_eq!(fields[&17613], [0, 3, 2, b'h', b'2']);
}

fn connect(
    peer: &Peer,
    config: Arc<ClientConfig>,
    fragments: bool,
) -> Result<(ClientConnection, TcpStream), std::io::Error> {
    let mut client = ClientConnection::new(config, "secret.test".try_into().unwrap()).unwrap();
    let mut hello = vec![];
    client.write_tls(&mut hello).unwrap();
    assert_cover(&hello);
    let mut socket = peer.socket();
    if fragments {
        // Split one ClientHello over multiple legal TLS records and small
        // transport writes; the transcript must still describe one message.
        for fragment in hello[5..].chunks(97) {
            let mut record = vec![22, 3, 1];
            record.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
            record.extend_from_slice(fragment);
            for chunk in record.chunks(13) {
                socket.write_all(chunk)?;
            }
        }
    } else {
        socket.write_all(&hello)?;
    }
    while client.is_handshaking() {
        client.complete_io(&mut socket)?;
    }
    Ok((client, socket))
}
fn echo(client: &mut ClientConnection, socket: &mut TcpStream) {
    let input: Vec<u8> = (0..65537).map(|n| (n % 251) as u8).collect();
    let mut output = vec![0; input.len()];
    let mut stream = rustls::Stream::new(client, socket);
    stream.write_all(&input).unwrap();
    stream.flush().unwrap();
    stream.read_exact(&mut output).unwrap();
    assert_eq!(input, output);
}

#[test]
#[ignore = "requires AEROBOX_ECH_PEER with browser fixture options"]
fn chrome133_ech_accepts_independent_peer_hrr_resumption_and_fragmentation() {
    for group in [4588, 29, 23, 24] {
        let peer = Peer::new("accept", group, true);
        let config = Arc::new(peer.config());
        for resumed in [false, true] {
            let (mut client, mut socket) = connect(&peer, config.clone(), true)
                .unwrap_or_else(|e| panic!("group={group} resumed={resumed}: {e}"));
            assert_eq!(client.ech_status(), EchStatus::Accepted);
            assert_eq!(
                client.protocol_version(),
                Some(rustls::ProtocolVersion::TLSv1_3)
            );
            assert_eq!(client.alpn_protocol(), Some(b"h2".as_slice()));
            assert_eq!(
                client.handshake_kind() == Some(HandshakeKind::Resumed),
                resumed
            );
            echo(&mut client, &mut socket);
            client.send_close_notify();
            client.write_tls(&mut socket).unwrap();
        }
        let stats = peer.stats();
        assert_eq!(stats["connections"], 2, "{stats}");
        assert_eq!(stats["ech_accepted"], 2, "{stats}");
        assert!(
            stats["handshakes"]
                .as_array()
                .unwrap()
                .iter()
                .all(|s| s["server_name"] == "secret.test")
        );
    }
}

#[test]
#[ignore = "requires AEROBOX_ECH_PEER with browser fixture options"]
fn chrome133_ech_authenticates_retries_and_never_exposes_application_data() {
    for mode in ["rotate", "reject", "badpublic"] {
        let peer = Peer::new(mode, 29, false);
        let rejections = Arc::new(Rejections::default());
        let mut config = peer.config();
        config.ech_rejection_handler = Some(rejections.clone());
        let result = connect(&peer, Arc::new(config.clone()), false);
        assert!(result.is_err(), "{mode}");
        let stats = peer.stats();
        assert_eq!(stats["connections"], 0, "{stats}");
        assert_eq!(stats["echoed_bytes"], 0, "{stats}");
        let received = rejections.0.lock().unwrap().clone();
        if mode == "badpublic" {
            assert!(
                received.is_empty(),
                "untrusted public certificate must never authorize retries"
            );
            continue;
        }
        assert_eq!(received.len(), 1, "{mode}");
        if mode == "rotate" {
            let retry = received[0].clone().expect("authenticated rotation config");
            config
                .set_ech_config(
                    EchConfig::new(retry.into(), aerobox_crypto::hpke::ALL_SUPPORTED_SUITES)
                        .unwrap(),
                )
                .unwrap();
            let (mut client, mut socket) = connect(&peer, Arc::new(config), false).unwrap();
            assert_eq!(client.ech_status(), EchStatus::Accepted);
            echo(&mut client, &mut socket);
        } else {
            assert!(received[0].is_none(), "no ECH key configured");
        }
    }
}
