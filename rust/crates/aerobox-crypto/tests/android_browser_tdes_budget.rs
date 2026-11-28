//! Real 3DES record-budget exhaustion through buffered and unbuffered rustls APIs.
//! No budget overrides: every connection encrypts almost/exactly 2^20 DES blocks.
//! All payloads, wire observers and transport buffers remain bounded by 64 KiB.
use rustls::{
    ClientConfig, ClientConnection, Error, ProtocolVersion,
    client::UnbufferedClientConnection,
    unbuffered::{ConnectionState, EncryptError},
};
use sha2::{Digest, Sha256};
use std::{
    io::{self, BufRead, BufReader, IoSlice, Read, Write},
    net::{Shutdown, TcpStream},
    process::{Child, ChildStdout, Command, Stdio},
    sync::{Arc, Mutex},
    time::Duration,
};

const FULL: usize = 16384;
const MAX_BLOCKS: usize = 1 << 20;
const FULL_BLOCKS: usize = 2051;
const FINISHED_BLOCKS: usize = 5;
const FULL_RECORDS: usize = (MAX_BLOCKS - FINISHED_BLOCKS) / FULL_BLOCKS;
const TAIL_BLOCKS: usize = MAX_BLOCKS - FINISHED_BLOCKS - FULL_RECORDS * FULL_BLOCKS;
const TAIL_PLAIN: usize = TAIL_BLOCKS * 8 - 21;
const LABEL: &[u8] = b"aerobox 3des budget exporter";
const CONTEXT: &[u8] = b"\0budget\0";
const RSA_CERT: &[u8] = include_bytes!("fixtures/rsa-cert.der");

#[derive(Debug)]
struct FixtureTime;
impl rustls::time_provider::TimeProvider for FixtureTime {
    fn current_time(&self) -> Option<rustls::pki_types::UnixTime> {
        Some(rustls::pki_types::UnixTime::since_unix_epoch(
            Duration::from_secs(1893456000),
        ))
    }
}

// In-memory test-only exporter oracle for the unbuffered API, which has no
// public exporter method. Secret material is never written to a log or artifact.
#[derive(Debug, Default)]
struct Secrets(Mutex<Option<([u8; 32], [u8; 48])>>);
impl rustls::KeyLog for Secrets {
    fn log(&self, label: &str, random: &[u8], secret: &[u8]) {
        assert_eq!(label, "CLIENT_RANDOM");
        *self.0.lock().unwrap() = Some((random.try_into().unwrap(), secret.try_into().unwrap()));
    }
}

fn config() -> (Arc<ClientConfig>, Arc<Secrets>) {
    let mut provider = aerobox_crypto::provider();
    provider.cipher_suites = aerobox_crypto::legacy_tdes::suites()
        .into_iter()
        .filter(|suite| u16::from(suite.suite()) == 0xc012)
        .collect();
    assert_eq!(provider.cipher_suites.len(), 1);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(RSA_CERT.into()).unwrap();
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.time_provider = Arc::new(FixtureTime);
    let secrets = Arc::new(Secrets::default());
    config.key_log = secrets.clone();
    (Arc::new(config), secrets)
}

#[derive(Default)]
struct Witness {
    record: Vec<u8>,
    encrypted: bool,
    blocks: usize,
    applications: usize,
    server_random: Option<[u8; 32]>,
}
impl Witness {
    fn feed(&mut self, input: &[u8]) {
        assert!(self.record.len() + input.len() <= 65536);
        self.record.extend_from_slice(input);
        while self.record.len() >= 5 {
            let size = usize::from(u16::from_be_bytes([self.record[3], self.record[4]]));
            assert!(size <= 18432);
            if self.record.len() < size + 5 {
                break;
            }
            let kind = self.record[0];
            if self.encrypted {
                assert_eq!(&self.record[1..3], &[3, 3]);
                assert!(size >= 32 && (size - 8) % 8 == 0);
                self.blocks += (size - 8) / 8;
                if kind == 23 {
                    self.applications += 1;
                }
            } else if kind == 20 {
                assert_eq!(&self.record[5..5 + size], &[1]);
                self.encrypted = true;
            } else if kind == 22 && size >= 38 && self.record[5] == 2 {
                // Go emits its initial ServerHello as a complete handshake message.
                assert!(self.server_random.is_none());
                self.server_random = Some(self.record[11..43].try_into().unwrap());
            }
            self.record.drain(..size + 5);
        }
    }
}

struct TappedTcp {
    socket: TcpStream,
    sent: Witness,
    received: Witness,
}
impl Read for TappedTcp {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let n = self.socket.read(output)?;
        self.received.feed(&output[..n]);
        Ok(n)
    }
}
impl Write for TappedTcp {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        // Bound each observation even when write_tls chooses a vectored flush.
        let n = self.socket.write(&input[..input.len().min(32768)])?;
        self.sent.feed(&input[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.socket.flush()
    }
}

struct Peer(Child);
impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn report(output: &mut BufReader<ChildStdout>) -> serde_json::Value {
    let mut line = String::new();
    output.by_ref().take(65537).read_line(&mut line).unwrap();
    assert!(!line.is_empty() && line.len() <= 65536 && line.ends_with('\n'));
    serde_json::from_str(&line).unwrap()
}
fn start(exact: bool) -> (Peer, BufReader<ChildStdout>, TappedTcp) {
    let mut peer = Peer(
        Command::new(
            std::env::var_os("AEROBOX_ANDROID_BROWSER_TDES_BUDGET_PEER")
                .expect("independent Go peer"),
        )
        .args([
            "--fixtures",
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures"),
            "--mode",
            if exact { "exact" } else { "partial" },
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap(),
    );
    let mut output = BufReader::new(peer.0.stdout.take().unwrap());
    let ready = report(&mut output);
    assert_eq!(ready["phase"], "ready", "{ready}");
    let port = u16::try_from(ready["port"].as_u64().unwrap()).unwrap();
    let socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(600)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(600)))
        .unwrap();
    (
        peer,
        output,
        TappedTcp {
            socket,
            sent: Witness::default(),
            received: Witness::default(),
        },
    )
}
fn fill(buffer: &mut [u8], offset: usize) {
    for (i, byte) in buffer.iter_mut().enumerate() {
        *byte = (((offset + i) * 17 + 3) % 251) as u8;
    }
}
fn hex(value: &[u8]) -> String {
    value.iter().map(|b| format!("{b:02x}")).collect()
}
fn exporter(secrets: &Secrets, socket: &TappedTcp) -> [u8; 32] {
    let guard = secrets.0.lock().unwrap();
    let (random, master) = guard.as_ref().unwrap();
    let mut seed = Vec::with_capacity(74);
    seed.extend_from_slice(random);
    seed.extend_from_slice(socket.received.server_random.as_ref().unwrap());
    seed.extend_from_slice(&(CONTEXT.len() as u16).to_be_bytes());
    seed.extend_from_slice(CONTEXT);
    let mut output = [0; 32];
    aerobox_crypto::legacy_tdes::TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
        .prf_provider
        .for_secret(&mut output, master, LABEL, &seed);
    output
}
fn check_io_error(error: io::Error) {
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(
        error.get_ref().unwrap().downcast_ref::<Error>(),
        Some(&Error::EncryptError)
    );
}
fn check_failure(result: Result<usize, EncryptError>, consumed: usize, written: usize) {
    match result {
        Err(EncryptError::EncryptFailed {
            error,
            plaintext_consumed,
            tls_bytes_written,
        }) => {
            assert_eq!(error, Error::EncryptError);
            assert_eq!(plaintext_consumed, consumed);
            assert_eq!(tls_bytes_written, written);
        }
        other => panic!("unexpected budget result: {other:?}"),
    }
}
fn drain(client: &mut ClientConnection, socket: &mut TappedTcp) {
    while client.wants_write() {
        assert!(client.write_tls(socket).unwrap() > 0);
    }
}
fn buffered_banner(client: &mut ClientConnection, socket: &mut TappedTcp) -> [u8; 36] {
    let mut banner = [0; 36];
    let mut n = 0;
    while n < banner.len() {
        match client.reader().read(&mut banner[n..]) {
            Ok(count) => {
                assert!(count > 0);
                n += count;
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                assert!(client.read_tls(socket).unwrap() > 0);
                client.process_new_packets().unwrap();
            }
            Err(err) => panic!("banner: {err}"),
        }
    }
    banner
}
fn finish(
    mut peer: Peer,
    output: &mut BufReader<ChildStdout>,
    socket: &mut TappedTcp,
    exact: bool,
    count: usize,
    hash: Sha256,
    expected_exporter: &[u8; 32],
) {
    assert!(socket.sent.record.is_empty());
    let blocks = if exact {
        MAX_BLOCKS
    } else {
        FINISHED_BLOCKS + FULL_RECORDS * FULL_BLOCKS
    };
    assert_eq!(socket.sent.blocks, blocks);
    assert_eq!(socket.sent.applications, FULL_RECORDS + usize::from(exact));
    assert_eq!(
        count,
        FULL_RECORDS * FULL + if exact { TAIL_PLAIN } else { 0 }
    );
    socket.socket.shutdown(Shutdown::Write).unwrap();
    let result = report(output);
    assert_eq!(result["phase"], "complete", "{result}");
    assert_eq!(result["plaintext_bytes"], count);
    assert_eq!(result["encrypted_blocks"], blocks);
    assert_eq!(result["application_records"], socket.sent.applications);
    assert_eq!(result["sha256"], hex(&hash.finalize()));
    assert_eq!(result["exporter"], hex(expected_exporter));
    assert_eq!(result["transport_truncation"], true);
    assert_eq!(result["close_notify_received"], false);
    assert_eq!(result["ems"], true);
    assert!(peer.0.wait().unwrap().success());
}

fn buffered(exact: bool) {
    let (peer, mut output, mut socket) = start(exact);
    let (config, secrets) = config();
    let mut client = ClientConnection::new(config, "localhost".try_into().unwrap()).unwrap();
    client.complete_io(&mut socket).unwrap();
    assert!(!client.is_handshaking());
    assert_eq!(client.protocol_version(), Some(ProtocolVersion::TLSv1_2));
    assert_eq!(client.peer_certificates().unwrap()[0].as_ref(), RSA_CERT);
    let banner = buffered_banner(&mut client, &mut socket);
    let expected = exporter(&secrets, &socket);
    assert_eq!(&banner[..4], b"ABBD");
    assert_eq!(&banner[4..], &expected);
    assert_eq!(
        client
            .export_keying_material([0; 32], LABEL, Some(CONTEXT))
            .unwrap(),
        expected
    );
    assert_eq!(socket.sent.blocks, FINISHED_BLOCKS);
    let mut data = [0; FULL * 4];
    let mut count = 0;
    let mut hash = Sha256::new();
    // Leave exactly one full record available to the multi-fragment partial write.
    for _ in 0..if exact {
        FULL_RECORDS
    } else {
        FULL_RECORDS - 1
    } {
        fill(&mut data[..FULL], count);
        assert_eq!(client.writer().write(&data[..FULL]).unwrap(), FULL);
        hash.update(&data[..FULL]);
        count += FULL;
        drain(&mut client, &mut socket);
    }
    if exact {
        fill(&mut data[..TAIL_PLAIN], count);
        assert_eq!(
            client.writer().write(&data[..TAIL_PLAIN]).unwrap(),
            TAIL_PLAIN
        );
        hash.update(&data[..TAIL_PLAIN]);
        count += TAIL_PLAIN;
        drain(&mut client, &mut socket);
        assert_eq!(
            socket.sent.blocks, MAX_BLOCKS,
            "last permitted block must be usable"
        );
        // CloseNotify itself is the first encryption attempted beyond the budget.
        client.send_close_notify();
        assert!(
            !client.wants_write(),
            "failed close cannot produce ciphertext or plaintext"
        );
        fill(&mut data, count);
        check_io_error(client.writer().write(&data).unwrap_err());
    } else {
        fill(&mut data, count);
        assert!(
            count + data.len() > MAX_BLOCKS * 8,
            "request exceeds real 8MiB budget"
        );
        let accepted = client
            .writer()
            .write_vectored(&[IoSlice::new(&data[..1000]), IoSlice::new(&data[1000..])])
            .unwrap();
        assert_eq!(accepted, FULL, "only one complete fragment was encrypted");
        hash.update(&data[..accepted]);
        count += accepted;
        drain(&mut client, &mut socket);
    }
    assert!(count + data.len() > MAX_BLOCKS * 8);
    for _ in 0..3 {
        check_io_error(
            client
                .writer()
                .write(b"must never reach the peer")
                .unwrap_err(),
        );
        check_io_error(client.writer().write(&[]).unwrap_err());
        check_io_error(client.writer().write_vectored(&[]).unwrap_err());
        check_io_error(client.writer().flush().unwrap_err());
        assert_eq!(
            client.process_new_packets().unwrap_err(),
            Error::EncryptError
        );
        let mut untouched = [0x77; 32];
        assert_eq!(
            client
                .export_keying_material(&mut untouched, LABEL, Some(CONTEXT))
                .unwrap_err(),
            Error::EncryptError
        );
        assert_eq!(untouched, [0x77; 32]);
        client.send_close_notify();
        assert!(!client.wants_write());
    }
    finish(
        peer,
        &mut output,
        &mut socket,
        exact,
        count,
        hash,
        &expected,
    );
}

fn unbuffered_banner(client: &mut UnbufferedClientConnection, socket: &mut TappedTcp) -> [u8; 36] {
    let mut incoming = Vec::new();
    let mut scratch = [0; 65536];
    let mut banner = Vec::new();
    for _ in 0..10000 {
        let status = client.process_tls_records(&mut incoming);
        let mut discard = status.discard;
        let mut read = false;
        let mut ready = false;
        match status.state.unwrap() {
            ConnectionState::EncodeTlsData(mut encode) => {
                let n = encode.encode(&mut scratch).unwrap();
                socket.write_all(&scratch[..n]).unwrap();
            }
            ConnectionState::TransmitTlsData(transmit) => transmit.done(),
            ConnectionState::ReadTraffic(mut traffic) => {
                while let Some(record) = traffic.next_record() {
                    let record = record.unwrap();
                    discard += record.discard;
                    assert!(banner.len() + record.payload.len() <= 36);
                    banner.extend_from_slice(record.payload);
                }
            }
            ConnectionState::BlockedHandshake => read = true,
            ConnectionState::WriteTraffic(_) => {
                if banner.len() == 36 {
                    ready = true;
                } else {
                    read = true;
                }
            }
            other => panic!("unexpected handshake state {other:?}"),
        }
        incoming.drain(..discard);
        if ready {
            assert!(incoming.is_empty());
            return banner.try_into().unwrap();
        }
        if read {
            let n = socket.read(&mut scratch[..16384]).unwrap();
            assert!(n > 0 && incoming.len() + n <= 65536);
            incoming.extend_from_slice(&scratch[..n]);
        }
    }
    panic!("handshake made no progress");
}
fn unbuffered(exact: bool) {
    let (peer, mut output, mut socket) = start(exact);
    let (config, secrets) = config();
    let mut client =
        UnbufferedClientConnection::new(config, "localhost".try_into().unwrap()).unwrap();
    let banner = unbuffered_banner(&mut client, &mut socket);
    assert!(!client.is_handshaking());
    assert_eq!(client.peer_certificates().unwrap()[0].as_ref(), RSA_CERT);
    let expected = exporter(&secrets, &socket);
    assert_eq!(&banner[..4], b"ABBD");
    assert_eq!(&banner[4..], &expected);
    assert_eq!(socket.sent.blocks, FINISHED_BLOCKS);
    let mut data = [0; FULL * 3];
    let mut wire = [0x77; 65536];
    let mut count = 0;
    let mut hash = Sha256::new();
    let status = client.process_tls_records(&mut []);
    assert_eq!(status.discard, 0);
    if let ConnectionState::WriteTraffic(mut writer) = status.state.unwrap() {
        for _ in 0..if exact {
            FULL_RECORDS
        } else {
            FULL_RECORDS - 1
        } {
            fill(&mut data[..FULL], count);
            let written = writer.encrypt(&data[..FULL], &mut wire).unwrap();
            assert_eq!(written, 5 + 8 + FULL_BLOCKS * 8);
            socket.write_all(&wire[..written]).unwrap();
            hash.update(&data[..FULL]);
            count += FULL;
        }
        if exact {
            fill(&mut data[..TAIL_PLAIN], count);
            let written = writer.encrypt(&data[..TAIL_PLAIN], &mut wire).unwrap();
            assert_eq!(written, 5 + 8 + TAIL_BLOCKS * 8);
            socket.write_all(&wire[..written]).unwrap();
            hash.update(&data[..TAIL_PLAIN]);
            count += TAIL_PLAIN;
            assert_eq!(socket.sent.blocks, MAX_BLOCKS);
            wire.fill(0x77);
            check_failure(writer.queue_close_notify(&mut wire), 0, 0);
            assert!(wire.iter().all(|byte| *byte == 0));
        } else {
            fill(&mut data, count);
            assert!(count + data.len() > MAX_BLOCKS * 8);
            wire.fill(0x77);
            let prefix = 5 + 8 + FULL_BLOCKS * 8;
            check_failure(writer.encrypt(&data, &mut wire), FULL, prefix);
            assert!(wire[prefix..].iter().all(|byte| *byte == 0));
            socket.write_all(&wire[..prefix]).unwrap();
            hash.update(&data[..FULL]);
            count += FULL;
        }
        assert!(count + data.len() > MAX_BLOCKS * 8);
        for _ in 0..3 {
            wire.fill(0x77);
            check_failure(writer.encrypt(&data, &mut wire), 0, 0);
            assert!(wire.iter().all(|byte| *byte == 0));
            wire.fill(0x77);
            check_failure(writer.encrypt(&[], &mut wire), 0, 0);
            assert!(wire.iter().all(|byte| *byte == 0));
            wire.fill(0x77);
            check_failure(writer.queue_close_notify(&mut wire), 0, 0);
            assert!(wire.iter().all(|byte| *byte == 0));
        }
    } else {
        panic!("expected ready writer");
    }
    for _ in 0..3 {
        let status = client.process_tls_records(&mut []);
        assert_eq!(status.discard, 0);
        assert!(matches!(status.state, Err(Error::EncryptError)));
    }
    finish(
        peer,
        &mut output,
        &mut socket,
        exact,
        count,
        hash,
        &expected,
    );
}

#[test]
#[ignore = "independent Go peer and real 8MiB budget; parent runs serially"]
fn buffered_real_3des_budget_partial_and_exact() {
    buffered(false);
    buffered(true);
}

#[test]
#[ignore = "independent Go peer and real 8MiB budget; parent runs serially"]
fn unbuffered_real_3des_budget_partial_and_exact() {
    unbuffered(false);
    unbuffered(true);
}
