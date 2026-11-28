//! The production async wrapper must retain partial-write accounting and flush
//! complete accepted TLS records after the real cipher's block budget expires.
use super::*;
use futures::future::poll_fn;
use std::{
    io::{BufRead, BufReader, Read as _},
    process::{Child, Command, Stdio},
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const FULL: usize = 16384;
const FULL_BLOCKS: usize = 2051;
const MAX_BLOCKS: usize = 1 << 20;
const FINISHED_BLOCKS: usize = 5;
const FULL_RECORDS: usize = (MAX_BLOCKS - FINISHED_BLOCKS) / FULL_BLOCKS;
const TAIL: usize = (MAX_BLOCKS - FINISHED_BLOCKS - FULL_RECORDS * FULL_BLOCKS) * 8 - 21;
const FIXTURES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../crates/aerobox-crypto/tests/fixtures"
);

struct Peer(Child);
impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

// Gate only application writes after authentication. This makes backpressure
// deterministic without assuming the kernel's socket-buffer capacity.
struct Gate {
    socket: tokio::net::TcpStream,
    open: bool,
}
impl AsyncRead for Gate {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket).poll_read(cx, buf)
    }
}
impl AsyncWrite for Gate {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.open {
            Pin::new(&mut self.socket).poll_write(cx, data)
        } else {
            // The test opens this gate before driving any awaited operation.
            Poll::Pending
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket).poll_shutdown(cx)
    }
}
impl AsyncPing for Gate {
    fn supports_ping(&self) -> bool {
        false
    }
    fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}
impl AsyncStream for Gate {}

#[derive(Debug)]
struct FixedTime;
impl rustls::time_provider::TimeProvider for FixedTime {
    fn current_time(&self) -> Option<rustls::pki_types::UnixTime> {
        Some(rustls::pki_types::UnixTime::since_unix_epoch(
            Duration::from_secs(1893456000),
        ))
    }
}

fn pattern(buffer: &mut [u8], offset: usize) {
    for (i, byte) in buffer.iter_mut().enumerate() {
        *byte = (((offset + i) * 17 + 3) % 251) as u8;
    }
}
fn budget_error(error: io::Error) {
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(
        error
            .get_ref()
            .and_then(|e| e.downcast_ref::<rustls::Error>()),
        Some(&rustls::Error::EncryptError)
    );
}

async fn exercise(exact: bool, vectored: bool, backpressure: bool) {
    let mut peer = Peer(
        Command::new(std::env::var_os("AEROBOX_ANDROID_BROWSER_TDES_BUDGET_PEER").unwrap())
            .args([
                "--fixtures",
                FIXTURES,
                "--mode",
                if exact { "exact" } else { "partial" },
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let mut output = BufReader::new(peer.0.stdout.take().unwrap());
    let mut line = String::new();
    output.by_ref().take(65537).read_line(&mut line).unwrap();
    assert!(line.len() <= 65536 && line.ends_with('\n'));
    let ready: serde_json::Value = serde_json::from_str(&line).unwrap();
    let socket = tokio::net::TcpStream::connect((
        "127.0.0.1",
        u16::try_from(ready["port"].as_u64().unwrap()).unwrap(),
    ))
    .await
    .unwrap();
    let mut provider = aerobox_crypto::provider();
    provider.cipher_suites = aerobox_crypto::legacy_tdes::suites()
        .into_iter()
        .filter(|suite| u16::from(suite.suite()) == 0xc012)
        .collect();
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(
            std::fs::read(format!("{FIXTURES}/rsa-cert.der"))
                .unwrap()
                .into(),
        )
        .unwrap();
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.time_provider = Arc::new(FixedTime);
    let connection =
        rustls::ClientConnection::new(Arc::new(config), "localhost".try_into().unwrap()).unwrap();
    let mut stream = CryptoTlsStream::handshake(
        Gate { socket, open: true },
        TlsConnection::new(connection),
        TlsReadMode::Stream,
        &[],
    )
    .await
    .unwrap();
    let mut banner = [0; 36];
    stream.read_exact(&mut banner).await.unwrap();
    assert_eq!(&banner[..4], b"ABBD");
    let mut data = [0; FULL * 3];
    let mut count = 0;
    for _ in 0..if exact {
        FULL_RECORDS
    } else {
        FULL_RECORDS - 1
    } {
        pattern(&mut data[..FULL], count);
        stream.write_all(&data[..FULL]).await.unwrap();
        count += FULL;
        stream.flush().await.unwrap();
    }
    if exact {
        pattern(&mut data[..TAIL], count);
        stream.write_all(&data[..TAIL]).await.unwrap();
        count += TAIL;
        stream.flush().await.unwrap();
        budget_error(stream.shutdown().await.unwrap_err());
    } else {
        pattern(&mut data, count);
        stream.io.open = !backpressure;
        let accepted = if vectored {
            stream
                .write_vectored(&[io::IoSlice::new(&data[..23]), io::IoSlice::new(&data[23..])])
                .await
                .unwrap()
        } else {
            stream.write(&data).await.unwrap()
        };
        assert_eq!(
            accepted, FULL,
            "count the one complete record before budget failure"
        );
        count += accepted;
        if backpressure {
            assert!(
                stream.session.wants_write(),
                "accepted record remains queued"
            );
            stream.io.open = true;
        }
        budget_error(stream.flush().await.unwrap_err());
        assert!(
            !stream.session.wants_write(),
            "flush handed the successful prefix to the transport"
        );
        for _ in 0..2 {
            budget_error(stream.write(&data).await.unwrap_err());
            budget_error(stream.write(&[]).await.unwrap_err());
            budget_error(
                stream
                    .write_vectored(&[io::IoSlice::new(&[])])
                    .await
                    .unwrap_err(),
            );
            budget_error(stream.flush().await.unwrap_err());
        }
    }
    poll_fn(|cx| stream.poll_drain_tls(cx)).await.unwrap();
    assert!(!stream.session.wants_write());
    stream.io.socket.shutdown().await.unwrap();
    drop(stream);
    let (mut peer, result) = tokio::task::spawn_blocking(move || {
        let mut line = String::new();
        output.by_ref().take(65537).read_line(&mut line).unwrap();
        assert!(line.len() <= 65536 && line.ends_with('\n'));
        (
            peer,
            serde_json::from_str::<serde_json::Value>(&line).unwrap(),
        )
    })
    .await
    .unwrap();
    assert_eq!(result["phase"], "complete", "{result}");
    assert_eq!(result["plaintext_bytes"], count);
    assert_eq!(
        result["encrypted_blocks"],
        if exact {
            MAX_BLOCKS
        } else {
            FINISHED_BLOCKS + FULL_RECORDS * FULL_BLOCKS
        }
    );
    assert_eq!(result["close_notify_received"], false);
    assert_eq!(result["transport_truncation"], true);
    assert!(peer.0.wait().unwrap().success());
}

#[tokio::test]
#[ignore = "requires independent Go 3DES budget peer; four real 8MiB streams"]
async fn production_stream_preserves_partial_plaintext_and_drains_cipher_budget_failures() {
    for (exact, vectored, blocked) in [
        (false, false, false),
        (false, false, true),
        (false, true, true),
        (true, false, false),
    ] {
        tokio::time::timeout(Duration::from_secs(600), exercise(exact, vectored, blocked))
            .await
            .unwrap();
    }
}
