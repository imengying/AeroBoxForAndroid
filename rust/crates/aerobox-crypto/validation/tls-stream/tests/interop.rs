use aerobox_tls_stream_validation::{
    CryptoTlsStream, TlsConnection, TlsReadMode,
    async_stream::{AsyncPing, AsyncStream},
    config,
};
use std::{
    io::{BufRead, BufReader},
    pin::Pin,
    process::{Child, Command, Stdio},
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
struct Peer(Child);
impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
async fn peer(mode: &str) -> (Peer, tokio::net::TcpStream) {
    let mut child = Command::new(std::env::var_os("AEROBOX_TLS12_RENEGOTIATION_PEER").unwrap())
        .args([
            "-fixtures",
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures"),
            "-mode",
            mode,
            "-mutual",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut s = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut s)
        .unwrap();
    let v: serde_json::Value = serde_json::from_str(&s).unwrap();
    let socket = tokio::net::TcpStream::connect(("127.0.0.1", v["port"].as_u64().unwrap() as u16))
        .await
        .unwrap();
    (Peer(child), socket)
}
// Short transport writes/reads and one readiness delay per direction stress
// cancellation without allocating a second copy of the TLS stream.
struct Chopped {
    socket: tokio::net::TcpStream,
    read_pending: bool,
    write_pending: bool,
}
impl AsyncRead for Chopped {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.read_pending {
            self.read_pending = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        self.read_pending = true;
        let mut small = [0; 13];
        let mut b = ReadBuf::new(&mut small[..13.min(buf.remaining())]);
        match Pin::new(&mut self.socket).poll_read(cx, &mut b) {
            Poll::Ready(Ok(())) => {
                buf.put_slice(b.filled());
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}
impl AsyncWrite for Chopped {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.write_pending {
            self.write_pending = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        self.write_pending = true;
        Pin::new(&mut self.socket).poll_write(cx, &buf[..buf.len().min(17)])
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.socket).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.socket).poll_shutdown(cx)
    }
}
impl AsyncPing for Chopped {
    fn supports_ping(&self) -> bool {
        false
    }
    fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}
impl AsyncStream for Chopped {}
#[tokio::test(flavor = "current_thread")]
async fn production_async_tls_drives_renegotiation_with_fragmentation_and_read_cancellation() {
    for records in [false, true] {
        for mode in [
            "valid",
            "inflight",
            "fragment",
            "bad-finished",
            "early-data",
        ] {
            tokio::time::timeout(Duration::from_secs(15), async {
                let (_peer, socket) = peer(mode).await;
                let client = rustls::ClientConnection::new(
                    Arc::new(config(true, true, true)),
                    "localhost".try_into().unwrap(),
                )
                .unwrap();
                let io = Chopped {
                    socket,
                    read_pending: true,
                    write_pending: true,
                };
                let mut stream = CryptoTlsStream::handshake(
                    io,
                    TlsConnection::new(client),
                    if records {
                        TlsReadMode::PreserveRecords
                    } else {
                        TlsReadMode::Stream
                    },
                    &[],
                )
                .await
                .unwrap();
                let mut initial = [0; 39];
                stream.read_exact(&mut initial).await.unwrap();
                assert_eq!(&initial[..7], b"initial");
                stream.write_all(b"ack").await.unwrap();
                stream.flush().await.unwrap();
                if mode == "inflight" {
                    let mut bytes = [0; 8];
                    stream.read_exact(&mut bytes).await.unwrap();
                    assert_eq!(&bytes, b"old-data");
                }
                // Drop repeated pending reads while the handshake progresses. Exact byte
                // consumption stays owned by the stream across all retries.
                let mut output = vec![];
                for _ in 0..80 {
                    let mut one = [0];
                    let mut b = ReadBuf::new(&mut one);
                    let attempt = futures::future::poll_fn(|cx| {
                        Poll::Ready(Pin::new(&mut stream).poll_read(cx, &mut b))
                    })
                    .await;
                    match attempt {
                        Poll::Ready(Ok(())) => output.extend_from_slice(b.filled()),
                        Poll::Ready(Err(error)) => {
                            assert!(mode == "bad-finished" || mode == "early-data", "{error}");
                            assert!(output.is_empty());
                            return;
                        }
                        Poll::Pending => {}
                    }
                    if output.len() == 39 {
                        break;
                    }
                }
                let mut remaining = vec![0; 39 - output.len()];
                let result = stream.read_exact(&mut remaining).await;
                if mode == "bad-finished" || mode == "early-data" {
                    assert!(result.is_err());
                    assert!(output.is_empty());
                    return;
                }
                result.unwrap();
                output.extend_from_slice(&remaining);
                assert_eq!(&output[..7], b"renewed");
                assert_ne!(&initial[7..], &output[7..]);
                let data: Vec<_> = (0..65537).map(|i| (i % 251) as u8).collect();
                stream.write_all(&data).await.unwrap();
                stream.flush().await.unwrap();
                let mut out = vec![0; data.len()];
                stream.read_exact(&mut out).await.unwrap();
                assert_eq!(data, out);
                stream.shutdown().await.unwrap();
                assert_eq!(stream.read(&mut [0]).await.unwrap(), 0);
            })
            .await
            .unwrap_or_else(|_| {
                panic!("async renegotiation stalled: records={records} mode={mode}")
            });
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn writer_drives_renegotiation_and_cancelled_writer_leaves_reader_progress() {
    for records in [false, true] {
        for cancel in [false, true] {
            tokio::time::timeout(Duration::from_secs(15), async {
                let (_peer, socket) = peer("valid").await;
                let client = rustls::ClientConnection::new(
                    Arc::new(config(true, true, true)),
                    "localhost".try_into().unwrap(),
                )
                .unwrap();
                let io = Chopped {
                    socket,
                    read_pending: true,
                    write_pending: true,
                };
                let mut stream = CryptoTlsStream::handshake(
                    io,
                    TlsConnection::new(client),
                    if records {
                        TlsReadMode::PreserveRecords
                    } else {
                        TlsReadMode::Stream
                    },
                    &[],
                )
                .await
                .unwrap();
                let mut initial = [0; 39];
                stream.read_exact(&mut initial).await.unwrap();
                stream.write_all(b"ack").await.unwrap();
                stream.flush().await.unwrap();
                while !aerobox_tls_stream_validation::handshaking(&stream) {
                    let mut one = [0];
                    let mut buf = ReadBuf::new(&mut one);
                    let polled = futures::future::poll_fn(|cx| {
                        Poll::Ready(Pin::new(&mut stream).poll_read(cx, &mut buf))
                    })
                    .await;
                    assert!(matches!(polled, Poll::Pending));
                    assert!(buf.filled().is_empty());
                    tokio::task::yield_now().await;
                }
                let data = vec![73; 65537];
                if cancel {
                    let polled = futures::future::poll_fn(|cx| {
                        Poll::Ready(Pin::new(&mut stream).poll_write(cx, &data))
                    })
                    .await;
                    assert!(
                        polled.is_pending(),
                        "the short-write carrier must suspend during ClientHello"
                    );
                    let mut renewed = [0; 39];
                    stream.read_exact(&mut renewed).await.unwrap();
                    assert_eq!(&renewed[..7], b"renewed");
                    stream.write_all(&data).await.unwrap();
                    stream.flush().await.unwrap();
                } else {
                    stream.write_all(&data).await.unwrap();
                    stream.flush().await.unwrap();
                    let mut renewed = [0; 39];
                    stream.read_exact(&mut renewed).await.unwrap();
                    assert_eq!(&renewed[..7], b"renewed");
                }
                let mut echoed = vec![0; data.len()];
                stream.read_exact(&mut echoed).await.unwrap();
                assert_eq!(echoed, data);
                stream.shutdown().await.unwrap();
            })
            .await
            .unwrap_or_else(|_| panic!("writer stalled: records={records} cancel={cancel}"));
        }
    }
}
