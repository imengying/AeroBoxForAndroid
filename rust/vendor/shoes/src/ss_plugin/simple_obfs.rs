//! A bounded streaming implementation of the simple-obfs wire format.
//! The TLS-looking records are a transport disguise, not a TLS connection.
use super::{ObfsMode, invalid};
use crate::async_stream::{AsyncPing, AsyncStream};
use base64::{Engine, engine::general_purpose::URL_SAFE};
use rand::{Rng, RngExt};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, BufReader, ReadBuf};

const CHUNK: usize = 16 * 1024;
const MAX_HTTP_HEADER: usize = 16 * 1024;

pub(super) struct Stream {
    inner: BufReader<Box<dyn AsyncStream>>,
    mode: ObfsMode,
    host: String,
    port: u16,
    first_write: bool,
    pending_write: Vec<u8>,
    written: usize,
    // HTTP: 0 = response header, 1 = raw. TLS: 0 = ServerHello,
    // 1 = ChangeCipherSpec, 2 = first payload, 3 = subsequent payloads.
    read_phase: u8,
    read_header: Vec<u8>,
    remaining: usize,
    eof: bool,
    shutdown: bool,
}

impl Stream {
    pub(super) fn new(
        inner: Box<dyn AsyncStream>,
        mode: ObfsMode,
        host: String,
        port: u16,
    ) -> Self {
        Self {
            inner: BufReader::new(inner),
            mode,
            host,
            port,
            first_write: true,
            pending_write: Vec::new(),
            written: 0,
            read_phase: 0,
            read_header: Vec::new(),
            remaining: 0,
            eof: false,
            shutdown: false,
        }
    }

    fn drain_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.written < self.pending_write.len() {
            let n = ready!(
                Pin::new(&mut self.inner).poll_write(cx, &self.pending_write[self.written..])
            )?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.written += n;
        }
        self.pending_write.clear();
        self.written = 0;
        Poll::Ready(Ok(()))
    }

    fn queue_write(&mut self, bytes: &[u8]) {
        match (self.mode, self.first_write) {
            (ObfsMode::Http, true) => {
                let mut rng = rand::rng();
                let key = URL_SAFE.encode(rng.random::<[u8; 16]>());
                let host = if self.port == 80 {
                    self.host.clone()
                } else {
                    format!("{}:{}", self.host, self.port)
                };
                self.pending_write.extend_from_slice(format!(
                    "GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: curl/7.{}.{}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: {key}\r\nContent-Length: {}\r\n\r\n",
                    rng.random_range(0..54), rng.random_range(0..2), bytes.len(),
                ).as_bytes());
                self.pending_write.extend_from_slice(bytes);
            }
            (ObfsMode::Http, false) => self.pending_write.extend_from_slice(bytes),
            (ObfsMode::Tls, true) => self.pending_write = client_hello(&self.host, bytes),
            (ObfsMode::Tls, false) => {
                self.pending_write.extend_from_slice(&[23, 3, 3]);
                put_u16(&mut self.pending_write, bytes.len());
                self.pending_write.extend_from_slice(bytes);
            }
        }
        self.first_write = false;
    }

    fn read_http(&mut self, cx: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if self.read_phase == 1 {
            return Pin::new(&mut self.inner).poll_read(cx, out);
        }
        // BufReader preserves any payload delivered alongside the response.
        for _ in 0..256 {
            let available = ready!(Pin::new(&mut self.inner).poll_fill_buf(cx))?;
            if available.is_empty() {
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
            let mut consumed = 0;
            for &byte in available {
                if self.read_header.len() == MAX_HTTP_HEADER {
                    return Poll::Ready(Err(invalid("simple-obfs HTTP header exceeds 16 KiB")));
                }
                self.read_header.push(byte);
                consumed += 1;
                if self.read_header.ends_with(b"\r\n\r\n") {
                    self.read_phase = 1;
                    break;
                }
            }
            Pin::new(&mut self.inner).consume(consumed);
            if self.read_phase == 1 {
                let mut headers = [httparse::EMPTY_HEADER; 64];
                let mut response = httparse::Response::new(&mut headers);
                response
                    .parse(&self.read_header)
                    .map_err(io::Error::other)?;
                if response.code != Some(101) {
                    return Poll::Ready(Err(invalid("simple-obfs HTTP response rejected")));
                }
                self.read_header.clear();
                return Pin::new(&mut self.inner).poll_read(cx, out);
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn read_tls(&mut self, cx: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        for _ in 0..256 {
            let available = ready!(Pin::new(&mut self.inner).poll_fill_buf(cx))?;
            if available.is_empty() {
                if self.read_phase == 3 && self.remaining == 0 && self.read_header.is_empty() {
                    self.eof = true;
                    return Poll::Ready(Ok(()));
                }
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
            if self.remaining != 0 {
                let delivers = self.read_phase >= 2;
                let limit = if delivers {
                    out.remaining()
                } else {
                    usize::MAX
                };
                let count = available.len().min(self.remaining).min(limit);
                if delivers {
                    out.put_slice(&available[..count]);
                }
                if self.read_phase == 1 && available[0] != 1 {
                    return Poll::Ready(Err(invalid("invalid simple-obfs change cipher spec")));
                }
                Pin::new(&mut self.inner).consume(count);
                self.remaining -= count;
                if self.remaining == 0 {
                    self.read_phase = (self.read_phase + 1).min(3);
                }
                if delivers {
                    return Poll::Ready(Ok(()));
                }
                continue;
            }
            let count = available.len().min(5 - self.read_header.len());
            self.read_header.extend_from_slice(&available[..count]);
            Pin::new(&mut self.inner).consume(count);
            if self.read_header.len() != 5 {
                continue;
            }
            let header = &self.read_header;
            let len = u16::from_be_bytes([header[3], header[4]]) as usize;
            let expected_type = match self.read_phase {
                0 | 2 => 22,
                1 => 20,
                _ => 23,
            };
            let version_ok =
                header[1] == 3 && (header[2] == 3 || self.read_phase == 0 && header[2] == 1);
            if header[0] != expected_type
                || !version_ok
                || self.read_phase == 0 && len != 91
                || self.read_phase == 1 && len != 1
                || self.read_phase == 3 && len > CHUNK
            {
                return Poll::Ready(Err(invalid("invalid simple-obfs TLS record")));
            }
            self.read_header.clear();
            self.remaining = len;
            if len == 0 {
                self.read_phase = (self.read_phase + 1).min(3);
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if out.remaining() == 0 || this.eof {
            return Poll::Ready(Ok(()));
        }
        match this.mode {
            ObfsMode::Http => this.read_http(cx, out),
            ObfsMode::Tls => this.read_tls(cx, out),
        }
    }
}
impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.shutdown {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        ready!(this.drain_write(cx))?;
        let count = bytes.len().min(CHUNK);
        this.queue_write(&bytes[..count]);
        // Accept one bounded frame. Flush or the next write drains it without
        // requiring the caller to keep the original slice alive.
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.drain_write(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.drain_write(cx))?;
        ready!(Pin::new(&mut this.inner).poll_flush(cx))?;
        ready!(Pin::new(&mut this.inner).poll_shutdown(cx))?;
        this.shutdown = true;
        Poll::Ready(Ok(()))
    }
}
impl AsyncPing for Stream {
    fn supports_ping(&self) -> bool {
        false
    }
    fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}
impl AsyncStream for Stream {
    fn tcp_socket_control(&self) -> std::io::Result<Option<crate::tcp::socket_control::TcpSocketControl>> {
        self.inner.get_ref().tcp_socket_control()
    }

    fn local_addr(&self) -> Option<std::net::SocketAddr> {
        self.inner.get_ref().local_addr()
    }
    fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        self.inner.get_ref().peer_addr()
    }
    fn flow(&self) -> Option<&std::sync::Arc<crate::control::flows::FlowEntry>> {
        self.inner.get_ref().flow()
    }
}

fn put_u16(out: &mut Vec<u8>, value: usize) {
    out.extend_from_slice(&(value as u16).to_be_bytes());
}
fn extension(out: &mut Vec<u8>, id: u16, payload: &[u8]) {
    out.extend_from_slice(&id.to_be_bytes());
    put_u16(out, payload.len());
    out.extend_from_slice(payload);
}

fn client_hello(host: &str, payload: &[u8]) -> Vec<u8> {
    // TLS structure is encoded field by field. The ticket contains the first
    // Shadowsocks bytes and is deliberately the first extension on the wire.
    let mut hello = vec![22, 3, 1, 0, 0, 1, 0, 0, 0, 3, 3];
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    hello.extend_from_slice(&timestamp.to_be_bytes());
    let mut random = [0; 60];
    rand::rng().fill_bytes(&mut random);
    hello.extend_from_slice(&random[..28]);
    hello.push(32);
    hello.extend_from_slice(&random[28..]);
    let suites: [u16; 28] = [
        0xc02c, 0xc030, 0x009f, 0xcca9, 0xcca8, 0xccaa, 0xc02b, 0xc02f, 0x009e, 0xc024, 0xc028,
        0x006b, 0xc023, 0xc027, 0x0067, 0xc00a, 0xc014, 0x0039, 0xc009, 0xc013, 0x0033, 0x009d,
        0x009c, 0x003d, 0x003c, 0x0035, 0x002f, 0x00ff,
    ];
    put_u16(&mut hello, suites.len() * 2);
    for suite in suites {
        hello.extend_from_slice(&suite.to_be_bytes());
    }
    hello.extend_from_slice(&[1, 0]);
    let extensions_at = hello.len();
    put_u16(&mut hello, 0);
    extension(&mut hello, 35, payload);
    let mut sni = Vec::new();
    put_u16(&mut sni, host.len() + 3);
    sni.push(0);
    put_u16(&mut sni, host.len());
    sni.extend_from_slice(host.as_bytes());
    extension(&mut hello, 0, &sni);
    extension(&mut hello, 11, &[3, 1, 0, 2]);
    extension(&mut hello, 10, &[0, 8, 0, 29, 0, 23, 0, 25, 0, 24]);
    let mut signatures = vec![0, 30];
    for hash in (2..=6).rev() {
        for key_type in 1..=3 {
            signatures.extend_from_slice(&[hash, key_type]);
        }
    }
    extension(&mut hello, 13, &signatures);
    extension(&mut hello, 22, &[]);
    extension(&mut hello, 23, &[]);
    let record_len = (hello.len() - 5) as u16;
    let handshake_len = (hello.len() - 9) as u16;
    let extensions_len = (hello.len() - extensions_at - 2) as u16;
    hello[3..5].copy_from_slice(&record_len.to_be_bytes());
    hello[7..9].copy_from_slice(&handshake_len.to_be_bytes());
    hello[extensions_at..extensions_at + 2].copy_from_slice(&extensions_len.to_be_bytes());
    hello
}
