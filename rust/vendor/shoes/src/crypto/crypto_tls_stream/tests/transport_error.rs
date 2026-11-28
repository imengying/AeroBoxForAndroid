//! The async Write contract counts plaintext accepted before transport failure.
use super::*;
use std::error::Error as _;
use std::io::Read as _;

#[derive(Clone, Copy, Debug)]
enum Failure {
    BrokenPipe,
    Zero,
}

#[derive(Default)]
struct IoState {
    output: Vec<u8>,
    write_polls: usize,
    flush_polls: usize,
    shutdown_polls: usize,
    ping_polls: usize,
    block: bool,
    short: Option<usize>,
    failure: Option<Failure>,
    fail_flush: bool,
}
struct ControlledIo(Arc<Mutex<IoState>>);
impl AsyncRead for ControlledIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}
impl AsyncWrite for ControlledIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut state = self.0.lock().unwrap();
        state.write_polls += 1;
        if state.block {
            return Poll::Pending;
        }
        if let Some(limit) = state.short.take() {
            let n = data.len().min(limit);
            state.output.extend_from_slice(&data[..n]);
            return Poll::Ready(Ok(n));
        }
        match state.failure {
            Some(Failure::BrokenPipe) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "fixture broken pipe after short write",
            ))),
            Some(Failure::Zero) => Poll::Ready(Ok(0)),
            None => {
                state.output.extend_from_slice(data);
                Poll::Ready(Ok(data.len()))
            }
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self.0.lock().unwrap();
        state.flush_polls += 1;
        if state.fail_flush {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "fixture flush reset",
            )))
        } else {
            Poll::Ready(Ok(()))
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.lock().unwrap().shutdown_polls += 1;
        Poll::Ready(Ok(()))
    }
}
impl AsyncPing for ControlledIo {
    fn supports_ping(&self) -> bool {
        true
    }
    fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> {
        self.0.lock().unwrap().ping_polls += 1;
        Poll::Ready(Ok(true))
    }
}
impl AsyncStream for ControlledIo {}

fn assert_error<T: std::fmt::Debug>(
    result: Poll<io::Result<T>>,
    kind: io::ErrorKind,
    message: &str,
) {
    match result {
        Poll::Ready(Err(error)) => {
            assert_eq!(error.kind(), kind);
            assert_eq!(error.to_string(), message);
            let original = error
                .get_ref()
                .unwrap()
                .source()
                .unwrap()
                .downcast_ref::<io::Error>()
                .unwrap();
            assert_eq!(original.kind(), kind);
            assert_eq!(original.to_string(), message);
        }
        other => panic!("expected permanent transport error, got {other:?}"),
    }
}
fn counters(state: &Arc<Mutex<IoState>>) -> (usize, usize, usize, usize, usize) {
    let s = state.lock().unwrap();
    (
        s.write_polls,
        s.flush_polls,
        s.shutdown_polls,
        s.ping_polls,
        s.output.len(),
    )
}
fn rejected_operations(
    stream: &mut CryptoTlsStream<ControlledIo>,
    state: &Arc<Mutex<IoState>>,
    cx: &mut Context<'_>,
    kind: io::ErrorKind,
    message: &str,
) {
    let before = counters(state);
    for _ in 0..3 {
        assert_error(
            Pin::new(&mut *stream).poll_write(cx, b"new secret must not be encrypted"),
            kind,
            message,
        );
        assert_error(Pin::new(&mut *stream).poll_write(cx, &[]), kind, message);
        assert_error(
            Pin::new(&mut *stream).poll_write_vectored(cx, &[io::IoSlice::new(b"secret")]),
            kind,
            message,
        );
        assert_error(
            Pin::new(&mut *stream).poll_write_vectored(cx, &[]),
            kind,
            message,
        );
        assert_error(Pin::new(&mut *stream).poll_flush(cx), kind, message);
        assert_error(Pin::new(&mut *stream).poll_shutdown(cx), kind, message);
        assert_error(stream.poll_drain_tls(cx), kind, message);
        assert_error(Pin::new(&mut *stream).poll_write_ping(cx), kind, message);
        let error = stream.start_raw_write(b"").unwrap_err();
        assert_eq!(error.kind(), kind);
        assert_eq!(error.to_string(), message);
    }
    assert_eq!(
        counters(state),
        before,
        "failed writes must not touch the underlying transport again"
    );
}
fn endpoints(reality: bool) -> (TlsConnection, TlsConnection) {
    if reality {
        crate::reality::established_pair()
    } else {
        completed_ordinary_connections()
    }
}

#[test]
fn accepted_prefix_survives_short_transport_write_then_broken_pipe_or_zero() {
    for reality in [false, true] {
        for vectored in [false, true] {
            for failure in [Failure::BrokenPipe, Failure::Zero] {
                let (session, mut peer) = endpoints(reality);
                let state = Arc::new(Mutex::new(IoState {
                    short: Some(7),
                    failure: Some(failure),
                    ..Default::default()
                }));
                let mut stream = CryptoTlsStream::new(ControlledIo(state.clone()), session, None);
                let mut cx = Context::from_waker(noop_waker_ref());
                let payload = [0x53; 4096];
                let accepted = if vectored {
                    Pin::new(&mut stream).poll_write_vectored(
                        &mut cx,
                        &[
                            io::IoSlice::new(&payload[..37]),
                            io::IoSlice::new(&payload[37..]),
                        ],
                    )
                } else {
                    Pin::new(&mut stream).poll_write(&mut cx, &payload)
                };
                let expected = if reality && vectored {
                    37
                } else {
                    payload.len()
                };
                assert!(
                    matches!(accepted,Poll::Ready(Ok(n)) if n==expected),
                    "{accepted:?}"
                );
                let (kind, message) = match failure {
                    Failure::BrokenPipe => (
                        io::ErrorKind::BrokenPipe,
                        "fixture broken pipe after short write".to_owned(),
                    ),
                    Failure::Zero => (
                        io::ErrorKind::WriteZero,
                        io::Error::from(io::ErrorKind::WriteZero).to_string(),
                    ),
                };
                assert_eq!(state.lock().unwrap().output.len(), 7);
                assert_eq!(state.lock().unwrap().write_polls, 2);
                assert!(stream.session.wants_write());
                rejected_operations(&mut stream, &state, &mut cx, kind, &message);
                // Reconstruct the already accepted TLS record in the test only.
                // Peer decryption proves no rejected plaintext was encrypted later.
                let mut wire = state.lock().unwrap().output.clone();
                while stream.session.wants_write() {
                    assert!(stream.session.write_tls(&mut wire).unwrap() > 0);
                }
                peer.feed(&wire).unwrap();
                let mut received = vec![0; expected];
                peer.reader().read_exact(&mut received).unwrap();
                assert_eq!(received, &payload[..expected]);
                assert_eq!(
                    peer.reader().read(&mut [0]).unwrap_err().kind(),
                    io::ErrorKind::WouldBlock
                );
            }
        }
    }
}

#[test]
fn transport_failure_before_acceptance_does_not_claim_or_encrypt_more_plaintext() {
    for vectored in [false, true] {
        let (session, mut peer) = completed_ordinary_connections();
        let state = Arc::new(Mutex::new(IoState {
            block: true,
            ..Default::default()
        }));
        let mut stream = CryptoTlsStream::new(ControlledIo(state.clone()), session, None);
        let mut cx = Context::from_waker(noop_waker_ref());
        let payload = [0x71; 16384];
        let mut accepted = 0;
        loop {
            match Pin::new(&mut stream).poll_write(&mut cx, &payload) {
                Poll::Ready(Ok(n)) => accepted += n,
                Poll::Pending => break,
                other => panic!("unexpected prefill {other:?}"),
            }
            assert!(accepted <= 65536);
        }
        {
            let mut s = state.lock().unwrap();
            s.block = false;
            s.failure = Some(Failure::BrokenPipe);
        }
        let result = if vectored {
            Pin::new(&mut stream).poll_write_vectored(&mut cx, &[io::IoSlice::new(b"rejected")])
        } else {
            Pin::new(&mut stream).poll_write(&mut cx, b"rejected")
        };
        assert_error(
            result,
            io::ErrorKind::BrokenPipe,
            "fixture broken pipe after short write",
        );
        rejected_operations(
            &mut stream,
            &state,
            &mut cx,
            io::ErrorKind::BrokenPipe,
            "fixture broken pipe after short write",
        );
        let mut wire = Vec::new();
        while stream.session.wants_write() {
            stream.session.write_tls(&mut wire).unwrap();
        }
        // Feed record by record to honor the peer's normal 16KiB plaintext cap.
        let mut seen = 0;
        while !wire.is_empty() {
            let n = 5 + usize::from(u16::from_be_bytes([wire[3], wire[4]]));
            peer.feed(&wire[..n]).unwrap();
            let mut plain = [0; 16384];
            loop {
                match peer.reader().read(&mut plain) {
                    Ok(n) => {
                        assert!(n > 0);
                        assert!(plain[..n].iter().all(|b| *b == 0x71));
                        seen += n;
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    other => panic!("unexpected peer read {other:?}"),
                }
            }
            wire.drain(..n);
        }
        assert_eq!(seen, accepted);
    }
}

#[test]
fn flush_failure_is_sticky_and_prevents_raw_handoff() {
    let (session, mut peer) = completed_ordinary_connections();
    let state = Arc::new(Mutex::new(IoState {
        fail_flush: true,
        ..Default::default()
    }));
    let mut stream = CryptoTlsStream::new(ControlledIo(state.clone()), session, None);
    let mut cx = Context::from_waker(noop_waker_ref());
    assert!(matches!(
        Pin::new(&mut stream).poll_write(&mut cx, b"accepted"),
        Poll::Ready(Ok(8))
    ));
    assert!(!stream.session.wants_write());
    assert_error(
        Pin::new(&mut stream).poll_flush(&mut cx),
        io::ErrorKind::ConnectionReset,
        "fixture flush reset",
    );
    state.lock().unwrap().fail_flush = false;
    rejected_operations(
        &mut stream,
        &state,
        &mut cx,
        io::ErrorKind::ConnectionReset,
        "fixture flush reset",
    );
    peer.feed(&state.lock().unwrap().output).unwrap();
    let mut plaintext = [0; 8];
    peer.reader().read_exact(&mut plaintext).unwrap();
    assert_eq!(&plaintext, b"accepted");
}

#[test]
fn raw_prefix_error_is_permanent_and_cannot_be_bypassed() {
    let state = Arc::new(Mutex::new(IoState {
        short: Some(7),
        failure: Some(Failure::BrokenPipe),
        ..Default::default()
    }));
    let mut stream = CryptoTlsStream::new(
        ControlledIo(state.clone()),
        completed_reality_connection(),
        None,
    );
    let mut cx = Context::from_waker(noop_waker_ref());
    stream
        .start_raw_write(b"last authenticated TLS record")
        .unwrap();
    let total = stream.raw_write_prefix.as_ref().unwrap().len();
    assert_error(
        Pin::new(&mut stream).poll_write(&mut cx, b"raw bytes"),
        io::ErrorKind::BrokenPipe,
        "fixture broken pipe after short write",
    );
    assert_eq!(stream.raw_write_prefix.as_ref().unwrap().len(), total - 7);
    rejected_operations(
        &mut stream,
        &state,
        &mut cx,
        io::ErrorKind::BrokenPipe,
        "fixture broken pipe after short write",
    );
    assert_eq!(stream.raw_write_prefix.as_ref().unwrap().len(), total - 7);
}

#[test]
fn failed_tls_session_cannot_switch_to_raw_with_an_empty_flight() {
    for reality in [false, true] {
        let (mut session, _) = endpoints(reality);
        assert!(session.feed(&[23, 3, 3, 0, 1, 0]).is_err());
        let expected = session.writer().flush().unwrap_err();
        let state = Arc::new(Mutex::new(IoState::default()));
        // with_input is intentional: a failed REALITY session reports handshaking.
        let mut stream =
            CryptoTlsStream::with_input(ControlledIo(state), session, TlsInput::Stream);
        let error = stream.start_raw_write(&[]).unwrap_err();
        assert_eq!(error.kind(), expected.kind());
        assert_eq!(error.to_string(), expected.to_string());
        assert!(!stream.write_raw);
        assert!(stream.raw_write_prefix.is_none());
    }
}

#[test]
fn raw_direct_writes_preserve_short_counts_and_store_the_first_failure() {
    for vectored in [false, true] {
        for failure in [Failure::BrokenPipe, Failure::Zero] {
            let state = Arc::new(Mutex::new(IoState::default()));
            let mut stream = CryptoTlsStream::new(
                ControlledIo(state.clone()),
                completed_reality_connection(),
                None,
            );
            let mut cx = Context::from_waker(noop_waker_ref());
            stream.start_raw_write(&[]).unwrap();
            assert!(matches!(
                Pin::new(&mut stream).poll_flush(&mut cx),
                Poll::Ready(Ok(()))
            ));
            assert!(stream.raw_write_prefix.is_none());
            {
                let mut io = state.lock().unwrap();
                io.output.clear();
                io.short = Some(7);
                io.failure = Some(failure);
            }
            let first = if vectored {
                Pin::new(&mut stream).poll_write_vectored(
                    &mut cx,
                    &[io::IoSlice::new(b"raw bytes"), io::IoSlice::new(b"tail")],
                )
            } else {
                Pin::new(&mut stream).poll_write(&mut cx, b"raw bytes")
            };
            assert!(matches!(first, Poll::Ready(Ok(7))));
            let (kind, message) = match failure {
                Failure::BrokenPipe => (
                    io::ErrorKind::BrokenPipe,
                    "fixture broken pipe after short write".to_owned(),
                ),
                Failure::Zero => (
                    io::ErrorKind::WriteZero,
                    io::Error::from(io::ErrorKind::WriteZero).to_string(),
                ),
            };
            let second = if vectored {
                Pin::new(&mut stream).poll_write_vectored(
                    &mut cx,
                    &[io::IoSlice::new(b"es"), io::IoSlice::new(b"tail")],
                )
            } else {
                Pin::new(&mut stream).poll_write(&mut cx, b"es")
            };
            assert_error(second, kind, &message);
            assert_eq!(state.lock().unwrap().output, b"raw byt");
            rejected_operations(&mut stream, &state, &mut cx, kind, &message);
        }
    }
}
