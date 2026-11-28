use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc,
    task::JoinHandle,
};

// An independent wire peer: enough HTTP/2 to accept one tunnel and optionally ACK PING.
// It deliberately does not use the production h2 driver, and can blackhole PINGs while
// continuing to send DATA, exercising read-idle rather than a fixed-period timer.
struct Peer {
    send: mpsc::UnboundedSender<Vec<u8>>,
    pings: Arc<AtomicUsize>,
    tasks: [JoinHandle<()>; 2],
}
impl Drop for Peer {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}
fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![
        (payload.len() >> 16) as u8,
        (payload.len() >> 8) as u8,
        payload.len() as u8,
        kind,
        flags,
    ];
    frame.extend(stream.to_be_bytes());
    frame.extend(payload);
    frame
}
fn make_peer(responsive: bool) -> (tokio::io::DuplexStream, Peer) {
    let (client, server) = tokio::io::duplex(8192);
    let (mut read, mut write) = tokio::io::split(server);
    let (send, mut writes) = mpsc::unbounded_channel::<Vec<u8>>();
    let pings = Arc::new(AtomicUsize::new(0));
    let tx = send.clone();
    let count = pings.clone();
    let reader = tokio::spawn(async move {
        let mut preface = [0; 24];
        read.read_exact(&mut preface).await.unwrap();
        assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        tx.send(frame(4, 0, 0, &[])).unwrap();
        loop {
            let mut header = [0; 9];
            if read.read_exact(&mut header).await.is_err() {
                return;
            }
            let length =
                usize::from(header[0]) << 16 | usize::from(header[1]) << 8 | usize::from(header[2]);
            let mut payload = vec![0; length];
            if read.read_exact(&mut payload).await.is_err() {
                return;
            }
            match (header[3], header[4]) {
                (4, 0) => {
                    let _ = tx.send(frame(4, 1, 0, &[]));
                }
                (1, _) => {
                    // HPACK static entry 8 = :status: 200; no END_STREAM.
                    tx.send(frame(1, 4, 1, &[0x88])).unwrap();
                    tx.send(frame(0, 0, 1, b"R")).unwrap();
                }
                (6, 0) => {
                    count.fetch_add(1, Ordering::SeqCst);
                    if responsive {
                        let _ = tx.send(frame(6, 1, 0, &payload));
                    }
                }
                (7, _) => return,
                _ => {}
            }
        }
    });
    let writer = tokio::spawn(async move {
        while let Some(bytes) = writes.recv().await {
            if write.write_all(&bytes).await.is_err() {
                return;
            }
        }
    });
    (
        client,
        Peer {
            send,
            pings,
            tasks: [reader, writer],
        },
    )
}

#[tokio::test(start_paused = true)]
async fn configured_ping_timeout_closes_an_active_blackholed_tunnel() {
    let (io, peer) = make_peer(false);
    let (session, mut stream) = aerobox_http2_transport_check::open(
        io,
        Some((Duration::from_secs(10), Duration::from_secs(3))),
    )
    .await
    .unwrap();
    assert_eq!(stream.read_u8().await.unwrap(), b'R');
    tokio::time::sleep(Duration::from_secs(9)).await;
    assert_eq!(peer.pings.load(Ordering::SeqCst), 0);
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(peer.pings.load(Ordering::SeqCst), 1);
    assert!(session.is_ready());
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(!session.is_ready());
    assert!(
        tokio::time::timeout(Duration::from_secs(1), stream.read_u8())
            .await
            .unwrap()
            .is_err()
    );
}

#[tokio::test(start_paused = true)]
async fn incoming_data_postpones_ping_and_responsive_idle_peers_stay_open() {
    let (io, peer) = make_peer(false);
    let (session, mut stream) = aerobox_http2_transport_check::open(
        io,
        Some((Duration::from_secs(10), Duration::from_secs(3))),
    )
    .await
    .unwrap();
    assert_eq!(stream.read_u8().await.unwrap(), b'R');
    for _ in 0..4 {
        tokio::time::sleep(Duration::from_secs(8)).await;
        peer.send.send(frame(0, 0, 1, b"D")).unwrap();
        assert_eq!(stream.read_u8().await.unwrap(), b'D');
        assert!(session.is_ready());
    }
    assert_eq!(peer.pings.load(Ordering::SeqCst), 0);
    drop(stream);
    drop(session);
    drop(peer);

    let (io, peer) = make_peer(true);
    let (session, mut stream) = aerobox_http2_transport_check::open(
        io,
        Some((Duration::from_secs(10), Duration::from_secs(3))),
    )
    .await
    .unwrap();
    assert_eq!(stream.read_u8().await.unwrap(), b'R');
    tokio::time::sleep(Duration::from_secs(45)).await;
    assert!(session.is_ready());
    assert!(peer.pings.load(Ordering::SeqCst) >= 3);
}

#[tokio::test(start_paused = true)]
async fn disabled_keepalive_and_default_ping_deadline_match_http2_transport() {
    let (io, peer) = make_peer(false);
    let (session, mut stream) =
        aerobox_http2_transport_check::open(io, Some((Duration::ZERO, Duration::ZERO)))
            .await
            .unwrap();
    assert_eq!(stream.read_u8().await.unwrap(), b'R');
    tokio::time::sleep(Duration::from_secs(90)).await;
    assert_eq!(peer.pings.load(Ordering::SeqCst), 0);
    assert!(session.is_ready());
    drop(stream);
    drop(session);
    drop(peer);

    let (io, peer) = make_peer(false);
    let (session, mut stream) =
        aerobox_http2_transport_check::open(io, Some((Duration::from_secs(10), Duration::ZERO)))
            .await
            .unwrap();
    assert_eq!(stream.read_u8().await.unwrap(), b'R');
    tokio::time::sleep(Duration::from_secs(24)).await;
    assert_eq!(peer.pings.load(Ordering::SeqCst), 1);
    assert!(session.is_ready());
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(!session.is_ready());
}

#[tokio::test(start_paused = true)]
async fn ordinary_proxy_sessions_still_retire_without_breaking_active_streams() {
    let (io, peer) = make_peer(false);
    let (session, mut stream) = aerobox_http2_transport_check::open(io, None).await.unwrap();
    assert_eq!(stream.read_u8().await.unwrap(), b'R');
    tokio::time::sleep(Duration::from_secs(36)).await;
    assert_eq!(peer.pings.load(Ordering::SeqCst), 1);
    assert!(!session.is_ready());
    peer.send.send(frame(0, 0, 1, b"D")).unwrap();
    assert_eq!(stream.read_u8().await.unwrap(), b'D');
}
