use bytes::{Bytes, BytesMut};
use futures_util::{future, FutureExt};
use http::Request;
use std::{task::Poll, time::Duration};
use tokio::sync::oneshot;

use super::{h3_quinn, Pair};
use crate::{
    client,
    error::{Code, StreamError},
    proto::{
        coding::Encode,
        frame::{Frame, Settings},
        stream::StreamType,
    },
    qpack::{
        block::{HeaderPrefix, Indexed, IndexedWithPostBase},
        stream::{DynamicTableSizeUpdate, InsertWithoutNameRef},
    },
    ConnectionState,
};

fn headers(trailers: bool) -> BytesMut {
    let mut block = BytesMut::new();
    HeaderPrefix::new(1, 0, 1, 65536).encode(&mut block);
    if !trailers {
        Indexed::Static(25).encode(&mut block);
    }
    IndexedWithPostBase(0).encode(&mut block);
    let mut wire = BytesMut::new();
    Frame::<Bytes>::Headers(block.freeze()).encode_with_payload(&mut wire);
    wire
}

#[tokio::test]
async fn blocked_response_handles_fragments_reset_connection_close_and_cancelled_future() {
    for mode in ["decode", "reset", "close", "retry", "drop"] {
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut pair = Pair::default();
            let server = pair.server_inner();
            let (blocked_tx, blocked_rx) = oneshot::channel();
            let (done_tx, done_rx) = oneshot::channel();
            let server_fut = async {
                let conn = server.accept().await.unwrap().await.unwrap();
                let mut control = conn.open_uni().await.unwrap();
                let mut settings = BytesMut::new();
                StreamType::CONTROL.encode(&mut settings);
                Frame::<Bytes>::Settings(Settings::default()).encode(&mut settings);
                control.write_all(&settings).await.unwrap();
                let mut encoder = conn.open_uni().await.unwrap();
                encoder.write_all(&[2]).await.unwrap();
                let mut decoder = None;
                let mut other_streams = Vec::new();
                for _ in 0..3 {
                    let mut stream = conn.accept_uni().await.unwrap();
                    let mut kind = [0];
                    stream.read_exact(&mut kind).await.unwrap();
                    if kind == [3] {
                        decoder = Some(stream);
                    } else {
                        other_streams.push(stream);
                    }
                }
                let mut decoder = decoder.unwrap();
                let (mut send, mut recv) = conn.accept_bi().await.unwrap();
                assert!(recv.read_chunk(8192, true).await.unwrap().is_some());
                send.write_all(&headers(false)).await.unwrap();
                blocked_rx.await.unwrap();
                match mode {
                    "reset" => {
                        send.reset(Code::H3_REQUEST_CANCELLED.value().try_into().unwrap())
                            .unwrap();
                    }
                    "close" => {
                        encoder.reset(17u32.into()).unwrap();
                    }
                    "drop" => (),
                    _ => {
                        let mut instructions = Vec::new();
                        DynamicTableSizeUpdate(128).encode(&mut instructions);
                        InsertWithoutNameRef::new("x-dynamic", "works")
                            .encode(&mut instructions)
                            .unwrap();
                        for byte in instructions {
                            encoder.write_all(&[byte]).await.unwrap();
                            tokio::task::yield_now().await;
                        }
                        let mut data = BytesMut::new();
                        // This DATA must remain intact while the header decode waits.
                        Frame::Data(Bytes::from_static(b"body-after-headers")).encode(&mut data);
                        data.extend_from_slice(b"body-after-headers");
                        data.extend_from_slice(&headers(true));
                        send.write_all(&data).await.unwrap();
                        send.finish().unwrap();
                    }
                }
                if mode != "close" {
                    let mut feedback = Vec::new();
                    let expected = if matches!(mode, "reset" | "drop") {
                        1
                    } else {
                        3
                    };
                    while feedback.len() < expected {
                        feedback.extend_from_slice(
                            &decoder.read_chunk(1024, true).await.unwrap().unwrap().bytes,
                        );
                    }
                    if matches!(mode, "reset" | "drop") {
                        assert_eq!(feedback, [0x40]);
                    } else {
                        assert_eq!(feedback, [1, 0x80, 0x80]);
                    }
                }
                done_tx.send(()).unwrap();
                conn.closed().await;
            };
            let client_fut = async {
                let conn = pair.client_inner().await;
                let (mut driver, mut sender) = client::builder()
                    .qpack_decoder(65536, 100)
                    .build::<_, _, Bytes>(h3_quinn::Connection::new(conn.clone()))
                    .await
                    .unwrap();
                let receiver = driver.shared_state().qpack_decoder.clone().unwrap();
                let driver_task = tokio::spawn(async move { driver.wait_idle().await });
                let mut request = sender
                    .send_request(Request::get("https://example.test/").body(()).unwrap())
                    .await
                    .unwrap();
                let mut response = Box::pin(request.recv_response());
                future::poll_fn(|cx| {
                    assert!(response.poll_unpin(cx).is_pending());
                    if receiver.is_blocked(0) {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    }
                })
                .await;
                if matches!(mode, "retry" | "drop") {
                    drop(response);
                    if mode == "retry" {
                        response = Box::pin(request.recv_response());
                    } else {
                        drop(request);
                        blocked_tx.send(()).unwrap();
                        done_rx.await.unwrap();
                        conn.close(0u32.into(), b"test complete");
                        driver_task.await.unwrap();
                        return;
                    }
                }
                blocked_tx.send(()).unwrap();
                match mode {
                    "reset" => assert!(matches!(
                        response.await,
                        Err(StreamError::RemoteTerminate {
                            code: Code::H3_REQUEST_CANCELLED,
                            ..
                        })
                    )),
                    "close" => assert!(matches!(
                        response.await,
                        Err(StreamError::ConnectionError(_))
                    )),
                    _ => {
                        let response = response.await.unwrap();
                        assert_eq!(response.status(), 200);
                        assert_eq!(response.headers()["x-dynamic"], "works");
                        use bytes::Buf;
                        let mut body = request.recv_data().await.unwrap().unwrap();
                        assert_eq!(
                            body.copy_to_bytes(body.remaining()).as_ref(),
                            b"body-after-headers"
                        );
                        assert!(request.recv_data().await.unwrap().is_none());
                        let trailers = request.recv_trailers().await.unwrap().unwrap();
                        assert_eq!(trailers["x-dynamic"], "works");
                    }
                }
                done_rx.await.unwrap();
                conn.close(0u32.into(), b"test complete");
                driver_task.await.unwrap();
            };
            tokio::join!(server_fut, client_fut);
        })
        .await
        .unwrap_or_else(|_| panic!("dynamic QPACK mode {mode} timed out"));
    }
}
