use std::{sync::Arc, task::Poll, time::Duration};

use assert_matches::assert_matches;
use bytes::{Bytes, BytesMut};
use futures_util::{future, poll};
use http::Request;
use tokio::sync::oneshot;

use crate::{
    client,
    error::{Code, ConnectionError, LocalError, StreamError},
    proto::{
        coding::Encode,
        frame::{Frame, Settings},
        stream::StreamType,
        varint::VarInt,
    },
    ConnectionState,
};

use super::{h3_quinn, Pair};

#[tokio::test]
async fn goaway_wakes_all_requests_waiting_for_stream_credit_without_new_credit() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut pair = Pair::default();
        Arc::get_mut(&mut pair.config)
            .unwrap()
            .max_concurrent_bidi_streams(1u32.into());
        let server = pair.server_inner();
        let (pending_tx, pending_rx) = oneshot::channel();
        let (closing_tx, closing_rx) = oneshot::channel();
        let (checked_tx, checked_rx) = oneshot::channel();

        let server_fut = async {
            let connection = server.accept().await.unwrap().await.unwrap();
            let mut control = connection.open_uni().await.unwrap();
            let mut bytes = BytesMut::new();
            StreamType::CONTROL.encode(&mut bytes);
            Frame::<Bytes>::Settings(Settings::default()).encode(&mut bytes);
            control.write_all(&bytes).await.unwrap();
            let (_old_send, mut old_recv) = connection.accept_bi().await.unwrap();
            assert!(old_recv.read_chunk(1024, true).await.unwrap().is_some());
            pending_rx.await.unwrap();
            bytes.clear();
            Frame::<Bytes>::Goaway(VarInt(4)).encode(&mut bytes);
            control.write_all(&bytes).await.unwrap();
            closing_rx.await.unwrap();
            // A closing peer need not grant any further stream credit.
            // No replacement request may appear on this connection.
            let mut extra = Box::pin(connection.accept_bi());
            assert!(poll!(&mut extra).is_pending());
            checked_tx.send(()).unwrap();
            connection.closed().await;
        };

        let client_fut = async {
            let connection = pair.client_inner().await;
            let (mut driver, mut sender) =
                client::new(h3_quinn::Connection::new(connection.clone()))
                    .await
                    .unwrap();
            let _old = sender
                .send_request(Request::get("https://example.test/old").body(()).unwrap())
                .await
                .unwrap();
            let observer = sender.clone();
            let mut pending = Vec::new();
            let mut started = Vec::new();
            for _ in 0..2 {
                let mut sender = sender.clone();
                let (ready, receiving) = oneshot::channel();
                pending.push(tokio::spawn(async move {
                    let mut request =
                        Box::pin(sender.send_request(
                            Request::get("https://example.test/new").body(()).unwrap(),
                        ));
                    assert!(poll!(&mut request).is_pending());
                    ready.send(()).unwrap();
                    request.await.map(|_| ())
                }));
                started.push(receiving);
            }
            for ready in started {
                ready.await.unwrap();
            }
            pending_tx.send(()).unwrap();
            future::poll_fn(|cx| {
                assert!(driver.poll_close(cx).is_pending());
                if observer.is_closing() {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
            for request in pending {
                assert_matches!(request.await.unwrap(), Err(StreamError::RemoteClosing));
            }
            closing_tx.send(()).unwrap();
            checked_rx.await.unwrap();
            connection.close(0u32.into(), b"test complete");
        };
        tokio::join!(server_fut, client_fut);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn qpack_fin_and_invalid_instructions_close_even_without_a_control_stream() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for (kind, bytes, finish, expected) in [
            (2, vec![], true, Code::H3_CLOSED_CRITICAL_STREAM),
            (3, vec![], true, Code::H3_CLOSED_CRITICAL_STREAM),
            (2, vec![0x21], false, Code::QPACK_ENCODER_STREAM_ERROR),
            (2, vec![0xc0], false, Code::QPACK_ENCODER_STREAM_ERROR),
            (3, vec![0x80], false, Code::QPACK_DECODER_STREAM_ERROR),
            (3, vec![0x01], false, Code::QPACK_DECODER_STREAM_ERROR),
            (3, [vec![0x7f], vec![0x80; 9]].concat(), false, Code::QPACK_DECODER_STREAM_ERROR),
        ] {
            let mut pair = Pair::default();
            let server = pair.server_inner();
            let server_fut = async {
                let connection = server.accept().await.unwrap().await.unwrap();
                let mut stream = connection.open_uni().await.unwrap();
                stream.write_all(&[kind]).await.unwrap();
                stream.write_all(&bytes).await.unwrap();
                if finish { stream.finish().unwrap(); }
                connection.closed().await;
            };
            let client_fut = async {
                let (mut driver, _sender) = client::new(pair.client().await).await.unwrap();
                assert_matches!(
                    future::poll_fn(|cx| driver.poll_close(cx)).await,
                    ConnectionError::Local { error: LocalError::Application { code, .. } } if code == expected
                );
            };
            tokio::join!(server_fut, client_fut);
        }
    }).await.unwrap();
}

#[tokio::test]
async fn fragmented_qpack_cancellation_does_not_block_control_or_hide_reset() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut pair = Pair::default();
        let server = pair.server_inner();
        let (closing_tx, closing_rx) = oneshot::channel();
        let server_fut = async {
            let connection = server.accept().await.unwrap().await.unwrap();
            let mut encoder = connection.open_uni().await.unwrap();
            encoder.write_all(&[2, 0x20]).await.unwrap();
            let mut decoder = connection.open_uni().await.unwrap();
            decoder.write_all(&[3, 0x7f]).await.unwrap();
            // Split a Stream Cancellation(64) across two writes.
            tokio::task::yield_now().await;
            decoder.write_all(&[0x01, 0x40]).await.unwrap();
            let mut control = connection.open_uni().await.unwrap();
            let mut bytes = BytesMut::new();
            StreamType::CONTROL.encode(&mut bytes);
            Frame::<Bytes>::Settings(Settings::default()).encode(&mut bytes);
            Frame::<Bytes>::Goaway(VarInt(0)).encode(&mut bytes);
            control.write_all(&bytes).await.unwrap();
            closing_rx.await.unwrap();
            encoder.reset(17u32.into()).unwrap();
            connection.closed().await;
        };
        let client_fut = async {
            let (mut driver, sender) = client::new(pair.client().await).await.unwrap();
            future::poll_fn(|cx| {
                assert!(driver.poll_close(cx).is_pending());
                if sender.is_closing() {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
            assert!(sender.get_conn_error().is_none());
            closing_tx.send(()).unwrap();
            assert_matches!(
                future::poll_fn(|cx| driver.poll_close(cx)).await,
                ConnectionError::Local {
                    error: LocalError::Application {
                        code: Code::H3_CLOSED_CRITICAL_STREAM,
                        ..
                    }
                }
            );
        };
        tokio::join!(server_fut, client_fut);
    })
    .await
    .unwrap();
}
