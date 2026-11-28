use std::{task::Poll, time::Duration};

use assert_matches::assert_matches;
use bytes::{Bytes, BytesMut};
use futures_util::future;
use http::Request;
use tokio::sync::oneshot;

use crate::{
    client,
    error::{Code, ConnectionError, LocalError, StreamError},
    proto::{
        coding::Encode,
        frame::{Frame, SettingId, Settings},
        stream::StreamType,
        varint::VarInt,
    },
    ConnectionState,
};

use super::{h3_quinn, Pair};

fn alps_header_limit() -> BytesMut {
    let mut settings = Settings::default();
    settings
        .insert(SettingId::MAX_HEADER_LIST_SIZE, 64)
        .unwrap();
    settings
        .insert(SettingId::ENABLE_CONNECT_PROTOCOL, 1)
        .unwrap();
    let mut bytes = BytesMut::new();
    Frame::<Bytes>::Settings(settings).encode(&mut bytes);
    bytes
}

#[tokio::test]
async fn alps_limits_requests_before_control_settings_and_control_updates_them() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut pair = Pair::default();
        let server = pair.server_inner();
        let (initial_tx, initial_rx) = oneshot::channel();
        let server_fut = async {
            let connection = server.accept().await.unwrap().await.unwrap();
            initial_rx.await.unwrap();
            let mut stream = connection.open_uni().await.unwrap();
            let mut bytes = BytesMut::new();
            StreamType::CONTROL.encode(&mut bytes);
            let mut settings = Settings::default();
            settings
                .insert(SettingId::MAX_HEADER_LIST_SIZE, 4096)
                .unwrap();
            Frame::<Bytes>::Settings(settings).encode(&mut bytes);
            stream.write_all(&bytes).await.unwrap();
            connection.closed().await;
        };
        let client_fut = async {
            let connection = pair.client_inner().await;
            let mut builder = client::builder();
            builder.peer_alps(&alps_header_limit()).unwrap();
            let (mut driver, mut sender) = builder
                .build::<_, _, Bytes>(h3_quinn::Connection::new(connection.clone()))
                .await
                .unwrap();
            assert_eq!(sender.settings().max_field_section_size, 64);
            assert!(matches!(
                sender
                    .send_request(
                        Request::get("https://example.test/long-request")
                            .header("x-test", "a".repeat(256))
                            .body(())
                            .unwrap()
                    )
                    .await,
                Err(StreamError::HeaderTooBig { max_size: 64, .. })
            ));
            initial_tx.send(()).unwrap();
            future::poll_fn(|cx| {
                assert!(driver.poll_close(cx).is_pending());
                if sender.settings().max_field_section_size == 4096 {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
            assert!(
                sender.settings().enable_extended_connect,
                "omitted settings retain their authenticated ALPS value"
            );
            sender
                .send_request(
                    Request::get("https://example.test/long-request")
                        .header("x-test", "a".repeat(256))
                        .body(())
                        .unwrap(),
                )
                .await
                .unwrap()
                .finish()
                .await
                .unwrap();
            connection.close(0u32.into(), b"ALPS test complete");
        };
        tokio::join!(server_fut, client_fut);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn alps_does_not_replace_the_required_control_stream_settings() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut pair = Pair::default();
        let server = pair.server_inner();
        let server_fut = async {
            let connection = server.accept().await.unwrap().await.unwrap();
            let mut stream = connection.open_uni().await.unwrap();
            let mut bytes = BytesMut::new();
            StreamType::CONTROL.encode(&mut bytes);
            Frame::<Bytes>::Goaway(VarInt(0)).encode(&mut bytes);
            stream.write_all(&bytes).await.unwrap();
            connection.closed().await;
        };
        let client_fut = async {
            let mut builder = client::builder();
            builder.peer_alps(&alps_header_limit()).unwrap();
            let (mut driver, _sender) = builder
                .build::<_, _, Bytes>(pair.client().await)
                .await
                .unwrap();
            assert_matches!(
                future::poll_fn(|cx| driver.poll_close(cx)).await,
                ConnectionError::Local {
                    error: LocalError::Application {
                        code: Code::H3_MISSING_SETTINGS,
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
