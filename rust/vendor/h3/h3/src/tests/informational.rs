use bytes::{Buf, Bytes, BytesMut};
use http::Request;
use std::time::Duration;
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
        self,
        block::{HeaderPrefix, Indexed},
        stream::{DynamicTableSizeUpdate, InsertWithoutNameRef},
        HeaderField,
    },
};

fn head(status: &str) -> BytesMut {
    let mut block = BytesMut::new();
    qpack::encode_stateless(&mut block, [HeaderField::new(":status", status)]).unwrap();
    let mut wire = BytesMut::new();
    Frame::<Bytes>::Headers(block.freeze()).encode_with_payload(&mut wire);
    wire
}

async fn control(conn: &quinn::Connection) -> quinn::SendStream {
    let mut send = conn.open_uni().await.unwrap();
    let mut wire = BytesMut::new();
    StreamType::CONTROL.encode(&mut wire);
    Frame::<Bytes>::Settings(Settings::default()).encode(&mut wire);
    send.write_all(&wire).await.unwrap();
    send
}

#[tokio::test]
async fn interim_heads_require_a_final_response_and_reject_upgrade_or_early_data() {
    for mode in ["success", "upgrade", "data", "eof"] {
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut pair = Pair::default();
            let server = pair.server_inner();
            let server_fut = async {
                let conn = server.accept().await.unwrap().await.unwrap();
                let _control = control(&conn).await;
                let (mut send, mut recv) = conn.accept_bi().await.unwrap();
                assert!(recv.read_chunk(8192, true).await.unwrap().is_some());
                let mut wire = head("100");
                wire.extend_from_slice(&head("103"));
                match mode {
                    "success" => {
                        wire.extend_from_slice(&head("200"));
                        Frame::Data(Bytes::from_static(b"final-body")).encode_with_payload(&mut wire);
                    }
                    "upgrade" => wire.extend_from_slice(&head("101")),
                    "data" => Frame::Data(Bytes::from_static(b"too-soon")).encode_with_payload(&mut wire),
                    "eof" => (),
                    _ => unreachable!(),
                }
                send.write_all(&wire).await.unwrap();
                send.finish().unwrap();
                conn.closed().await;
            };
            let client_fut = async {
                let conn = pair.client_inner().await;
                let (mut driver, mut client) = client::new(h3_quinn::Connection::new(conn.clone())).await.unwrap();
                let driving = tokio::spawn(async move { driver.wait_idle().await });
                let mut request = client.send_request(Request::get("https://example.test/").body(()).unwrap()).await.unwrap();
                let result = request.recv_response().await;
                if mode == "success" {
                    assert_eq!(result.unwrap().status(), 200);
                    let mut body = Vec::new();
                    while let Some(mut data) = request.recv_data().await.unwrap() {
                        body.extend_from_slice(&data.copy_to_bytes(data.remaining()));
                    }
                    assert_eq!(body, b"final-body");
                } else if mode == "upgrade" {
                    assert!(matches!(result, Err(StreamError::StreamError {code, ..}) if code == Code::H3_MESSAGE_ERROR));
                    assert!(conn.close_reason().is_none(), "malformed status must remain a stream error");
                } else {
                    assert!(result.is_err(), "{mode} cannot replace a final response");
                }
                conn.close(0u32.into(), b"test complete");
                driving.await.unwrap();
            };
            tokio::join!(server_fut, client_fut);
        }).await.unwrap_or_else(|_| panic!("interim mode {mode} timed out"));
    }
}

#[tokio::test]
async fn dynamic_interim_is_acknowledged_and_cancelled_read_resumes_at_final_head() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut pair = Pair::default();
        let server = pair.server_inner();
        let (acked_tx, acked_rx) = oneshot::channel();
        let (resume_tx, resume_rx) = oneshot::channel();
        let (done_tx, done_rx) = oneshot::channel();
        let server_fut = async {
            let conn = server.accept().await.unwrap().await.unwrap();
            let _control = control(&conn).await;
            let mut encoder = conn.open_uni().await.unwrap();
            encoder.write_all(&[2]).await.unwrap();
            let mut decoder = None;
            let mut others = Vec::new();
            for _ in 0..3 {
                let mut stream = conn.accept_uni().await.unwrap();
                let mut kind = [0];
                stream.read_exact(&mut kind).await.unwrap();
                if kind == [3] {
                    decoder = Some(stream);
                } else {
                    others.push(stream);
                }
            }
            let mut decoder = decoder.unwrap();
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            assert!(recv.read_chunk(8192, true).await.unwrap().is_some());
            let mut block = BytesMut::new();
            HeaderPrefix::new(1, 1, 1, 65536).encode(&mut block);
            Indexed::Dynamic(0).encode(&mut block);
            let mut wire = BytesMut::new();
            Frame::<Bytes>::Headers(block.freeze()).encode_with_payload(&mut wire);
            send.write_all(&wire).await.unwrap();
            let mut instructions = Vec::new();
            DynamicTableSizeUpdate(128).encode(&mut instructions);
            InsertWithoutNameRef::new(":status", "103")
                .encode(&mut instructions)
                .unwrap();
            for byte in instructions {
                encoder.write_all(&[byte]).await.unwrap();
            }
            let mut feedback = [0; 2];
            decoder.read_exact(&mut feedback).await.unwrap();
            assert_eq!(feedback, [1, 0x80]);
            acked_tx.send(()).unwrap();
            resume_rx.await.unwrap();
            send.write_all(&head("200")).await.unwrap();
            send.finish().unwrap();
            done_tx.send(()).unwrap();
            conn.closed().await;
        };
        let client_fut = async {
            let conn = pair.client_inner().await;
            let (mut driver, mut client) = client::builder()
                .qpack_decoder(65536, 100)
                .build::<_, _, Bytes>(h3_quinn::Connection::new(conn.clone()))
                .await
                .unwrap();
            let driving = tokio::spawn(async move { driver.wait_idle().await });
            let mut request = client
                .send_request(Request::get("https://example.test/").body(()).unwrap())
                .await
                .unwrap();
            {
                let response = request.recv_response();
                tokio::pin!(response);
                tokio::select! {
                    result = &mut response => panic!("interim response escaped: {result:?}"),
                    _ = acked_rx => (),
                }
            }
            resume_tx.send(()).unwrap();
            assert_eq!(request.recv_response().await.unwrap().status(), 200);
            assert!(request.recv_data().await.unwrap().is_none());
            done_rx.await.unwrap();
            conn.close(0u32.into(), b"test complete");
            driving.await.unwrap();
        };
        tokio::join!(server_fut, client_fut);
    })
    .await
    .expect("dynamic interim cancellation timed out");
}
