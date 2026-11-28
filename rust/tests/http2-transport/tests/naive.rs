use aerobox_http2_transport_check::{
    address::{Address, NetLocation},
    h2_multi_stream::H2MultiStream,
    header_options::{Headers, Options},
    naive_client_session::NaiveClientSession,
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
fn target() -> NetLocation {
    NetLocation::new(Address::Hostname("capture.invalid".into()), 443)
}
async fn frame(peer: &mut tokio::io::DuplexStream) -> (u8, u8, u32, Vec<u8>) {
    let mut h = [0; 9];
    peer.read_exact(&mut h).await.unwrap();
    let len = u32::from_be_bytes([0, h[0], h[1], h[2]]) as usize;
    let mut p = vec![0; len];
    peer.read_exact(&mut p).await.unwrap();
    (
        h[3],
        h[4],
        u32::from_be_bytes(h[5..].try_into().unwrap()),
        p,
    )
}
#[tokio::test]
async fn production_session_emits_chromium_settings_and_connect_encoding() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (io, mut peer) = tokio::io::duplex(65536);
        let opts = Options {
            stream_receive_window: 64 * 1024 * 1024,
            session_receive_window: 128 * 1024 * 1024,
            ..Default::default()
        };
        let mut session = NaiveClientSession::with_options(Box::new(io), &opts)
            .await
            .unwrap();
        let task = tokio::spawn(async move {
            session
                .open_stream(&target(), "Basic dXNlcjpwYXNz", true)
                .await
        });
        let mut preface = [0; 24];
        peer.read_exact(&mut preface).await.unwrap();
        assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        peer.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).await.unwrap();
        let mut settings = false;
        let mut credit = false;
        loop {
            let (kind, flags, id, payload) = frame(&mut peer).await;
            match kind {
                4 if flags == 0 => {
                    assert_eq!(id, 0);
                    let actual: Vec<_> = payload
                        .chunks_exact(6)
                        .map(|p| {
                            (
                                u16::from_be_bytes(p[..2].try_into().unwrap()),
                                u32::from_be_bytes(p[2..].try_into().unwrap()),
                            )
                        })
                        .collect();
                    assert_eq!(actual, [(1, 65536), (2, 0), (4, 67108864), (6, 262144)]);
                    settings = true;
                }
                8 => {
                    assert_eq!(id, 0);
                    assert_eq!(u32::from_be_bytes(payload.try_into().unwrap()), 134152193);
                    credit = true;
                }
                1 => {
                    assert_eq!(id, 1);
                    assert_eq!(flags, 0x24);
                    assert_eq!(&payload[..14], b"\x80\0\0\0\x49\x02\x07CONNECT");
                    break;
                }
                4 if flags == 1 => {}
                other => panic!("unexpected frame {other}"),
            }
        }
        assert!(settings && credit);
        peer.write_all(&[0, 0, 1, 1, 4, 0, 0, 0, 1, 0x88])
            .await
            .unwrap();
        let stream = task.await.unwrap().unwrap();
        drop(stream);
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn production_session_preserves_overrides_and_reuses_carrier_with_large_responses() {
    tokio::time::timeout(Duration::from_secs(5),async {
        let (io,peer)=tokio::io::duplex(65536);
        let server=tokio::spawn(async move {
            let mut connection=h2::server::handshake(peer).await.unwrap();
            let mut tasks=tokio::task::JoinSet::new();
            for _ in 0..2 {
                let (request,mut response)=connection.accept().await.unwrap().unwrap();
                assert_eq!(request.headers()["proxy-authorization"],"Basic overridden");
                assert_eq!(request.headers()["user-agent"],"");
                assert_eq!(request.headers().get_all("x-extra").iter().count(),2);
                assert!(!request.headers().contains_key("padding-type-request"));
                let response_headers=http::Response::builder().header("x-metadata","x".repeat(32768)).body(()).unwrap();
                let send=response.send_response(response_headers,false).unwrap();
                tasks.spawn(async move {
                    let mut stream=H2MultiStream::new(send,request.into_body());
                    let mut input=Vec::new();stream.read_to_end(&mut input).await.unwrap();
                    assert_eq!(input.len(),65537);stream.write_all(&input).await.unwrap();stream.shutdown().await.unwrap();
                });
            }
            tokio::select! {
                _=async {while tasks.join_next().await.is_some(){}}=>{},
                _=connection.accept()=>panic!("unexpected extra request")
            }
            while connection.accept().await.is_some(){}
        });
        let mut session=NaiveClientSession::new(Box::new(io)).await.unwrap();
        let headers:Headers=serde_json::from_value(serde_json::json!({"proxy-authorization":"Basic overridden","x-extra":["first","second"]})).unwrap();
        for _ in 0..2 {
            let mut stream=session.open_with_headers(&target(),"Basic ignored",false,&headers).await.unwrap();
            let bytes=vec![b'x';65537];stream.write_all(&bytes).await.unwrap();stream.shutdown().await.unwrap();
            let mut echoed=Vec::new();stream.read_to_end(&mut echoed).await.unwrap();assert_eq!(bytes,echoed);
        }
        drop(session);server.await.unwrap();
    }).await.unwrap();
}
