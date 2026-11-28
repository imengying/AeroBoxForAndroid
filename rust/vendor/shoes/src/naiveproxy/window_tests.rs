use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{naive_client_session::NaiveClientSession, options::Options};

async fn advertised_windows(options: Options) -> (u32, u32) {
    // HTTP/2 starts with 65535 connection bytes. WINDOW_UPDATE only increases
    // credit; an application target below that value takes effect after reads.
    let initial_session_credit = options.session_receive_window.max(65535);
    let (client, mut peer) = tokio::io::duplex(8192);
    let _session = NaiveClientSession::with_options(Box::new(client), &options)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut preface = [0; 24];
        peer.read_exact(&mut preface).await.unwrap();
        assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        peer.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).await.unwrap();
        let mut settings = Vec::new();
        let mut session_credit = 65_535u32;
        let mut acknowledgement = false;
        while !acknowledgement || settings.is_empty() || session_credit < initial_session_credit {
            let mut header = [0; 9];
            peer.read_exact(&mut header).await.unwrap();
            let length = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
            assert!(length <= 16384);
            let mut data = vec![0; length];
            peer.read_exact(&mut data).await.unwrap();
            match header[3] {
                4 if header[4] == 1 => {
                    assert!(data.is_empty());
                    acknowledgement = true;
                }
                4 => {
                    assert_eq!(data.len() % 6, 0);
                    for item in data.as_chunks::<6>().0 {
                        settings.push((
                            u16::from_be_bytes(item[..2].try_into().unwrap()),
                            u32::from_be_bytes(item[2..].try_into().unwrap()),
                        ));
                    }
                }
                8 => {
                    assert_eq!(&header[5..], &[0; 4]);
                    session_credit += u32::from_be_bytes(data.try_into().unwrap());
                }
                other => panic!("unexpected initial H2 frame {other}"),
            }
        }
        // Decode the actual frame rather than consulting Builder state. The
        // reference's explicit settings are ordered by ID; default frame size
        // and concurrent-stream settings must not silently add wire entries.
        assert_eq!(
            settings,
            vec![
                (1, 65_536),
                (2, 0),
                (4, options.stream_receive_window),
                (6, 262_144),
            ]
        );
        (settings[2].1, session_credit)
    })
    .await
    .expect("H2 flow-control windows were not advertised")
}

#[tokio::test]
async fn android_windows_reach_h2_settings_and_connection_credit() {
    for (stream, session) in [
        (64 * 1024 * 1024, 128 * 1024 * 1024),
        (1024 * 1024, 2 * 1024 * 1024),
        // An odd configured connection window verifies floor(W/2). Keep the
        // increment above h2's WINDOW_UPDATE batching threshold (a two-byte
        // increase from 65535 is intentionally delayed until data is consumed).
        (65536, 131073),
        (16384, 32768),
        (0, 1),
        (i32::MAX as u32 / 2, i32::MAX as u32),
    ] {
        let options = Options {
            stream_receive_window: stream,
            session_receive_window: session,
            ..Options::default()
        };
        assert_eq!(
            advertised_windows(options).await,
            (stream, session.max(65535))
        );
    }
    // Native JSON retains its independent defaults; only Android conversion changes.
    assert_eq!(
        advertised_windows(Options::default()).await,
        (256 * 1024, 256 * 1024)
    );
}

#[test]
fn windows_validate_the_cronet_and_h2_integer_limit() {
    for (quic, stream, session) in [
        (false, 64 * 1024 * 1024, 128 * 1024 * 1024),
        (true, 6 * 1024 * 1024, 15 * 1024 * 1024),
    ] {
        let options = Options {
            quic,
            stream_receive_window: stream,
            session_receive_window: session,
            ..Options::default()
        };
        options.validate().unwrap();
        Options {
            stream_receive_window: i32::MAX as u32,
            session_receive_window: i32::MAX as u32,
            ..options.clone()
        }
        .validate()
        .unwrap();
        assert!(
            Options {
                stream_receive_window: i32::MAX as u32 + 1,
                ..options.clone()
            }
            .validate()
            .is_err()
        );
        assert!(
            Options {
                session_receive_window: i32::MAX as u32 + 1,
                ..options
            }
            .validate()
            .is_err()
        );
    }
}
