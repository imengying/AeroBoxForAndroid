//! Production Naive TLS/H2 against an independent Go frame and HPACK observer.
use std::{path::PathBuf, process::Stdio, sync::Arc, time::Duration};

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

use super::{naive_client_session::NaiveClientSession, options::Options};
use crate::{
    address::NetLocation,
    config::tls::TlsClientOptions,
    crypto::{CryptoTlsStream, TlsConnection, TlsReadMode},
};

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[tokio::test]
#[ignore = "requires AEROBOX_NAIVE_PROFILE_PEER and a fresh AEROBOX_NAIVE_PROFILE_OUTPUT directory"]
async fn production_naive_tls_h2_matches_independent_reference_observer() {
    let peer = std::env::var_os("AEROBOX_NAIVE_PROFILE_PEER")
        .expect("set AEROBOX_NAIVE_PROFILE_PEER to the naive-profile-peer executable");
    let output = PathBuf::from(
        std::env::var_os("AEROBOX_NAIVE_PROFILE_OUTPUT")
            .expect("set AEROBOX_NAIVE_PROFILE_OUTPUT to a new absolute directory"),
    );
    assert!(
        output.is_absolute(),
        "the capture directory must be absolute"
    );
    assert!(
        !output.exists(),
        "the observer creates a fresh capture directory"
    );

    tokio::time::timeout(Duration::from_secs(60), async {
        let mut child = tokio::process::Command::new(peer)
            .args(["-mode", "serve", "-requests", "2", "-output"])
            .arg(&output)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let mut ready_line = String::new();
        assert_ne!(stdout.read_line(&mut ready_line).await.unwrap(), 0);
        let ready: serde_json::Value = serde_json::from_str(&ready_line).unwrap();
        assert_eq!(ready["phase"], "ready");
        assert_eq!(ready["server_name"], "localhost");
        let ca = PathBuf::from(ready["ca_pem"].as_str().unwrap());
        assert_eq!(ca, output.join("ca.pem"));
        std::fs::write(output.join("ready.json"), ready_line).unwrap();

        let options = TlsClientOptions {
            root_certificates: vec![std::fs::read_to_string(ca).unwrap()],
            ..TlsClientOptions::default()
        };
        let config = crate::rustls_config_util::naive::create_config(&options, false).unwrap();
        let socket = tokio::net::TcpStream::connect((
            std::net::Ipv4Addr::LOCALHOST,
            u16::try_from(ready["port"].as_u64().unwrap()).unwrap(),
        ))
        .await
        .unwrap();
        let connection = rustls::ClientConnection::new(
            Arc::new(config),
            ready["server_name"]
                .as_str()
                .unwrap()
                .to_owned()
                .try_into()
                .unwrap(),
        )
        .unwrap();
        let tls = CryptoTlsStream::handshake(
            socket,
            TlsConnection::new(connection),
            TlsReadMode::Stream,
            &[],
        )
        .await
        .unwrap();
        // These are the Android App's Naive defaults, also used by Cronet.
        let options = Options {
            stream_receive_window: 64 * 1024 * 1024,
            session_receive_window: 128 * 1024 * 1024,
            ..Options::default()
        };
        let mut session = NaiveClientSession::with_options(Box::new(tls), &options)
            .await
            .unwrap();
        let target = NetLocation::from_str("capture.invalid:443", None).unwrap();
        let payload: Vec<_> = (0..65537)
            .map(|index| ((index * 17 + 3) % 251) as u8)
            .collect();
        for _ in 0..2 {
            let stream = session
                .open_stream(&target, "Basic dXNlcjpwYXNz", true)
                .await
                .unwrap();
            let (read, mut write) = tokio::io::split(stream);
            // One extra byte detects unexpected payload without unbounded allocation.
            let mut read = read.take(payload.len() as u64 + 1);
            let mut received = Vec::with_capacity(payload.len());
            let upload = async {
                write.write_all(&payload).await?;
                write.shutdown().await
            };
            let download = read.read_to_end(&mut received);
            tokio::try_join!(upload, download).unwrap();
            assert_eq!(received, payload);
        }
        drop(session);

        // Drain stdout while waiting, so a larger capture cannot fill the pipe.
        let mut ending = String::new();
        let (status, _) =
            tokio::try_join!(child.wait(), stdout.read_to_string(&mut ending)).unwrap();
        std::fs::write(output.join("server-ending.json"), &ending).unwrap();
        assert!(status.success(), "observer failed: {ending}");
        let completed: serde_json::Value = serde_json::from_str(&ending).unwrap();
        let capture: serde_json::Value =
            serde_json::from_slice(&std::fs::read(output.join("capture.json")).unwrap()).unwrap();
        assert_eq!(completed, capture);
        assert_eq!(capture["phase"], "complete");
        assert_eq!(capture["requests"], 2);
        assert_eq!(capture["version"], 0x0304);
        assert!((0x1301..=0x1303).contains(&capture["cipher"].as_u64().unwrap()));

        let frames = capture["frames"].as_array().unwrap();
        let settings = frames
            .iter()
            .find(|frame| frame["Type"] == "SETTINGS" && frame["Flags"] == 0)
            .unwrap();
        assert_eq!(settings["Stream"], 0);
        assert_eq!(
            settings["Settings"],
            serde_json::json!([[1, 65536], [2, 0], [4, 67108864], [6, 262144]])
        );
        let window = frames
            .iter()
            .find(|frame| frame["Type"] == "WINDOW_UPDATE" && frame["Stream"] == 0)
            .unwrap();
        assert_eq!(window["Payload"], "07ff0001"); // 128 MiB - 65535.
        let headers: Vec<_> = frames
            .iter()
            .filter(|frame| frame["Type"] == "HEADERS")
            .collect();
        assert_eq!(headers.len(), 2);
        for (index, frame) in headers.iter().enumerate() {
            let stream_id = 1 + 2 * index;
            assert_eq!(frame["Stream"], stream_id);
            assert_eq!(frame["Flags"], 0x24); // PRIORITY | END_HEADERS, no END_STREAM.
            let encoded = decode_hex(frame["Payload"].as_str().unwrap());
            // The observer exposes the HPACK fragment after the PRIORITY fields.
            assert!(encoded.starts_with(b"\x02\x07CONNECT"));
            if index == 1 {
                assert_ne!(
                    encoded[9] & 0x80,
                    0,
                    "authority must reuse the first tunnel's table"
                );
            }
            let fields = frame["Headers"].as_array().unwrap();
            assert_eq!(fields.len(), 5);
            assert_eq!(fields[0]["Name"], ":method");
            assert_eq!(fields[0]["Value"], "CONNECT");
            assert_eq!(fields[1]["Name"], ":authority");
            assert_eq!(fields[1]["Value"], "capture.invalid:443");
            assert_eq!(fields[4]["Name"], "user-agent");
            assert_eq!(fields[4]["Value"], "");
            assert!(fields.iter().all(
                |field| field["Name"] != "padding-type-request" && field["Sensitive"] == false
            ));
            let authorization = fields
                .iter()
                .find(|field| field["Name"] == "proxy-authorization")
                .unwrap();
            assert_eq!(authorization["Value"], "Basic dXNlcjpwYXNz");
            let padding = fields
                .iter()
                .find(|field| field["Name"] == "padding")
                .unwrap()["Value"]
                .as_str()
                .unwrap()
                .as_bytes();
            assert!((30..=61).contains(&padding.len()));
            assert!(
                padding[..16]
                    .iter()
                    .all(|byte| b"!#$()+<>?@[]^`{}".contains(byte))
            );
            assert!(padding[16..].iter().all(|byte| *byte == b'~'));
            assert_eq!(
                frames
                    .iter()
                    .filter(|frame| frame["Type"] == "DATA"
                        && frame["Stream"] == stream_id
                        && frame["Flags"].as_u64().unwrap() & 1 != 0)
                    .count(),
                1,
                "each tunnel must flush its FIN"
            );
        }
        assert!(frames.iter().all(|frame| frame["Type"] != "RST_STREAM"));
    })
    .await
    .expect("Naive reference observer test timed out");
}
