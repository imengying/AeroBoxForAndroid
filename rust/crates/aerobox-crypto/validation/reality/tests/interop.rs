use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
    process::{Child, Command, Stdio},
    time::Duration,
};
struct Peer(Child);
impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn peer(group: u16, mode: &str, args: &[&str]) -> (Peer, TcpStream) {
    let mut child = Command::new(
        std::env::var_os("AEROBOX_TLS_PROFILE_PEER").expect("AEROBOX_TLS_PROFILE_PEER"),
    )
    .args([
        "-fixtures",
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures"),
        "-reality",
        mode,
        "-group",
        &group.to_string(),
    ])
    .args(args)
    .stdout(Stdio::piped())
    .stderr(Stdio::inherit())
    .spawn()
    .unwrap();
    let mut ready = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut ready)
        .unwrap();
    let ready: serde_json::Value = serde_json::from_str(&ready).unwrap();
    let socket = TcpStream::connect(("127.0.0.1", ready["port"].as_u64().unwrap() as u16)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    (Peer(child), socket)
}

#[test]
fn production_reality_authentication_uses_the_independent_share_with_go() {
    for (group, browser) in [(29, true), (29, false), (4588, false)] {
        let (_peer, mut socket) = peer(
            group,
            "valid",
            if browser {
                &["-server-settings", "01020304", "-reality-browser"]
            } else {
                &["-server-settings", "01020304"]
            },
        );
        let mut client = aerobox_reality_browser_validation::new_client(browser);
        while client.is_handshaking() {
            client.complete_io(&mut socket).unwrap();
        }
        assert_eq!(
            client.negotiated_key_exchange_group().unwrap().name(),
            rustls::NamedGroup::from(group)
        );
        assert_eq!(
            client.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );
        assert_eq!(
            client.peer_application_settings(),
            Some([1, 2, 3, 4].as_slice())
        );
        let input: Vec<_> = (0..65537).map(|n| (n % 251) as u8).collect();
        let mut output = vec![0; input.len()];
        let mut stream = rustls::Stream::new(&mut client, &mut socket);
        stream.write_all(&input).unwrap();
        stream.flush().unwrap();
        stream.read_exact(&mut output).unwrap();
        assert_eq!(input, output);
        client.send_close_notify();
        client.write_tls(&mut socket).unwrap();
    }
}

#[test]
fn production_reality_rejects_bad_authentication_signatures_finished_and_hrr() {
    for (mode, group, args) in [
        ("bad-hmac", 29, vec![]),
        ("bad-signature", 29, vec![]),
        ("bad-short-id", 29, vec![]),
        ("valid", 29, vec!["-bad-finished"]),
        ("valid", 23, vec![]),
        ("valid", 29, vec!["-cookie-retry"]),
    ] {
        let mut args = args;
        args.push("-reality-browser");
        let (_peer, mut socket) = peer(group, mode, &args);
        let mut client = aerobox_reality_browser_validation::new_client(true);
        let result: std::io::Result<()> = (|| {
            while client.is_handshaking() {
                client.complete_io(&mut socket)?;
            }
            Ok(())
        })();
        assert!(result.is_err(), "mode={mode} group={group} args={args:?}");
        assert!(
            client.peer_application_settings().is_none(),
            "settings must remain unpublished before authenticated Finished"
        );
    }
}
