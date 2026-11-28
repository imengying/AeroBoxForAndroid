#![cfg(all(unix, feature = "cli"))]

use std::{
    net::{Ipv4Addr, SocketAddr},
    process::Stdio,
    time::Duration,
};

use hickory_proto::{
    op::{Message, OpCode, Query, ResponseCode},
    rr::{
        RData, Record, RecordType,
        rdata::{A, TXT},
    },
};
use tendns::names::canonical_name;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream, UdpSocket},
    process::Command,
    time::timeout,
};

const DEADLINE: Duration = Duration::from_secs(5);

fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tendns"));
    command.kill_on_drop(true);
    command
}

#[tokio::test]
async fn generated_key_and_txt_work_through_the_server_process_and_sigterm() {
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("tendns.toml");
    let generated = timeout(DEADLINE, command().arg("keygen").output())
        .await
        .unwrap()
        .unwrap();
    assert!(generated.status.success());
    let key = String::from_utf8(generated.stdout).unwrap();
    let publisher_socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    let publisher_port = publisher_socket.local_addr().unwrap().port();
    let reserved_tcp = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let port = reserved_tcp.local_addr().unwrap().port();
    let reserved_udp = UdpSocket::bind(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), port))
        .await
        .unwrap();
    std::fs::write(&config_path, format!(
        "listeners=[{{type='dns', address='0.0.0.0:{port}'}}]\n[[upstreams]]\ntype='plain'\naddress='127.0.0.1:{publisher_port}'\n[[discovery]]\ndomain='example.com'\nkey='{}'", key.trim()
    )).unwrap();
    let generated = timeout(
        DEADLINE,
        command()
            .arg("--config")
            .arg(&config_path)
            .args([
                "txt",
                "--name",
                "example.com",
                "--subdomain",
                "nas",
                "--a",
                "192.0.2.42",
            ])
            .output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(generated.status.success());
    let value = String::from_utf8(generated.stdout).unwrap();
    let publisher = tokio::spawn(async move {
        let mut bytes = [0; 4096];
        let (len, peer) = timeout(DEADLINE, publisher_socket.recv_from(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        let request = Message::from_vec(&bytes[..len]).unwrap();
        assert_eq!(
            request.queries,
            vec![Query::query(
                canonical_name("example.com").unwrap(),
                RecordType::TXT
            )]
        );
        let mut response = Message::response(request.metadata.id, OpCode::Query);
        response.queries = request.queries;
        response.answers.push(Record::from_rdata(
            canonical_name("example.com").unwrap(),
            60,
            RData::TXT(TXT::from_bytes(
                value.trim().as_bytes().chunks(20).collect(),
            )),
        ));
        publisher_socket
            .send_to(&response.to_vec().unwrap(), peer)
            .await
            .unwrap();
    });
    drop(reserved_tcp);
    drop(reserved_udp);
    let mut server = command()
        .arg("--config")
        .arg(&config_path)
        .arg("serve")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stderr = BufReader::new(server.stderr.take().unwrap());
    let mut startup = String::new();
    timeout(DEADLINE, stderr.read_line(&mut startup))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(startup, format!("listening on 0.0.0.0:{port} (UDP/TCP)\n"));
    let mut stream = timeout(DEADLINE, TcpStream::connect((Ipv4Addr::LOCALHOST, port)))
        .await
        .unwrap()
        .unwrap();
    let mut request = Message::query();
    request.metadata.id = 1234;
    request.queries.push(Query::query(
        canonical_name("nas.example.com").unwrap(),
        RecordType::A,
    ));
    let bytes = request.to_vec().unwrap();
    timeout(DEADLINE, async {
        stream.write_u16(bytes.len() as u16).await.unwrap();
        stream.write_all(&bytes).await.unwrap();
        let len = stream.read_u16().await.unwrap();
        let mut bytes = vec![0; len as usize];
        stream.read_exact(&mut bytes).await.unwrap();
        let response = Message::from_vec(&bytes).unwrap();
        assert_eq!(response.metadata.id, 1234);
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert_eq!(
            response.answers[0].data,
            RData::A(A("192.0.2.42".parse().unwrap()))
        );
    })
    .await
    .unwrap();
    drop(stream);
    timeout(DEADLINE, publisher).await.unwrap().unwrap();
    let status = timeout(
        DEADLINE,
        Command::new("kill")
            .args(["-TERM", &server.id().unwrap().to_string()])
            .status(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(status.success());
    assert!(
        timeout(DEADLINE, server.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
    let mut rest = String::new();
    stderr.read_to_string(&mut rest).await.unwrap();
    assert!(rest.is_empty(), "unexpected shutdown diagnostics: {rest}");
    // Shutdown must release both sockets, not merely stop responding to queries.
    let _tcp = TcpListener::bind(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), port))
        .await
        .unwrap();
    let _udp = UdpSocket::bind(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), port))
        .await
        .unwrap();
}

#[tokio::test]
async fn partial_bind_failure_releases_udp_and_does_not_advertise_startup() {
    let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("tendns.toml");
    std::fs::write(
        &path,
        format!("listeners=[{{type='dns', address='0.0.0.0:{port}'}}]\n[[upstreams]]\ntype='plain'\naddress='192.0.2.1:53'"),
    )
    .unwrap();
    let result = timeout(
        DEADLINE,
        command().arg("--config").arg(path).arg("serve").output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    let error = String::from_utf8(result.stderr).unwrap();
    assert!(error.contains("cannot bind TCP listener"));
    assert!(!error.contains("listening on"));
    let _udp = UdpSocket::bind(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), port))
        .await
        .unwrap();
}
