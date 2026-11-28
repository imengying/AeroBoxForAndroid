#![cfg(all(unix, feature = "cli"))]

use std::{net::Ipv4Addr, process::Stdio, time::Duration};

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use hickory_proto::{
    op::{Message, Query},
    rr::RecordType,
};
use reqwest::{Client, StatusCode, Version};
use serde_json::Value;
use tendns::names::canonical_name;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream, UdpSocket},
    process::{Child, Command},
    time::timeout,
};

const DEADLINE: Duration = Duration::from_secs(10);
const PATHS: [&str; 3] = ["/plain/dns", "/secure/dns", "/dns-query"];

fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tendns"));
    command.kill_on_drop(true);
    command
}

fn pem(label: &str, der: &[u8]) -> String {
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        STANDARD.encode(der)
    )
}

fn wire_query(kind: RecordType) -> Vec<u8> {
    let mut request = Message::query();
    request.metadata.id = 1234;
    request.metadata.recursion_desired = true;
    request.queries.push(Query::query(
        canonical_name("c0000201.hex.test").unwrap(),
        kind,
    ));
    request.to_vec().unwrap()
}

struct Fixture {
    process: Child,
    directory: tempfile::TempDir,
    ports: Vec<u16>,
    stderr: BufReader<tokio::process::ChildStderr>,
    cert: reqwest::Certificate,
}

impl Fixture {
    async fn start() -> Self {
        Self::start_with_https_http2(None).await
    }

    async fn start_with_https_http2(http2: Option<bool>) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let mut reserved = Vec::new();
        let mut ports = Vec::new();
        for _ in 0..3 {
            let socket = TcpListener::bind("0.0.0.0:0").await.unwrap();
            ports.push(socket.local_addr().unwrap().port());
            reserved.push(socket);
        }
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        std::fs::write(
            directory.path().join("server.crt"),
            pem("CERTIFICATE", cert.cert.der()),
        )
        .unwrap();
        std::fs::write(
            directory.path().join("server.key"),
            pem("PRIVATE KEY", &cert.signing_key.serialize_der()),
        )
        .unwrap();
        std::fs::write(
            directory.path().join("tokens.txt"),
            "file-token\r\n\r\nsecond-file-token\n",
        )
        .unwrap();
        std::fs::write(directory.path().join("empty.txt"), "\n\r\n").unwrap();
        let http2 = http2.map_or(String::new(), |enabled| format!("http2 = {enabled}"));
        std::fs::write(
            directory.path().join("config.toml"),
            format!(
                r#"
            hex_zones = ["hex.test"]
            request_timeout = "1s"
            [[listeners]]
            type = "http"
            address = "0.0.0.0:{}"
            path = "{http_path}"
            auth_tokens = ["inline-token"]
            auth_token_file = "tokens.txt"
            [[listeners]]
            type = "https"
            address = "0.0.0.0:{}"
            path = "{https_path}"
            {http2}
            cert = "server.crt"
            key = "server.key"
            auth_tokens = ["https-token"]
            [[listeners]]
            type = "http"
            address = "0.0.0.0:{}"
            auth_token_file = "empty.txt"
            [[upstreams]]
            type = "plain"
            address = "192.0.2.1:53"
        "#,
                ports[0],
                ports[1],
                ports[2],
                http_path = PATHS[0],
                https_path = PATHS[1],
            ),
        )
        .unwrap();
        drop(reserved);
        let mut process = command()
            .arg("--config")
            .arg(directory.path().join("config.toml"))
            .arg("serve")
            .stderr(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let mut stderr = BufReader::new(process.stderr.take().unwrap());
        let mut messages = String::new();
        timeout(DEADLINE, async {
            let mut listening = 0;
            while listening < 3 {
                let mut line = String::new();
                assert!(
                    stderr.read_line(&mut line).await.unwrap() > 0,
                    "startup stopped: {messages}"
                );
                if line.starts_with("listening on") {
                    listening += 1;
                }
                messages.push_str(&line);
            }
        })
        .await
        .unwrap();
        assert_eq!(messages.matches("authentication is disabled").count(), 1);
        assert!(messages.contains(&format!(
            "HTTP listener 0.0.0.0:{} has no auth tokens",
            ports[2]
        )));
        assert!(!messages.contains("inline-token"));
        for (listener, protocol) in ["HTTP", "HTTPS", "HTTP"].iter().enumerate() {
            assert!(messages.contains(&format!(
                "listening on 0.0.0.0:{} ({protocol}, {})",
                ports[listener], PATHS[listener]
            )));
        }
        Self {
            process,
            directory,
            ports,
            stderr,
            cert: reqwest::Certificate::from_der(cert.cert.der()).unwrap(),
        }
    }

    fn url(&self, listener: usize) -> String {
        let (scheme, host) = if listener == 1 {
            ("https", "localhost")
        } else {
            ("http", "127.0.0.1")
        };
        format!(
            "{scheme}://{host}:{}{}",
            self.ports[listener], PATHS[listener]
        )
    }

    async fn stop(mut self) {
        let status = Command::new("kill")
            .args(["-TERM", &self.process.id().unwrap().to_string()])
            .status()
            .await
            .unwrap();
        assert!(status.success());
        assert!(
            timeout(DEADLINE, self.process.wait())
                .await
                .unwrap()
                .unwrap()
                .success()
        );
        let mut diagnostics = String::new();
        self.stderr.read_to_string(&mut diagnostics).await.unwrap();
        assert!(diagnostics.is_empty(), "{diagnostics}");
        for port in self.ports {
            let _listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, port))
                .await
                .unwrap();
        }
    }
}

fn client() -> reqwest::ClientBuilder {
    Client::builder().no_proxy().timeout(DEADLINE)
}

#[tokio::test]
async fn doh_paths_match_exactly_and_are_independent_per_listener() {
    let fixture = Fixture::start().await;
    let http = client()
        .add_root_certificate(fixture.cert.clone())
        .build()
        .unwrap();
    for (listener, token) in [
        (0, Some("inline-token")),
        (1, Some("https-token")),
        (2, None),
    ] {
        let endpoint = reqwest::Url::parse(&fixture.url(listener)).unwrap();
        for path in [
            "/dns-query",
            "/plain/dns",
            "/secure/dns",
            "/plain/dns/",
            "/secure/dns/",
            "/plain/dns-extra",
            "/PLAIN/dns",
            "/SECURE/dns",
            "/%70lain/dns",
            "/%73ecure/dns",
            "/dns%2Dquery",
            "/",
        ] {
            let mut url = endpoint.clone();
            url.set_path(path);
            let mut request = http
                .get(url.clone())
                .query(&[("name", "c0000201.hex.test")]);
            if let Some(token) = token {
                request = request.bearer_auth(token);
            }
            let response = request.send().await.unwrap();
            let expected = if path == PATHS[listener] {
                StatusCode::OK
            } else {
                StatusCode::NOT_FOUND
            };
            assert_eq!(response.status(), expected, "{url}");
        }
    }
    fixture.stop().await;
}

#[tokio::test]
async fn https_http2_can_be_disabled_without_disabling_http1() {
    let fixture = Fixture::start_with_https_http2(Some(false)).await;
    let http = client()
        .add_root_certificate(fixture.cert.clone())
        .build()
        .unwrap();
    let response = http
        .get(fixture.url(1))
        .bearer_auth("https-token")
        .query(&[("name", "c0000201.hex.test")])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.version(), Version::HTTP_11);
    let http2 = client()
        .add_root_certificate(fixture.cert.clone())
        .http2_prior_knowledge()
        .build()
        .unwrap();
    assert!(
        http2
            .get(fixture.url(1))
            .bearer_auth("https-token")
            .query(&[("name", "c0000201.hex.test")])
            .send()
            .await
            .is_err()
    );
    fixture.stop().await;
}

#[tokio::test]
async fn doh_http_https_binary_json_auth_and_startup_only_credentials() {
    let fixture = Fixture::start().await;
    let http = client().http1_only().build().unwrap();
    let https = client()
        .add_root_certificate(fixture.cert.clone())
        .http2_prior_knowledge()
        .build()
        .unwrap();
    let binary = wire_query(RecordType::A);

    for token in ["inline-token", "file-token", "second-file-token"] {
        let response = http
            .get(fixture.url(0))
            .bearer_auth(token)
            .query(&[("dns", URL_SAFE_NO_PAD.encode(&binary))])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.version(), Version::HTTP_11);
        assert_eq!(
            response.headers()["content-type"],
            "application/dns-message"
        );
        assert_eq!(response.headers()["cache-control"], "no-store");
        let answer = Message::from_vec(&response.bytes().await.unwrap()).unwrap();
        assert_eq!(answer.metadata.id, 1234);
        assert_eq!(answer.answers[0].data.to_string(), "192.0.2.1");
        assert!(!answer.metadata.authentic_data);
    }
    let h2c = client().http2_prior_knowledge().build().unwrap();
    assert!(
        h2c.get(fixture.url(0))
            .bearer_auth("inline-token")
            .query(&[("name", "c0000201.hex.test")])
            .send()
            .await
            .is_err()
    );
    for listener in [0, 1] {
        let transport = if listener == 0 { &http } else { &https };
        for token in [
            None,
            Some("wrong"),
            Some(if listener == 0 {
                "https-token"
            } else {
                "inline-token"
            }),
        ] {
            let mut request = transport
                .get(fixture.url(listener))
                .query(&[("name", "c0000201.hex.test")]);
            if let Some(token) = token {
                request = request.bearer_auth(token);
            }
            let response = request.send().await.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(
                response.headers()["www-authenticate"],
                "Bearer realm=\"dns\""
            );
        }
    }
    let response = https
        .post(fixture.url(1))
        .bearer_auth("https-token")
        .header("content-type", "application/dns-message")
        .body(binary.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(response.version(), Version::HTTP_2);
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        Message::from_vec(&response.bytes().await.unwrap())
            .unwrap()
            .answers
            .len(),
        1
    );

    let response = https
        .get(fixture.url(1))
        .bearer_auth("https-token")
        .header("accept", "application/dns-json")
        .query(&[("name", "c0000201.hex.test"), ("type", "A")])
        .send()
        .await
        .unwrap();
    assert_eq!(response.headers()["content-type"], "application/dns-json");
    let answer: Value = response.json().await.unwrap();
    assert_eq!(answer["Status"], 0);
    assert_eq!(answer["Answer"][0]["data"], "192.0.2.1");
    assert_eq!(answer["Answer"][0]["type"], 1);
    assert_eq!(answer["AD"], false);
    assert_eq!(answer["Question"][0]["name"], "c0000201.hex.test.");

    for (name, kind, status) in [("c0000201.hex.test", "AAAA", 0), ("bad.hex.test", "A", 3)] {
        let answer: Value = http
            .get(fixture.url(2))
            .query(&[("name", name), ("type", kind)])
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(answer["Status"], status);
        assert_eq!(answer["Answer"].as_array().unwrap().len(), 0);
    }
    // A listener snapshots all three files before accepting any requests.
    for file in ["server.crt", "server.key", "tokens.txt"] {
        std::fs::remove_file(fixture.directory.path().join(file)).unwrap();
    }
    let fresh_tls = client()
        .add_root_certificate(fixture.cert.clone())
        .http1_only()
        .build()
        .unwrap();
    assert_eq!(
        fresh_tls
            .get(fixture.url(1))
            .bearer_auth("https-token")
            .query(&[("name", "c0000201.hex.test")])
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        http.get(fixture.url(0))
            .bearer_auth("file-token")
            .query(&[("name", "c0000201.hex.test")])
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert!(
        client()
            .build()
            .unwrap()
            .get(fixture.url(1))
            .send()
            .await
            .is_err()
    );
    assert!(
        client()
            .add_root_certificate(fixture.cert.clone())
            .build()
            .unwrap()
            .get(fixture.url(1).replace("localhost", "127.0.0.1"))
            .send()
            .await
            .is_err()
    );
    assert!(
        http.get(fixture.url(1).replace("https://", "http://"))
            .send()
            .await
            .is_err()
    );
    fixture.stop().await;
}

#[tokio::test]
async fn doh_accept_exhaustion_recovers_without_stopping_dns() {
    let directory = tempfile::tempdir().unwrap();
    let http = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let dns = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let http_port = http.local_addr().unwrap().port();
    let dns_port = dns.local_addr().unwrap().port();
    let udp = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, dns_port))
        .await
        .unwrap();
    let config = directory.path().join("config.toml");
    std::fs::write(
        &config,
        format!(
            r#"
            hex_zones = ["hex.test"]
            [[listeners]]
            type = "http"
            address = "0.0.0.0:{http_port}"
            auth_tokens = ["test-token"]
            [[listeners]]
            type = "dns"
            address = "0.0.0.0:{dns_port}"
            [[upstreams]]
            type = "plain"
            address = "192.0.2.1:53"
            "#
        ),
    )
    .unwrap();
    drop((http, dns, udp));
    let mut process = Command::new("sh")
        .args([
            "-c",
            "ulimit -n 64 || exit; exec \"$@\"",
            "doh-fd-limit",
            env!("CARGO_BIN_EXE_tendns"),
            "--config",
        ])
        .arg(&config)
        .arg("serve")
        .kill_on_drop(true)
        .stderr(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let mut stderr = BufReader::new(process.stderr.take().unwrap());
    timeout(DEADLINE, async {
        for _ in 0..2 {
            let mut line = String::new();
            assert!(stderr.read_line(&mut line).await.unwrap() > 0);
            assert!(line.starts_with("listening on"), "{line}");
        }
    })
    .await
    .unwrap();

    let mut sockets = Vec::new();
    for _ in 0..80 {
        let socket = timeout(
            DEADLINE,
            TcpStream::connect((Ipv4Addr::LOCALHOST, http_port)),
        )
        .await
        .unwrap();
        match socket {
            Ok(socket) => sockets.push(socket),
            Err(_) => break,
        }
    }
    timeout(DEADLINE, async {
        loop {
            let mut line = String::new();
            assert!(stderr.read_line(&mut line).await.unwrap() > 0);
            if line.contains("DoH accept failed") {
                break;
            }
        }
    })
    .await
    .unwrap();
    drop(sockets);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(process.try_wait().unwrap().is_none());

    let response = client()
        .build()
        .unwrap()
        .get(format!("http://127.0.0.1:{http_port}/dns-query"))
        .bearer_auth("test-token")
        .query(&[("name", "c0000201.hex.test")])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let answer: Value = response.json().await.unwrap();
    assert_eq!(answer["Answer"][0]["data"], "192.0.2.1");
    let udp = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    udp.send_to(&wire_query(RecordType::A), (Ipv4Addr::LOCALHOST, dns_port))
        .await
        .unwrap();
    let mut bytes = [0; 512];
    let (length, _) = timeout(DEADLINE, udp.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    let answer = Message::from_vec(&bytes[..length]).unwrap();
    assert_eq!(answer.answers[0].data.to_string(), "192.0.2.1");

    // An unfinished HTTP request must not prevent mixed DNS/DoH shutdown.
    let mut slow = TcpStream::connect((Ipv4Addr::LOCALHOST, http_port))
        .await
        .unwrap();
    slow.write_all(b"POST /dns-query HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer test-token\r\nContent-Type: application/dns-message\r\nContent-Length: 30\r\n\r\n")
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        Command::new("kill")
            .args(["-TERM", &process.id().unwrap().to_string()])
            .status()
            .await
            .unwrap()
            .success()
    );
    assert!(
        timeout(DEADLINE, process.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
    for port in [http_port, dns_port] {
        let _available = TcpListener::bind((Ipv4Addr::UNSPECIFIED, port))
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn doh_rejects_bad_http_requests_and_limits_body_reads() {
    let fixture = Fixture::start().await;
    let http = client().http1_only().build().unwrap();
    let base = fixture.url(2);
    for (suffix, status) in [
        ("?dns=not-base64!", StatusCode::BAD_REQUEST),
        ("?dns=AA", StatusCode::BAD_REQUEST),
        (
            "?name=c0000201.hex.test&name=other.test",
            StatusCode::BAD_REQUEST,
        ),
        (
            "?name=c0000201.hex.test&type=invalid",
            StatusCode::BAD_REQUEST,
        ),
        ("?name=c0000201.hex.test&dns=AAAA", StatusCode::BAD_REQUEST),
        ("?type=A", StatusCode::BAD_REQUEST),
        ("/other", StatusCode::NOT_FOUND),
    ] {
        assert_eq!(
            http.get(format!("{base}{suffix}"))
                .send()
                .await
                .unwrap()
                .status(),
            status,
            "{suffix}"
        );
    }
    let response = http.put(&base).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(response.headers()["allow"], "GET, POST");
    assert_eq!(
        http.get(&base)
            .query(&[("name", "c0000201.hex.test")])
            .header("accept", "text/html")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_ACCEPTABLE
    );
    assert_eq!(
        http.post(&base)
            .header("content-type", "application/json")
            .body("{}")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
    assert_eq!(
        http.post(&base)
            .header("content-type", "application/dns-message")
            .body(vec![0; 65_536])
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    let mut socket = TcpStream::connect((Ipv4Addr::LOCALHOST, fixture.ports[2]))
        .await
        .unwrap();
    socket.write_all(b"POST /dns-query HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/dns-message\r\nContent-Length: 30\r\n\r\n").await.unwrap();
    let mut line = String::new();
    timeout(DEADLINE, BufReader::new(socket).read_line(&mut line))
        .await
        .unwrap()
        .unwrap();
    assert!(line.contains("408"), "{line}");
    fixture.stop().await;
}

#[tokio::test]
async fn excessive_request_timeout_is_rejected_before_doh_startup() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    for settings in [
        "type='http'",
        "type='https'\ncert='server.crt'\nkey='server.key'",
    ] {
        let reserved = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let port = reserved.local_addr().unwrap().port();
        drop(reserved);
        std::fs::write(
            &path,
            format!("request_timeout='18446744073709551615s'\n[[listeners]]\naddress='0.0.0.0:{port}'\n{settings}\n[[upstreams]]\ntype='plain'\naddress='192.0.2.1:53'"),
        )
        .unwrap();
        let result = timeout(
            DEADLINE,
            command().arg("--config").arg(&path).arg("serve").output(),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(!result.status.success());
        let error = String::from_utf8(result.stderr).unwrap();
        assert!(
            error.contains("request_timeout must not exceed 24h"),
            "{error}"
        );
        assert!(!error.contains("listening on"));
        let _available = TcpListener::bind((Ipv4Addr::UNSPECIFIED, port))
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn bad_startup_credentials_never_advertise_a_listener_or_leak_tokens() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let other = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    std::fs::write(
        directory.path().join("valid.crt"),
        pem("CERTIFICATE", cert.cert.der()),
    )
    .unwrap();
    std::fs::write(
        directory.path().join("wrong.key"),
        pem("PRIVATE KEY", &other.signing_key.serialize_der()),
    )
    .unwrap();
    std::fs::write(directory.path().join("bad.txt"), "bad secret token\n").unwrap();
    let reserved = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let port = reserved.local_addr().unwrap().port();
    drop(reserved);
    for settings in [
        "type='https'\ncert='absent.crt'\nkey='absent.key'",
        "type='https'\ncert='valid.crt'\nkey='wrong.key'",
        "type='http'\nauth_token_file='absent.txt'",
        "type='http'\nauth_token_file='bad.txt'",
        "type='http'\nauth_tokens=['secret with whitespace']",
    ] {
        std::fs::write(&path, format!("[[listeners]]\naddress='0.0.0.0:{port}'\n{settings}\n[[upstreams]]\ntype='plain'\naddress='192.0.2.1:53'")).unwrap();
        let result = timeout(
            DEADLINE,
            command().arg("--config").arg(&path).arg("serve").output(),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(!result.status.success());
        let error = String::from_utf8(result.stderr).unwrap();
        assert!(error.contains(&format!("DoH listener 0.0.0.0:{port}")));
        assert!(!error.contains("listening on"));
        assert!(!error.contains("secret with whitespace"));
        assert!(!error.contains("bad secret token"));
        let _available = TcpListener::bind((Ipv4Addr::UNSPECIFIED, port))
            .await
            .unwrap();
    }
}
