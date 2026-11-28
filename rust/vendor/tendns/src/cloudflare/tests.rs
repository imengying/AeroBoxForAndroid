use super::*;
use bytes::Bytes;
use serde_json::{Value as Json, json};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};
use tokio_rustls::TlsAcceptor;

const KEY: &str = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc";
const ZONE: &str = "11111111111111111111111111111111";
const RECORD: &str = "22222222222222222222222222222222";
const TOKEN: &str = "test-cloudflare-token-do-not-log";

struct Step {
    method: Method,
    path: String,
    status: u16,
    response: Option<Json>,
}

#[derive(Clone)]
struct Call {
    url: Url,
    body: Json,
}

struct Fixture {
    api: Cloudflare,
    steps: Arc<Mutex<VecDeque<Step>>>,
    calls: Arc<Mutex<Vec<Call>>>,
    stop: oneshot::Sender<()>,
    task: JoinHandle<()>,
}

impl Fixture {
    async fn start(steps: Vec<Step>) -> Self {
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.cert.der().clone()], key.into())
            .unwrap();
        tls.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(tls));
        let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let api = Cloudflare {
            client: Cloudflare::client_builder(TOKEN)
                .unwrap()
                .tls_certs_only([reqwest::Certificate::from_der(cert.cert.der()).unwrap()])
                .no_proxy()
                .timeout(Duration::from_secs(2))
                .build()
                .unwrap(),
            base: format!("https://127.0.0.1:{port}/client/v4/")
                .parse()
                .unwrap(),
        };
        let steps = Arc::new(Mutex::new(VecDeque::from(steps)));
        let calls = Arc::new(Mutex::new(Vec::new()));
        let pending = steps.clone();
        let recorded = calls.clone();
        let (stop, mut shutdown) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                let (socket, _) = tokio::select! {
                    _ = &mut shutdown => break,
                    Some(result) = connections.join_next(), if !connections.is_empty() => { result.unwrap(); continue; }
                    socket = listener.accept() => socket.unwrap(),
                };
                let acceptor = acceptor.clone();
                let pending = pending.clone();
                let recorded = recorded.clone();
                connections.spawn(async move {
                    let Ok(tls) = acceptor.accept(socket).await else { return; };
                    let mut connection = h2::server::handshake(tls).await.unwrap();
                    let mut handlers = tokio::task::JoinSet::new();
                    loop {
                        let request = tokio::select! {
                            Some(result) = handlers.join_next(), if !handlers.is_empty() => { result.unwrap(); continue; }
                            request = connection.accept() => request,
                        };
                        let Some(Ok((request, mut sender))) = request else { break; };
                        let pending = pending.clone();
                        let recorded = recorded.clone();
                        handlers.spawn(async move {
                            let step = pending.lock().unwrap().pop_front().expect("unexpected API request");
                            assert_eq!(request.method(), step.method);
                            assert_eq!(request.uri().path(), step.path);
                            assert_eq!(request.headers()["authorization"], format!("Bearer {TOKEN}"));
                            let url = Url::parse(&format!("https://api.test{}", request.uri().path_and_query().unwrap())).unwrap();
                            let mut body = request.into_body();
                            let mut bytes = Vec::new();
                            while let Some(chunk) = body.data().await {
                                let chunk = chunk.unwrap();
                                body.flow_control().release_capacity(chunk.len()).unwrap();
                                bytes.extend_from_slice(&chunk);
                            }
                            let body: Json = if bytes.is_empty() { Json::Null } else { serde_json::from_slice(&bytes).unwrap() };
                            recorded.lock().unwrap().push(Call { url, body: body.clone() });
                            let response = step.response.unwrap_or_else(|| {
                                let mut record = body;
                                record["id"] = json!(RECORD);
                                // Equivalent provider normalization must not fail write verification.
                                record["content"] = json!(record["content"].as_str().unwrap().replace("td1.", r"td\049."));
                                json!({"success": true, "result": record})
                            });
                            let response_headers = http::Response::builder().status(step.status)
                                .header("content-type", "application/json")
                                .header("location", "https://127.0.0.1:9/should-not-follow")
                                .body(()).unwrap();
                            sender.send_response(response_headers, false).unwrap()
                                .send_data(Bytes::from(serde_json::to_vec(&response).unwrap()), true).unwrap();
                        });
                    }
                    while let Some(result) = handlers.join_next().await { result.unwrap(); }
                });
            }
            connections.abort_all();
            while let Some(result) = connections.join_next().await {
                if let Err(error) = result {
                    assert!(error.is_cancelled(), "API fixture failed: {error}");
                }
            }
        });
        Self {
            api,
            steps,
            calls,
            stop,
            task,
        }
    }

    async fn finish(self) -> Vec<Call> {
        assert!(
            self.steps.lock().unwrap().is_empty(),
            "unconsumed API steps"
        );
        let _ = self.stop.send(());
        tokio::time::timeout(Duration::from_secs(3), self.task)
            .await
            .unwrap()
            .unwrap();
        self.calls.lock().unwrap().clone()
    }
}

fn get(path: &str, result: Json, page: u32, total_pages: u32) -> Step {
    Step {
        method: Method::GET,
        path: format!("/client/v4/{path}"),
        status: 200,
        response: Some(
            json!({"success": true, "result": result, "result_info": {"page": page, "total_pages": total_pages}}),
        ),
    }
}

fn zone(name: &str) -> Step {
    get("zones", json!([{"id": ZONE, "name": name}]), 1, 1)
}

fn records(values: Vec<Json>) -> Step {
    get(&format!("zones/{ZONE}/dns_records"), json!(values), 1, 1)
}

fn write(method: Method) -> Step {
    let path = if method == Method::POST {
        format!("zones/{ZONE}/dns_records")
    } else {
        format!("zones/{ZONE}/dns_records/{RECORD}")
    };
    Step {
        method,
        path: format!("/client/v4/{path}"),
        status: 200,
        response: None,
    }
}

fn config() -> Config {
    Config::parse(&format!("[[discovery]]\ndomain='example.com'\nkey='{KEY}'")).unwrap()
}

fn address(label: &str, ip: &str) -> Entry {
    Entry {
        subdomain: label.into(),
        value: Value::A(ip.parse().unwrap()),
    }
}

fn publication(entries: Vec<Entry>) -> Publication {
    let now = SystemClock.now().unwrap();
    Publication {
        issued_at: now,
        expires_at: now + 3600,
        entries,
    }
}

fn record(config: &Config, owner: &str, publication: &Publication) -> Json {
    let name = canonical_name(owner).unwrap();
    let content = protocol::encrypt(
        publication,
        &config.discovery_for(&name).unwrap().key,
        &name,
    )
    .unwrap();
    json!({"id": RECORD, "name": owner, "type": "TXT", "ttl": 120, "content": txt_content(&content, &name).unwrap()})
}

fn set(ip: &str) -> Change {
    Change::Set {
        values: vec![Value::A(ip.parse().unwrap())],
        valid_for: Duration::from_secs(7200),
    }
}

fn written_publication(call: &Call, config: &Config) -> Publication {
    let owner = canonical_name(call.body["name"].as_str().unwrap()).unwrap();
    protocol::decrypt_for_update(
        &txt_bytes(call.body["content"].as_str().unwrap()).unwrap(),
        &config.discovery_for(&owner).unwrap().key,
        &owner,
    )
    .unwrap()
}

#[test]
fn txt_presentation_roundtrips_chunks_and_provider_limits() {
    let owner = canonical_name("example.com").unwrap();
    let value = format!("td1.{}", "a".repeat(700));
    let encoded = txt_content(&value, &owner).unwrap();
    assert_eq!(encoded.matches('"').count(), 6);
    assert_eq!(txt_bytes(&encoded).unwrap(), value.as_bytes());
    assert_eq!(txt_bytes(&value).unwrap(), value.as_bytes());
    assert!(txt_content(&"a".repeat(4096), &owner).is_err());
}

#[test]
fn txt_presentation_decodes_decimal_escapes_and_preserves_literal_text() {
    assert_eq!(
        txt_bytes(r#""td\049." "ciphertext""#).unwrap(),
        b"td1.ciphertext"
    );
    assert_eq!(
        txt_bytes(r#""\000\255\\\"""#).unwrap(),
        [0, 255, b'\\', b'"']
    );
    assert_eq!(txt_bytes(r#" "a""b" "c" "#).unwrap(), b"abc");
    for literal in [
        "smile :) ok",
        "a(b)c",
        "$a",
        "@",
        "unquoted spaces",
        r"td\049.literal",
    ] {
        assert_eq!(txt_bytes(literal).unwrap(), literal.as_bytes());
    }
    for invalid in [
        r#""td\49.""#,
        r#""td\256.""#,
        r#""td\12x.""#,
        r#""unterminated"#,
        r#""closed" trailing"#,
    ] {
        assert!(txt_bytes(invalid).is_err(), "{invalid}");
    }
}

#[tokio::test]
async fn creates_parent_txt_without_sending_hidden_name_or_address() {
    let config = config();
    let fixture = Fixture::start(vec![
        zone("example.com"),
        records(vec![]),
        write(Method::POST),
    ])
    .await;
    let result = fixture
        .api
        .change(
            &config,
            &canonical_name("nas.example.com").unwrap(),
            false,
            set("192.0.2.1"),
        )
        .await
        .unwrap();
    assert_eq!(result.action, "created");
    assert_eq!(result.owner.to_ascii(), "example.com.");
    let calls = fixture.finish().await;
    assert!(
        calls[0]
            .url
            .query_pairs()
            .any(|(key, value)| key == "name" && value == "example.com")
    );
    assert!(
        calls[1]
            .url
            .query_pairs()
            .any(|(key, value)| key == "name.exact" && value == "example.com")
    );
    assert!(
        calls[1]
            .url
            .query_pairs()
            .any(|(key, value)| key == "type" && value == "TXT")
    );
    assert!(calls.iter().all(|call| !call.url.as_str().contains("nas")));
    let body = &calls[2].body;
    assert_eq!(body["type"], "TXT");
    assert_eq!(body["ttl"], 60);
    assert_eq!(body.as_object().unwrap().len(), 4);
    assert!(!body.to_string().contains("192.0.2.1"));
    let publication = written_publication(&calls[2], &config);
    assert_eq!(publication.entries, vec![address("nas", "192.0.2.1")]);
    assert_eq!(publication.expires_at - publication.issued_at, 7200);
}

#[tokio::test]
async fn appends_to_existing_array_and_replaces_only_selected_hostname_and_type() {
    for existing_a in [false, true] {
        let config = config();
        let mut entries = vec![
            address("other", "192.0.2.99"),
            Entry {
                subdomain: "nas".into(),
                value: Value::Aaaa("2001:db8::1".parse().unwrap()),
            },
        ];
        if existing_a {
            entries.extend([address("nas", "192.0.2.2"), address("nas", "192.0.2.3")]);
        }
        let mut old = publication(entries.clone());
        old.issued_at = 100;
        old.expires_at = 200;
        let mut data = record(&config, "example.com", &old);
        data["content"] = json!(
            data["content"]
                .as_str()
                .unwrap()
                .replace("td1.", r"td\049.")
        );
        assert!(
            protocol::decrypt(
                &txt_bytes(data["content"].as_str().unwrap()).unwrap(),
                &config.policy.discovery()[0].key,
                &canonical_name("example.com").unwrap(),
                200
            )
            .is_err()
        );
        let ordinary = json!({"id": "33333333333333333333333333333333", "name": "example.com", "type": "TXT", "ttl": 300, "content": "\"v=spf1 -all\""});
        let fixture = Fixture::start(vec![
            zone("example.com"),
            records(vec![ordinary, data]),
            write(Method::PATCH),
        ])
        .await;
        let values = vec![
            Value::A("192.0.2.4".parse().unwrap()),
            Value::A("192.0.2.5".parse().unwrap()),
            Value::A("192.0.2.4".parse().unwrap()),
        ];
        fixture
            .api
            .change(
                &config,
                &canonical_name("nas.example.com").unwrap(),
                false,
                Change::Set {
                    values,
                    valid_for: Duration::from_secs(7200),
                },
            )
            .await
            .unwrap();
        let calls = fixture.finish().await;
        let updated = written_publication(&calls[2], &config);
        entries.retain(|entry| entry.subdomain != "nas" || !matches!(entry.value, Value::A(_)));
        entries.extend([address("nas", "192.0.2.4"), address("nas", "192.0.2.5")]);
        assert_eq!(updated.entries, entries);
        assert!(updated.issued_at > old.expires_at);
        assert_eq!(updated.expires_at - updated.issued_at, 7200);
        assert!(!calls[2].body.as_object().unwrap().contains_key("tags"));
        assert!(!calls[2].body.as_object().unwrap().contains_key("comment"));
    }
}

#[tokio::test]
async fn removal_preserves_other_entries_and_times_or_deletes_empty_txt() {
    for last in [false, true] {
        let config = config();
        let mut original = publication(vec![address("nas", "192.0.2.1")]);
        if !last {
            original.entries.push(address("other", "192.0.2.2"));
        }
        let mut mutation = write(if last { Method::DELETE } else { Method::PATCH });
        if last {
            mutation.response = Some(json!({"success": true, "result": {"id": RECORD}}));
        }
        let fixture = Fixture::start(vec![
            zone("example.com"),
            records(vec![record(&config, "example.com", &original)]),
            mutation,
        ])
        .await;
        let result = fixture
            .api
            .change(
                &config,
                &canonical_name("nas.example.com").unwrap(),
                false,
                Change::Remove {
                    kind: RecordType::A,
                },
            )
            .await
            .unwrap();
        let calls = fixture.finish().await;
        if last {
            assert_eq!(result.action, "deleted");
            assert!(calls[2].body.is_null());
        } else {
            let updated = written_publication(&calls[2], &config);
            assert_eq!(updated.entries, vec![address("other", "192.0.2.2")]);
            assert_eq!(
                (updated.issued_at, updated.expires_at),
                (original.issued_at, original.expires_at)
            );
            assert_eq!(calls[2].body["ttl"], 120);
        }
    }
}

#[tokio::test]
async fn pagination_finds_existing_record_before_deciding_to_create() {
    let config = config();
    let fixture = Fixture::start(vec![
        zone("example.com"),
        get(&format!("zones/{ZONE}/dns_records"), json!([]), 1, 2),
        get(
            &format!("zones/{ZONE}/dns_records"),
            json!([record(
                &config,
                "example.com",
                &publication(vec![address("other", "192.0.2.1")])
            )]),
            2,
            2,
        ),
        write(Method::PATCH),
    ])
    .await;
    fixture
        .api
        .change(
            &config,
            &canonical_name("nas.example.com").unwrap(),
            false,
            set("192.0.2.2"),
        )
        .await
        .unwrap();
    let calls = fixture.finish().await;
    assert!(
        calls[2]
            .url
            .query_pairs()
            .any(|(key, value)| key == "page" && value == "2")
    );
    assert_eq!(written_publication(&calls[3], &config).entries.len(), 2);
}

#[tokio::test]
async fn refuses_ambiguous_or_invalid_ciphertexts_without_writing() {
    let config = config();
    let valid = record(
        &config,
        "example.com",
        &publication(vec![address("nas", "192.0.2.1")]),
    );
    for content in ["td1.invalid", "td2.unknown"] {
        let mut bad = valid.clone();
        bad["content"] = json!(content);
        let fixture = Fixture::start(vec![zone("example.com"), records(vec![bad])]).await;
        assert!(
            fixture
                .api
                .change(
                    &config,
                    &canonical_name("nas.example.com").unwrap(),
                    false,
                    set("192.0.2.2")
                )
                .await
                .is_err()
        );
        fixture.finish().await;
    }
    let mut second = valid.clone();
    second["id"] = json!("33333333333333333333333333333333");
    let fixture = Fixture::start(vec![zone("example.com"), records(vec![valid, second])]).await;
    assert!(
        fixture
            .api
            .change(
                &config,
                &canonical_name("nas.example.com").unwrap(),
                false,
                set("192.0.2.2")
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("multiple encrypted")
    );
    fixture.finish().await;
}

#[tokio::test]
async fn cname_conflicts_and_missing_removals_do_not_write() {
    let config = config();
    let alias = Entry {
        subdomain: "nas".into(),
        value: Value::Cname(canonical_name("target.net").unwrap()),
    };
    for (existing, change) in [
        (alias.clone(), set("192.0.2.1")),
        (
            address("nas", "192.0.2.1"),
            Change::Set {
                values: vec![alias.value],
                valid_for: Duration::from_secs(3600),
            },
        ),
        (
            address("other", "192.0.2.1"),
            Change::Remove {
                kind: RecordType::A,
            },
        ),
    ] {
        let fixture = Fixture::start(vec![
            zone("example.com"),
            records(vec![record(
                &config,
                "example.com",
                &publication(vec![existing]),
            )]),
        ])
        .await;
        assert!(
            fixture
                .api
                .change(
                    &config,
                    &canonical_name("nas.example.com").unwrap(),
                    false,
                    change
                )
                .await
                .is_err()
        );
        fixture.finish().await;
    }
}

#[tokio::test]
async fn direct_mode_respects_nested_keys_and_checks_parent_precedence() {
    let other_key = protocol::Secret::generate().unwrap();
    let config = Config::parse(&format!("[[discovery]]\ndomain='example.com'\nkey='{KEY}'\n[[discovery]]\ndomain='nas.example.com'\nkey='{other_key}'")).unwrap();
    let name = canonical_name("nas.example.com").unwrap();
    let fixture = Fixture::start(vec![]).await;
    assert!(
        fixture
            .api
            .change(&config, &name, false, set("192.0.2.1"))
            .await
            .unwrap_err()
            .to_string()
            .contains("--direct")
    );
    fixture.finish().await;
    let fixture = Fixture::start(vec![
        get("zones", json!([]), 1, 0),
        zone("example.com"),
        records(vec![]),
        write(Method::POST),
    ])
    .await;
    fixture
        .api
        .change(&config, &name, true, set("192.0.2.1"))
        .await
        .unwrap();
    let calls = fixture.finish().await;
    let publication = written_publication(&calls[3], &config);
    assert_eq!(publication.entries[0].subdomain, "");
    assert!(
        protocol::decrypt(
            &txt_bytes(calls[3].body["content"].as_str().unwrap()).unwrap(),
            &protocol::Secret::decode(KEY).unwrap(),
            &name,
            SystemClock.now().unwrap()
        )
        .is_err()
    );

    let config = super::tests::config();
    let mut hidden = record(
        &config,
        "example.com",
        &super::tests::publication(vec![Entry {
            subdomain: "nas".into(),
            value: Value::Aaaa("2001:db8::1".parse().unwrap()),
        }]),
    );
    hidden["content"] = json!(
        hidden["content"]
            .as_str()
            .unwrap()
            .replace("td1.", r"td\049.")
    );
    let fixture = Fixture::start(vec![
        get("zones", json!([]), 1, 0),
        zone("example.com"),
        zone("example.com"),
        records(vec![]),
        records(vec![hidden]),
    ])
    .await;
    assert!(
        fixture
            .api
            .change(&config, &name, true, set("192.0.2.1"))
            .await
            .unwrap_err()
            .to_string()
            .contains("shadows")
    );
    fixture.finish().await;
}

#[tokio::test]
async fn api_failures_and_redirects_do_not_retry_or_echo_secrets() {
    for (status, response) in [
        (401, json!({"error": TOKEN})),
        (429, json!({"error": TOKEN})),
        (500, json!({"error": TOKEN})),
        (302, json!({"error": TOKEN})),
        (
            200,
            json!({"success": false, "result": null, "errors": [TOKEN]}),
        ),
        (200, json!({"success": TOKEN})),
    ] {
        let fixture = Fixture::start(vec![Step {
            method: Method::GET,
            path: "/client/v4/zones".into(),
            status,
            response: Some(response),
        }])
        .await;
        let error = fixture
            .api
            .change(
                &config(),
                &canonical_name("nas.example.com").unwrap(),
                false,
                set("192.0.2.1"),
            )
            .await
            .unwrap_err();
        assert!(!format!("{error:#}").contains(TOKEN));
        assert_eq!(fixture.finish().await.len(), 1);
    }
}

#[tokio::test]
async fn ipv6_and_cname_values_can_be_added_and_replaced() {
    for value in [
        Value::Aaaa("2001:db8::2".parse().unwrap()),
        Value::Cname(canonical_name("new.target.net").unwrap()),
    ] {
        let config = config();
        let existing = Entry {
            subdomain: "nas".into(),
            value: match &value {
                Value::Aaaa(_) => Value::Aaaa("2001:db8::1".parse().unwrap()),
                _ => Value::Cname(canonical_name("old.target.net").unwrap()),
            },
        };
        let fixture = Fixture::start(vec![
            zone("example.com"),
            records(vec![record(
                &config,
                "example.com",
                &publication(vec![existing]),
            )]),
            write(Method::PATCH),
        ])
        .await;
        fixture
            .api
            .change(
                &config,
                &canonical_name("nas.example.com").unwrap(),
                false,
                Change::Set {
                    values: vec![value.clone()],
                    valid_for: Duration::from_secs(3600),
                },
            )
            .await
            .unwrap();
        let calls = fixture.finish().await;
        assert_eq!(
            written_publication(&calls[2], &config).entries,
            vec![Entry {
                subdomain: "nas".into(),
                value
            }]
        );
    }
}

#[tokio::test]
async fn direct_mode_allows_valid_parent_misses_but_rejects_broken_parents() {
    let config = config();
    let name = canonical_name("nas.example.com").unwrap();
    for mode in ["valid", "expired", "cname", "invalid", "malformed"] {
        let mut steps = vec![
            get("zones", json!([]), 1, 0),
            zone("example.com"),
            zone("example.com"),
        ];
        if mode == "cname" {
            steps.push(records(vec![json!({"id": RECORD, "name": "example.com", "type": "CNAME", "content": "target.net", "ttl": 60})]));
        } else {
            steps.push(records(vec![]));
            let mut parent = publication(vec![address("other", "192.0.2.1")]);
            if mode == "expired" {
                parent.issued_at = 100;
                parent.expires_at = 200;
            }
            let mut parent = record(&config, "example.com", &parent);
            if mode == "invalid" {
                parent["content"] = json!("td1.invalid");
            }
            if mode == "malformed" {
                parent["content"] = json!("\"unterminated");
            }
            steps.push(records(vec![parent]));
            if mode == "valid" {
                steps.extend([records(vec![]), write(Method::POST)]);
            }
        }
        let fixture = Fixture::start(steps).await;
        let result = fixture
            .api
            .change(&config, &name, true, set("192.0.2.2"))
            .await;
        assert_eq!(result.is_ok(), mode == "valid", "{mode}");
        if mode == "malformed" {
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("parent TXT has invalid content")
            );
        }
        let calls = fixture.finish().await;
        if mode == "valid" {
            assert_eq!(
                written_publication(calls.last().unwrap(), &config).entries,
                vec![address("", "192.0.2.2")]
            );
        }
    }
}

#[tokio::test]
async fn refusal_limits_and_wrong_keys_never_mutate_dns() {
    let config = config();
    let other = Config::parse(&format!(
        "[[discovery]]\ndomain='example.com'\nkey='{}'",
        protocol::Secret::generate().unwrap()
    ))
    .unwrap();
    let ordinary = json!({"id": RECORD, "name": "example.com", "type": "TXT", "content": "\"v=spf1 -all\"", "ttl": 60});
    for records_at_owner in [
        vec![ordinary; 16],
        vec![record(
            &other,
            "example.com",
            &publication(vec![address("other", "192.0.2.1")]),
        )],
    ] {
        let fixture = Fixture::start(vec![zone("example.com"), records(records_at_owner)]).await;
        assert!(
            fixture
                .api
                .change(
                    &config,
                    &canonical_name("nas.example.com").unwrap(),
                    false,
                    set("192.0.2.2")
                )
                .await
                .is_err()
        );
        fixture.finish().await;
    }
}

#[tokio::test]
async fn write_errors_are_not_retried() {
    let config = config();
    let mut mutation = write(Method::POST);
    mutation.status = 500;
    mutation.response = Some(json!({"error": TOKEN}));
    let fixture = Fixture::start(vec![zone("example.com"), records(vec![]), mutation]).await;
    let error = fixture
        .api
        .change(
            &config,
            &canonical_name("nas.example.com").unwrap(),
            false,
            set("192.0.2.1"),
        )
        .await
        .unwrap_err();
    assert!(!format!("{error:#}").contains(TOKEN));
    assert_eq!(fixture.finish().await.len(), 3);
}

#[tokio::test]
async fn owner_limits_allow_sixteenth_txt_but_reject_combined_size_overflow() {
    for (contents, allowed) in [
        (vec!["ordinary TXT".to_owned(); 15], true),
        (
            vec!["x".repeat(4000), "y".repeat(4000), "z".repeat(180)],
            false,
        ),
    ] {
        let existing = contents.into_iter().enumerate().map(|(i, content)| {
            json!({"id": format!("{:032x}", i + 3), "name": "example.com", "type": "TXT", "ttl": 60, "content": content})
        }).collect();
        let mut steps = vec![zone("example.com"), records(existing)];
        if allowed {
            steps.push(write(Method::POST));
        }
        let fixture = Fixture::start(steps).await;
        let result = fixture
            .api
            .change(
                &config(),
                &canonical_name("nas.example.com").unwrap(),
                false,
                set("192.0.2.1"),
            )
            .await;
        if allowed {
            assert_eq!(result.unwrap().action, "created");
        } else {
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("combined content limit")
            );
        }
        fixture.finish().await;
    }
}

#[tokio::test]
async fn write_result_must_echo_requested_ciphertext() {
    let config = config();
    let original = record(
        &config,
        "example.com",
        &publication(vec![address("nas", "192.0.2.1")]),
    );
    for malformed in [false, true] {
        let mut echoed = original.clone();
        if malformed {
            echoed["content"] = json!("\"unterminated");
        }
        let mut mutation = write(Method::PATCH);
        mutation.response = Some(json!({"success": true, "result": echoed}));
        let fixture = Fixture::start(vec![
            zone("example.com"),
            records(vec![original.clone()]),
            mutation,
        ])
        .await;
        let error = fixture
            .api
            .change(
                &config,
                &canonical_name("nas.example.com").unwrap(),
                false,
                set("192.0.2.2"),
            )
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("check publication status before retrying")
        );
        assert_eq!(fixture.finish().await.len(), 3);
    }
}

#[tokio::test]
async fn https_client_rejects_plaintext_and_untrusted_certificates() {
    let fixture = Fixture::start(vec![]).await;
    let mut api = Cloudflare::new(TOKEN).unwrap();
    api.base = fixture.api.base.clone();
    assert!(
        api.find_zone(&canonical_name("example.com").unwrap())
            .await
            .is_err()
    );
    api.base.set_scheme("http").unwrap();
    assert!(
        api.find_zone(&canonical_name("example.com").unwrap())
            .await
            .is_err()
    );
    assert!(fixture.finish().await.is_empty());
}
