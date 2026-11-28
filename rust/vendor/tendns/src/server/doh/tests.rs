use super::*;
use crate::names::canonical_name;

#[test]
fn bearer_auth_combines_sources_without_reloading_or_leaking_tokens() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("tokens");
    std::fs::write(&path, "file-one\r\n\r\nfile-two\n").unwrap();
    let auth = Auth::load(&[Zeroizing::new("inline".to_owned())], Some(&path)).unwrap();
    std::fs::write(&path, "replacement").unwrap();
    for (header, accepted) in [
        ("Bearer inline", true),
        ("bearer file-one", true),
        ("Bearer   file-two", true),
        ("Bearer replacement", false),
        ("Basic inline", false),
        ("Bearer inline ", false),
        ("Bearer", false),
        ("Bearer other", false),
    ] {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, header.parse().unwrap());
        assert_eq!(auth.accepts(&headers), accepted, "{header}");
    }
    assert!(!auth.accepts(&HeaderMap::new()));
    let mut headers = HeaderMap::new();
    headers.append(header::AUTHORIZATION, "Bearer inline".parse().unwrap());
    headers.append(header::AUTHORIZATION, "Bearer file-one".parse().unwrap());
    assert!(!auth.accepts(&headers));
    for token in ["", "secret token", "secret\ttoken", "=", "secret=token"] {
        let error = Auth::load(&[Zeroizing::new(token.to_owned())], None)
            .err()
            .unwrap();
        assert!(!error.to_string().contains("secret"));
    }
    std::fs::write(&path, "bad token").unwrap();
    assert!(Auth::load(&[], Some(&path)).is_err());
    std::fs::remove_file(&path).unwrap();
    assert!(Auth::load(&[], Some(&path)).is_err());
    assert!(Auth::load(&[], None).unwrap().accepts(&HeaderMap::new()));
}

#[test]
fn bearer_auth_enforces_token_count_length_and_file_size_limits() {
    let maximum = Zeroizing::new("x".repeat(1024));
    let inline = vec![maximum.clone(); 1024];
    assert!(Auth::load(&inline, None).is_ok());
    assert!(Auth::load(&vec![maximum; 1025], None).is_err());
    assert!(Auth::load(&[Zeroizing::new("x".repeat(1025))], None).is_err());

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("tokens");
    std::fs::write(&path, "file-token").unwrap();
    assert!(Auth::load(&inline, Some(&path)).is_err());
    std::fs::write(&path, "\n".repeat(1024 * 1024)).unwrap();
    assert!(Auth::load(&[], Some(&path)).unwrap().0.is_empty());
    std::fs::write(&path, "\n".repeat(1024 * 1024 + 1)).unwrap();
    assert!(Auth::load(&[], Some(&path)).is_err());
}

#[test]
fn accept_negotiation_respects_quality_specificity_and_rejections() {
    for (header, expected) in [
        ("application/dns-json", Some(Format::Json)),
        ("application/dns-message", Some(Format::Binary)),
        ("application/dns-message;q=0, */*;q=1", Some(Format::Json)),
        (
            "application/dns-message;q=0.8, application/dns-json;q=0.9",
            Some(Format::Json),
        ),
        ("application/*", Some(Format::Binary)),
        ("text/html", None),
        ("*/*;q=0", None),
        ("application/dns-json;q=NaN", None),
    ] {
        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT, header.parse().unwrap());
        assert!(
            negotiate(&headers, Format::Binary).ok() == expected,
            "{header}"
        );
    }
}

#[test]
fn json_question_parses_types_and_dnssec_flags() {
    let params = |value: &str| {
        url::form_urlencoded::parse(value.as_bytes())
            .into_owned()
            .collect()
    };
    let query = json_query(&params("name=EXAMPLE.com&type=28&do=1&cd=true")).unwrap();
    assert_eq!(query.queries[0].query_type(), RecordType::AAAA);
    assert_eq!(query.queries[0].name().to_ascii(), "example.com.");
    assert!(query.metadata.checking_disabled);
    assert!(query.edns.unwrap().flags().dnssec_ok);
    for value in [
        "type=A",
        "name=",
        "name=example.com&type=65536",
        "name=example.com&do=yes",
        "name=example.com&edns_client_subnet=1.2.3.4",
    ] {
        assert!(json_query(&params(value)).is_err(), "{value}");
    }
}

#[test]
fn json_question_accepts_dns_names_beyond_hostnames() {
    for (name, kind, expected) in [
        ("_dmarc.example.com", "TXT", "_dmarc.example.com."),
        ("_sip._tcp.example.com", "SRV", "_sip._tcp.example.com."),
        ("_443._tcp.example.com", "TLSA", "_443._tcp.example.com."),
        (".", "NS", "."),
        ("b\u{fc}cher.example", "A", "xn--bcher-kva.example."),
    ] {
        let params = [("name".into(), name.into()), ("type".into(), kind.into())].into();
        let query = json_query(&params).unwrap();
        assert_eq!(query.queries[0].name().to_ascii(), expected);
        assert_eq!(query.queries[0].query_type().to_string(), kind);
        assert!(query.queries[0].name().is_fqdn());
    }
}

#[test]
fn json_txt_preserves_binary_octets_and_character_string_boundaries() {
    let data = RData::TXT(hickory_proto::rr::rdata::TXT::from_bytes(vec![
        b"a\"b\\c",
        &[0, 255],
    ]));
    assert_eq!(json_record_data(&data).unwrap(), r#""a\"b\\c" "\000\255""#);
}

#[test]
fn json_character_strings_preserve_bytes_and_field_boundaries() {
    use hickory_proto::rr::rdata::{CAA, HINFO, NAPTR};

    let hinfo = RData::HINFO(HINFO::from_bytes(
        b"cpu \xff".to_vec().into_boxed_slice(),
        b"test os".to_vec().into_boxed_slice(),
    ));
    assert_eq!(json_record_data(&hinfo).unwrap(), r#""cpu \255" "test os""#);
    let naptr = RData::NAPTR(NAPTR::new(
        10,
        20,
        b"s".to_vec().into_boxed_slice(),
        b"test service".to_vec().into_boxed_slice(),
        b"\"\\\xff".to_vec().into_boxed_slice(),
        canonical_name("next.example").unwrap(),
    ));
    assert_eq!(
        json_record_data(&naptr).unwrap(),
        r#"10 20 "s" "test service" "\"\\\255" next.example."#
    );
    let mut caa = CAA::new_issue(false, None, vec![]);
    caa.value = b"issuer \"\\\xff".to_vec();
    assert_eq!(
        json_record_data(&RData::CAA(caa)).unwrap(),
        r#"0 issue "issuer \"\\\255""#
    );
}

#[test]
fn json_generic_rdata_preserves_service_parameters_and_unknown_bytes() {
    use hickory_proto::rr::rdata::{
        HTTPS, NULL, SVCB,
        svcb::{SvcParamKey, SvcParamValue, Unknown},
    };

    let service = SVCB::new(
        1,
        Name::root(),
        vec![(
            SvcParamKey::Key(123),
            SvcParamValue::Unknown(Unknown(vec![0xff, b'"', b'\\', b' '])),
        )],
    );
    for data in [RData::SVCB(service.clone()), RData::HTTPS(HTTPS(service))] {
        assert_eq!(
            json_record_data(&data).unwrap(),
            r"\# 11 000100007b0004ff225c20"
        );
    }
    for data in [
        RData::NULL(NULL::with(vec![0, 255])),
        RData::Unknown {
            code: RecordType::Unknown(65280),
            rdata: NULL::with(vec![0, 255]),
        },
    ] {
        assert_eq!(json_record_data(&data).unwrap(), r"\# 2 00ff");
    }
}

#[tokio::test]
async fn http_uses_the_existing_resolver_without_udp_truncation_or_auth_bypass() {
    use crate::{config::Config, resolver::Resolver, upstream::Exchange};
    use hickory_proto::{
        op::OpCode,
        rr::rdata::{A, HINFO, TXT},
    };
    use std::sync::Mutex;

    #[derive(Default)]
    struct Upstream(Mutex<Vec<Message>>);
    #[async_trait::async_trait]
    impl Exchange for Upstream {
        async fn exchange(&self, request: Message) -> Result<Message> {
            self.0.lock().unwrap().push(request.clone());
            let mut response = Message::response(request.metadata.id, OpCode::Query);
            response.metadata.recursion_available = true;
            response.metadata.recursion_desired = request.metadata.recursion_desired;
            response.metadata.authentic_data = true;
            response.metadata.checking_disabled = request.metadata.checking_disabled;
            response.queries = request.queries;
            response.answers.push(Record::from_rdata(
                canonical_name("public.test").unwrap(),
                42,
                hickory_proto::rr::RData::TXT(TXT::new(vec!["x".repeat(200); 6])),
            ));
            response.additionals.push(Record::from_rdata(
                canonical_name("extra.test").unwrap(),
                30,
                hickory_proto::rr::RData::A(A("192.0.2.1".parse().unwrap())),
            ));
            response.additionals.push(Record::from_rdata(
                canonical_name("extra.test").unwrap(),
                30,
                RData::HINFO(HINFO::from_bytes(
                    b"cpu \xff".to_vec().into_boxed_slice(),
                    b"test os".to_vec().into_boxed_slice(),
                )),
            ));
            Ok(response)
        }
    }
    let config = Config::parse("").unwrap();
    let upstream = Arc::new(Upstream::default());
    let handler = Handler::new(
        Arc::new(Resolver::new(config.policy, upstream.clone())),
        8,
        Duration::from_secs(2),
    );
    let bound = BoundListener::bind(&Listener::Http {
        address: "0.0.0.0:0".parse().unwrap(),
        path: "/dns-query".into(),
        auth_tokens: vec![Zeroizing::new("test-token".to_owned())],
        auth_token_file: None,
    })
    .await
    .unwrap();
    let url = format!(
        "http://127.0.0.1:{}/dns-query",
        bound.socket.local_addr().unwrap().port()
    );
    let (shutdown, receiver) = watch::channel(false);
    let task = tokio::spawn(bound.run(handler, 8, Duration::from_secs(2), receiver));
    let client = reqwest::Client::builder()
        .no_proxy()
        .http1_only()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    assert_eq!(
        client
            .get(&url)
            .query(&[("name", "public.test")])
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert!(upstream.0.lock().unwrap().is_empty());
    let response = client
        .get(&url)
        .bearer_auth("test-token")
        .query(&[
            ("name", "public.test"),
            ("type", "TXT"),
            ("do", "true"),
            ("cd", "true"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(response.version(), http::Version::HTTP_11);
    let json: Value = response.json().await.unwrap();
    assert_eq!(json["Answer"][0]["TTL"], 42);
    assert!(json["Answer"][0]["data"].as_str().unwrap().len() > 1200);
    assert_eq!(json["Additional"][0]["data"], "192.0.2.1");
    assert_eq!(json["Additional"][1]["data"], r#""cpu \255" "test os""#);
    assert_eq!(json["AD"], true);
    assert_eq!(json["CD"], true);
    {
        let calls = upstream.0.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].metadata.checking_disabled);
        assert!(calls[0].edns.as_ref().unwrap().flags().dnssec_ok);
    }
    let mut query = Message::query();
    query.metadata.id = 42;
    query.queries.push(Query::query(
        canonical_name("public.test").unwrap(),
        RecordType::TXT,
    ));
    let bytes = query.to_vec().unwrap();
    let response = client
        .post(&url)
        .bearer_auth("test-token")
        .header("content-type", BINARY)
        .body(bytes.clone())
        .send()
        .await
        .unwrap();
    let bytes = response.bytes().await.unwrap();
    assert!(bytes.len() > 512);
    let decoded = Message::from_vec(&bytes).unwrap();
    assert!(!decoded.metadata.truncation);
    assert_eq!(decoded.metadata.id, 42);
    let response = client
        .get(&url)
        .bearer_auth("test-token")
        .header("accept", JSON)
        .query(&[("dns", URL_SAFE_NO_PAD.encode(query.to_vec().unwrap()))])
        .send()
        .await
        .unwrap();
    assert_eq!(response.headers()["content-type"], JSON);
    let response = client
        .get(&url)
        .bearer_auth("test-token")
        .header("accept", BINARY)
        .query(&[("name", "public.test"), ("type", "TXT")])
        .send()
        .await
        .unwrap();
    assert_eq!(response.headers()["content-type"], BINARY);
    let mut extra = query.to_vec().unwrap();
    extra.push(0);
    assert!(binary_query(&extra).is_err());
    for (name, kind) in [("_dmarc.example.com", "TXT"), (".", "NS")] {
        let response = client
            .get(&url)
            .bearer_auth("test-token")
            .query(&[("name", name), ("type", kind)])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json: Value = response.json().await.unwrap();
        assert_eq!(
            json["Question"][0]["name"],
            if name == "." {
                name.to_owned()
            } else {
                format!("{name}.")
            }
        );
    }
    shutdown.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
