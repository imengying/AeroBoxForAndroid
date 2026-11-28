use hickory_proto::{
    op::{Edns, Message, MessageType, OpCode, Query, ResponseCode},
    rr::{
        DNSClass, Record, RecordType,
        rdata::{TSIG, tsig::TsigAlgorithm},
    },
};
use tendns::{
    names::canonical_name,
    resolver::{local_response, validate_request},
};

fn request() -> Message {
    let mut request = Message::query();
    request.metadata.id = 1234;
    request.queries.push(Query::query(
        canonical_name("example.com").unwrap(),
        RecordType::A,
    ));
    request
}

#[test]
fn request_validation_rejects_unsupported_operations_and_signatures() {
    assert_eq!(validate_request(&request()), None);
    for kind in [RecordType::AXFR, RecordType::IXFR] {
        let mut request = request();
        request.queries[0].set_query_type(kind);
        assert_eq!(validate_request(&request), Some(ResponseCode::Refused));
    }
    let mut empty = request();
    empty.queries.clear();
    assert_eq!(validate_request(&empty), Some(ResponseCode::FormErr));
    let mut multiple = request();
    multiple.queries.push(multiple.queries[0].clone());
    assert_eq!(validate_request(&multiple), Some(ResponseCode::FormErr));
    let mut update = request();
    update.metadata.op_code = OpCode::Update;
    assert_eq!(validate_request(&update), Some(ResponseCode::NotImp));
    let mut non_internet = request();
    non_internet.queries[0].set_query_class(DNSClass::CH);
    assert_eq!(validate_request(&non_internet), Some(ResponseCode::Refused));
    let mut signed = request();
    signed.signature = Some(Box::new(Record::from_rdata(
        canonical_name("key.example.com").unwrap(),
        0,
        TSIG::new(
            TsigAlgorithm::HmacSha256,
            100,
            60,
            vec![0; 32],
            1234,
            None,
            vec![],
        ),
    )));
    assert_eq!(validate_request(&signed), Some(ResponseCode::Refused));
}

#[test]
fn synthetic_responses_preserve_request_identity_but_not_dnssec_claims() {
    for payload in [None, Some(128), Some(512), Some(4096)] {
        let mut request = request();
        request.metadata.recursion_desired = true;
        request.metadata.checking_disabled = true;
        request.metadata.authentic_data = true;
        request.metadata.authoritative = true;
        if let Some(size) = payload {
            let mut edns = Edns::new();
            edns.set_max_payload(size);
            request.edns = Some(edns);
        }
        let response = local_response(&request, ResponseCode::ServFail);
        assert_eq!(response.metadata.message_type, MessageType::Response);
        assert_eq!(response.metadata.id, 1234);
        assert_eq!(response.queries, request.queries);
        assert!(response.metadata.recursion_desired && response.metadata.recursion_available);
        assert!(response.metadata.checking_disabled);
        assert!(!response.metadata.authentic_data && !response.metadata.authoritative);
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
        assert_eq!(
            response.edns.map(|e| e.max_payload()),
            payload.map(|p| p.clamp(512, 1232))
        );
    }
}
