//! Bounded wire-answer cache for a DNS routing policy. The complete request
//! (except transaction ID) isolates flags, query types and EDNS behavior.
use hickory_resolver::proto::{
    op::{Message, MessageType, OpCode, ResponseCode},
    rr::RData,
};
use lru::LruCache;
use std::{
    num::NonZeroUsize,
    time::{Duration, Instant},
};

const MAX_ENTRIES: usize = 256;
const MAX_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug)]
struct Entry {
    wire: Vec<u8>,
    created: Instant,
    ttl: Duration,
}
#[derive(Debug)]
pub(super) struct AnswerCache {
    entries: LruCache<Vec<u8>, Entry>,
    bytes: usize,
}
impl Default for AnswerCache {
    fn default() -> Self {
        Self {
            entries: LruCache::new(NonZeroUsize::new(MAX_ENTRIES).unwrap()),
            bytes: 0,
        }
    }
}
impl AnswerCache {
    pub(super) fn key(request: &Message, wire: &[u8]) -> Option<Vec<u8>> {
        if request.metadata.message_type != MessageType::Query
            || request.metadata.op_code != OpCode::Query
            || request.queries.len() != 1
            || wire.len() > 1024
            || !request.answers.is_empty()
            || !request.authorities.is_empty()
            || !request.additionals.is_empty()
            || super::message::is_signed(request)
            || request
                .edns
                .as_ref()
                .is_some_and(|edns| edns.version() != 0 || !edns.options().options.is_empty())
        {
            return None;
        }
        let mut key = wire.to_vec();
        key[..2].fill(0);
        Some(key)
    }
    pub(super) fn get(&mut self, key: &[u8], request: &Message, now: Instant) -> Option<Vec<u8>> {
        let expired = self
            .entries
            .peek(key)
            .is_some_and(|entry| now.saturating_duration_since(entry.created) >= entry.ttl);
        if expired {
            self.remove(key);
            return None;
        }
        let entry = self.entries.get(key)?;
        let mut response = super::message::decode(&entry.wire).ok()?;
        let age = now
            .saturating_duration_since(entry.created)
            .as_secs()
            .min(u32::MAX as u64) as u32;
        for record in response
            .answers
            .iter_mut()
            .chain(&mut response.authorities)
            .chain(&mut response.additionals)
        {
            record.ttl = record.ttl.saturating_sub(age);
        }
        response.metadata.id = request.metadata.id;
        // OPT is transaction metadata, so recreate it from this request.
        response.edns = request.edns.clone();
        response.to_vec().ok()
    }
    pub(super) fn insert(&mut self, key: Vec<u8>, request: &Message, wire: &[u8], now: Instant) {
        let Ok(mut response) = super::message::decode(wire) else {
            return;
        };
        if response.metadata.message_type != MessageType::Response
            || response.metadata.id != request.metadata.id
            || response.metadata.op_code != request.metadata.op_code
            || response.queries != request.queries
            || response.metadata.truncation
            || super::message::is_signed(&response)
            || response
                .edns
                .as_ref()
                .is_some_and(|edns| edns.version() != 0 || !edns.options().options.is_empty())
            || !matches!(
                response.metadata.response_code,
                ResponseCode::NoError | ResponseCode::NXDomain
            )
        {
            return;
        }
        let records_ttl = response.all_sections().map(|record| record.ttl).min();
        let negative = response.metadata.response_code == ResponseCode::NXDomain
            || response.answers.is_empty();
        let ttl = if negative {
            response
                .authorities
                .iter()
                .filter_map(|record| match &record.data {
                    RData::SOA(soa) => Some(record.ttl.min(soa.minimum)),
                    _ => None,
                })
                .min()
                .map(|ttl| ttl.min(records_ttl.unwrap_or(ttl)))
        } else {
            records_ttl
        };
        let Some(ttl) = ttl.filter(|ttl| *ttl != 0) else {
            return;
        };
        response.edns = None;
        response.metadata.id = 0;
        let Ok(wire) = response.to_vec() else {
            return;
        };
        let cost = key.len() + wire.len();
        if cost > MAX_BYTES {
            return;
        }
        self.remove(&key);
        while self.bytes + cost > MAX_BYTES || self.entries.len() >= MAX_ENTRIES {
            let Some((key, entry)) = self.entries.pop_lru() else {
                break;
            };
            self.bytes -= key.len() + entry.wire.len();
        }
        self.bytes += cost;
        self.entries.put(
            key,
            Entry {
                wire,
                created: now,
                ttl: Duration::from_secs(ttl.into()),
            },
        );
    }
    fn remove(&mut self, key: &[u8]) {
        if let Some((key, entry)) = self.entries.pop_entry(key) {
            self.bytes -= key.len() + entry.wire.len();
        }
    }
    pub(super) fn clear(&mut self) {
        self.entries.clear();
        self.bytes = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::proto::{
        op::Query,
        rr::{
            Name, Record, RecordType,
            rdata::{A, SOA},
        },
    };
    fn query() -> Message {
        let mut query = Message::query();
        query.metadata.id = 123;
        query.add_query(Query::query(
            Name::from_ascii("www.example.").unwrap(),
            RecordType::A,
        ));
        query
    }
    fn answer(query: &Message) -> Message {
        let mut reply = crate::dns::fake_ip::responder::response(query, ResponseCode::NoError);
        reply.add_answer(Record::from_rdata(
            query.queries[0].name.clone(),
            30,
            RData::A(A("192.0.2.1".parse().unwrap())),
        ));
        reply
    }
    #[test]
    fn caches_with_decreasing_ttl_and_current_id_then_expires() {
        let mut cache = AnswerCache::default();
        let mut query = query();
        let key = AnswerCache::key(&query, &query.to_vec().unwrap()).unwrap();
        let now = Instant::now();
        cache.insert(key.clone(), &query, &answer(&query).to_vec().unwrap(), now);
        query.metadata.id = 999;
        let reply = crate::dns::message::decode(
            &cache
                .get(&key, &query, now + Duration::from_secs(12))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(reply.metadata.id, 999);
        assert_eq!(reply.answers[0].ttl, 18);
        assert!(
            cache
                .get(&key, &query, now + Duration::from_secs(30))
                .is_none()
        );
        assert_eq!(cache.bytes, 0);
    }
    #[test]
    fn negative_cache_requires_soa_and_uses_its_minimum() {
        let mut cache = AnswerCache::default();
        let query = query();
        let key = AnswerCache::key(&query, &query.to_vec().unwrap()).unwrap();
        let now = Instant::now();
        let mut reply = crate::dns::fake_ip::responder::response(&query, ResponseCode::NXDomain);
        cache.insert(key.clone(), &query, &reply.to_vec().unwrap(), now);
        assert!(cache.entries.is_empty());
        reply.add_authority(Record::from_rdata(
            Name::from_ascii("example").unwrap(),
            300,
            RData::SOA(SOA::new(
                Name::from_ascii("ns.example").unwrap(),
                Name::from_ascii("hostmaster.example").unwrap(),
                1,
                3600,
                600,
                86400,
                20,
            )),
        ));
        cache.insert(key.clone(), &query, &reply.to_vec().unwrap(), now);
        assert!(
            cache
                .get(&key, &query, now + Duration::from_secs(19))
                .is_some()
        );
        assert!(
            cache
                .get(&key, &query, now + Duration::from_secs(20))
                .is_none()
        );
    }
    #[test]
    fn malformed_mismatched_truncated_failure_and_zero_ttl_are_not_cached() {
        let query = query();
        let key = AnswerCache::key(&query, &query.to_vec().unwrap()).unwrap();
        for kind in 0..5 {
            let mut cache = AnswerCache::default();
            let mut reply = answer(&query);
            match kind {
                0 => reply.metadata.id ^= 1,
                1 => reply.queries[0].name = Name::from_ascii("other.example").unwrap(),
                2 => reply.metadata.truncation = true,
                3 => reply.metadata.response_code = ResponseCode::ServFail,
                _ => reply.answers[0].ttl = 0,
            }
            cache.insert(
                key.clone(),
                &query,
                &reply.to_vec().unwrap(),
                Instant::now(),
            );
            assert!(cache.entries.is_empty());
        }
        let mut cache = AnswerCache::default();
        cache.insert(key, &query, b"bad", Instant::now());
        assert!(cache.entries.is_empty());
    }
}
