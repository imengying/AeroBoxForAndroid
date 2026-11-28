use crate::atomic::AtomicU64;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use parking_lot::Mutex;
use serde::Serialize;
use tokio_util::sync::CancellationToken;

use super::connection_notes::{ConnectionNotes, MAX_FLOWS, Note};
use crate::address::{NetLocation, ResolvedLocation};

#[derive(Debug, Default)]
pub struct FlowCounters {
    upload: AtomicU64,
    download: AtomicU64,
}

impl FlowCounters {
    pub fn upload(&self, bytes: usize) {
        self.upload.fetch_add(bytes as u64, Ordering::Relaxed);
    }
    pub fn download(&self, bytes: usize) {
        self.download.fetch_add(bytes as u64, Ordering::Relaxed);
    }
    pub fn totals(&self) -> (u64, u64) {
        (
            self.upload.load(Ordering::Relaxed),
            self.download.load(Ordering::Relaxed),
        )
    }
}

#[derive(Debug, Clone)]
pub struct FlowContext {
    pub registry: Arc<FlowRegistry>,
    pub generation: u64,
    pub inbound: String,
    pub scope: String,
    pub protocol: String,
}

#[derive(Debug, Default)]
pub struct FlowInfo {
    pub(crate) owner: Option<crate::embedding::owner::FlowOwner>,
    pub source: Option<std::net::SocketAddr>,
    pub original: Option<NetLocation>,
    pub restored_host: Option<String>,
    pub sniff_host: Option<String>,
    pub sniff_protocol: Option<crate::rules::Protocol>,
    pub fake_dns: bool,
    pub notes: Option<Arc<ConnectionNotes>>,
}

#[derive(Debug, Default, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowMetadata {
    pub network: String,
    #[serde(rename = "type")]
    pub protocol: String,
    #[serde(rename = "sourceIP")]
    pub source_ip: String,
    pub source_port: String,
    #[serde(rename = "destinationIP")]
    pub destination_ip: String,
    pub destination_port: String,
    pub host: String,
    pub sniff_host: String,
    pub sniff_protocol: String,
    pub dns_mode: String,
    pub inbound_name: String,
    pub process: String,
    pub process_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub packages: Vec<String>,
    pub remote_destination: String,
    pub shoes_original_destination: String,
}

#[derive(Debug)]
pub struct FlowEntry {
    order: u64,
    pub(crate) owner: crate::embedding::owner::FlowOwner,
    pub id: String,
    pub generation: u64,
    pub start: String,
    pub metadata: FlowMetadata,
    pub chains: Vec<String>,
    pub rule_payload: String,
    pub counters: FlowCounters,
    pub cancel: CancellationToken,
    pub notes: Option<Arc<ConnectionNotes>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionSnapshot {
    pub id: String,
    pub start: String,
    pub metadata: FlowMetadata,
    pub chains: Vec<String>,
    pub provider_chains: Vec<String>,
    pub rule: &'static str,
    pub rule_payload: String,
    pub upload: u64,
    pub download: u64,
    pub shoes_generation: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<Vec<Note>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionsSnapshot {
    #[serde(skip)]
    pub sequence: u64,
    pub upload_total: u64,
    pub download_total: u64,
    pub memory: u64,
    pub connections: Vec<ConnectionSnapshot>,
}

#[derive(Debug, Default)]
struct RegistryState {
    next_order: u64,
    snapshot_sequence: u64,
    entries: BTreeMap<String, Arc<FlowEntry>>,
    closed_upload: u64,
    closed_download: u64,
}

#[derive(Debug, Default)]
pub struct FlowRegistry {
    state: Mutex<RegistryState>,
    notes_slots: Option<Arc<tokio::sync::Semaphore>>,
}

#[derive(Debug)]
pub struct FlowGuard {
    registry: Arc<FlowRegistry>,
    pub entry: Arc<FlowEntry>,
}

impl FlowContext {
    pub fn register(
        &self,
        network: &str,
        target: &ResolvedLocation,
        chains: Vec<String>,
        rule_payload: &str,
        info: FlowInfo,
    ) -> FlowGuard {
        let destination: &NetLocation = target.location();
        let hostname = destination.address().hostname();
        let mut entry = FlowEntry {
            order: 0,
            owner: info.owner.unwrap_or_default(),
            id: crate::uuid_util::generate_uuid(),
            generation: self.generation,
            start: chrono::Utc::now().to_rfc3339(),
            metadata: FlowMetadata {
                network: network.into(),
                source_ip: info
                    .source
                    .map(|addr| addr.ip().to_string())
                    .unwrap_or_default(),
                source_port: info
                    .source
                    .map(|addr| addr.port().to_string())
                    .unwrap_or_default(),
                protocol: self.protocol.clone(),
                destination_ip: target
                    .resolved_addr()
                    .map(|addr| addr.ip().to_string())
                    .unwrap_or_else(|| {
                        if hostname.is_none() {
                            destination.address().to_string()
                        } else {
                            String::new()
                        }
                    }),
                destination_port: destination.port().to_string(),
                host: info
                    .restored_host
                    .unwrap_or_else(|| hostname.unwrap_or("").to_owned()),
                sniff_host: info.sniff_host.unwrap_or_default(),
                sniff_protocol: info.sniff_protocol.map_or("", |p| p.as_str()).into(),
                remote_destination: destination.to_string(),
                shoes_original_destination: info
                    .original
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_default(),
                inbound_name: self.inbound.clone(),
                dns_mode: if info.fake_dns { "fake-ip" } else { "normal" }.into(),
                ..Default::default()
            },
            chains: if chains.is_empty() {
                vec!["DIRECT".into()]
            } else {
                chains
            },
            rule_payload: format!("{} ({}): {}", self.inbound, self.scope, rule_payload),
            counters: FlowCounters::default(),
            cancel: CancellationToken::new(),
            notes: info.notes,
        };
        let entry = {
            let mut state = self.registry.state.lock();
            entry.order = state.next_order;
            state.next_order += 1;
            let entry = Arc::new(entry);
            state.entries.insert(entry.id.clone(), entry.clone());
            entry
        };
        FlowGuard {
            registry: self.registry.clone(),
            entry,
        }
    }
}

impl FlowRegistry {
    pub fn new(connection_notes: bool) -> Self {
        Self {
            notes_slots: connection_notes.then(|| Arc::new(tokio::sync::Semaphore::new(MAX_FLOWS))),
            ..Default::default()
        }
    }

    pub fn notes_enabled(&self) -> bool {
        self.notes_slots.is_some()
    }

    pub fn start_notes(&self) -> Option<Arc<ConnectionNotes>> {
        let permit = self
            .notes_slots
            .as_ref()?
            .clone()
            .try_acquire_owned()
            .ok()?;
        Some(Arc::new(ConnectionNotes::new(permit)))
    }

    pub fn cancel(&self, id: &str) {
        let entry = self.state.lock().entries.get(id).cloned();
        if let Some(entry) = entry {
            entry.owner.close();
            entry.cancel.cancel();
        }
    }

    pub fn cancel_all(&self) {
        let entries: Vec<_> = self.state.lock().entries.values().cloned().collect();
        for entry in entries {
            entry.owner.close();
            entry.cancel.cancel();
        }
    }

    /// Traffic polling does not need connection metadata, owner lookups or JSON.
    pub fn stats(&self) -> crate::embedding::Stats {
        let state = self.state.lock();
        let mut totals = crate::embedding::Stats {
            upload_total: state.closed_upload,
            download_total: state.closed_download,
            active_connections: state.entries.len(),
        };
        for entry in state.entries.values() {
            let (upload, download) = entry.counters.totals();
            totals.upload_total += upload;
            totals.download_total += download;
        }
        totals
    }

    pub fn snapshot(&self, memory: u64) -> ConnectionsSnapshot {
        self.snapshot_limited(memory, usize::MAX)
    }

    /// Select newest entries before copying details; totals still cover every flow.
    pub fn snapshot_limited(&self, memory: u64, limit: usize) -> ConnectionsSnapshot {
        let (sequence, entries, upload_total, download_total) = {
            let mut state = self.state.lock();
            state.snapshot_sequence += 1;
            let mut upload_total = state.closed_upload;
            let mut download_total = state.closed_download;
            let mut recent = BTreeMap::new();
            for entry in state.entries.values() {
                let (upload, download) = entry.counters.totals();
                upload_total += upload;
                download_total += download;
                if limit > 0
                    && (recent.len() < limit
                        || recent
                            .first_key_value()
                            .is_some_and(|(&oldest, _)| entry.order > oldest))
                {
                    recent.insert(entry.order, (entry, upload, download));
                    if recent.len() > limit {
                        recent.pop_first();
                    }
                }
            }
            (
                state.snapshot_sequence,
                recent
                    .into_values()
                    .rev()
                    .map(|(entry, upload, download)| (entry.clone(), upload, download))
                    .collect::<Vec<_>>(),
                upload_total,
                download_total,
            )
        };
        let connections = entries
            .into_iter()
            .map(|(entry, upload, download)| {
                let mut metadata = entry.metadata.clone();
                if let Some(owner) = entry.owner.snapshot() {
                    metadata.uid = Some(owner.uid);
                    metadata.process = owner.packages.first().cloned().unwrap_or_default();
                    metadata.packages = owner.packages;
                }
                ConnectionSnapshot {
                    id: entry.id.clone(),
                    start: entry.start.clone(),
                    metadata,
                    chains: entry.chains.clone(),
                    provider_chains: Vec::new(),
                    rule: "Shoes",
                    rule_payload: entry.rule_payload.clone(),
                    upload,
                    download,
                    shoes_generation: entry.generation,
                    notes: entry.notes.as_ref().map(|notes| notes.snapshot()),
                }
            })
            .collect();
        ConnectionsSnapshot {
            sequence,
            upload_total,
            download_total,
            memory,
            connections,
        }
    }
}

impl Drop for FlowGuard {
    fn drop(&mut self) {
        self.entry.owner.close();
        let mut state = self.registry.state.lock();
        if state.entries.remove(&self.entry.id).is_some() {
            let (upload, download) = self.entry.counters.totals();
            state.closed_upload += upload;
            state.closed_download += download;
        }
    }
}

#[cfg(test)]
pub(crate) fn test_guard() -> FlowGuard {
    FlowContext {
        registry: Arc::new(FlowRegistry::default()),
        generation: 1,
        inbound: "test".into(),
        scope: "root".into(),
        protocol: "Socks5".into(),
    }
    .register(
        "tcp",
        &NetLocation::from_str("test.example:443", None)
            .unwrap()
            .into(),
        vec!["DIRECT".into()],
        "all",
        FlowInfo::default(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_snapshots_keep_latest_flows_and_all_traffic_totals() {
        let registry = Arc::new(FlowRegistry::default());
        let context = FlowContext {
            registry: registry.clone(),
            generation: 1,
            inbound: "test".into(),
            scope: "root".into(),
            protocol: "Socks5".into(),
        };
        let target = NetLocation::from_str("192.0.2.1:443", None).unwrap().into();
        let mut guards = (0..700)
            .map(|_| {
                let guard = context.register(
                    "tcp",
                    &target,
                    vec!["proxy".into()],
                    "all",
                    FlowInfo::default(),
                );
                guard.entry.counters.upload(3);
                guard.entry.counters.download(7);
                guard
            })
            .collect::<Vec<_>>();
        let closed_id = guards.pop().unwrap().entry.id.clone();
        let stats = registry.stats();
        assert_eq!(stats.active_connections, 699);
        assert_eq!((stats.upload_total, stats.download_total), (2100, 4900));
        for limit in [0, 1, 500, 1000] {
            let snapshot = registry.snapshot_limited(0, limit);
            assert_eq!(
                (snapshot.upload_total, snapshot.download_total),
                (2100, 4900)
            );
            assert_eq!(snapshot.connections.len(), limit.min(699));
            let actual: Vec<_> = snapshot
                .connections
                .iter()
                .map(|row| row.id.as_str())
                .collect();
            let expected: Vec<_> = guards
                .iter()
                .rev()
                .take(limit)
                .map(|guard| guard.entry.id.as_str())
                .collect();
            assert_eq!(actual, expected);
            assert!(!actual.contains(&closed_id.as_str()));
        }
        drop(guards);
        let stats = registry.stats();
        assert_eq!(stats.active_connections, 0);
        assert_eq!((stats.upload_total, stats.download_total), (2100, 4900));
    }

    #[test]
    fn connection_notes_are_optional_and_disappear_with_active_connections() {
        use super::super::connection_notes::Phase;
        for enabled in [false, true] {
            let registry = Arc::new(FlowRegistry::new(enabled));
            let context = FlowContext {
                registry: registry.clone(),
                generation: 7,
                inbound: "test".into(),
                scope: "root".into(),
                protocol: "Socks5".into(),
            };
            let notes = registry.start_notes();
            let weak = notes.as_ref().map(Arc::downgrade);
            if let Some(notes) = &notes {
                notes.event(Phase::Routing, format_args!("fixture rule"));
            }
            assert!(registry.snapshot(0).connections.is_empty());
            let guard = context.register(
                "tcp",
                &NetLocation::from_str("fixture.test:443", None)
                    .unwrap()
                    .into(),
                vec!["DIRECT".into()],
                "all",
                FlowInfo {
                    notes,
                    ..Default::default()
                },
            );
            guard.entry.counters.upload(13);
            guard.entry.counters.download(27);
            let snapshot = serde_json::to_value(registry.snapshot(0)).unwrap();
            let connection = &snapshot["connections"][0];
            assert_eq!(connection["id"], guard.entry.id);
            assert_eq!(connection["shoesGeneration"], 7);
            assert_eq!(connection["chains"], serde_json::json!(["DIRECT"]));
            assert_eq!(connection.get("notes").is_some(), enabled);
            if enabled {
                assert_eq!(connection["notes"][0]["text"], "fixture rule");
                assert!(connection["notes"][0]["elapsedUs"].is_u64());
            }
            registry.cancel(&guard.entry.id);
            assert!(guard.entry.cancel.is_cancelled());
            drop(guard);
            assert!(weak.is_none_or(|notes| notes.upgrade().is_none()));
            let snapshot = registry.snapshot(0);
            assert!(snapshot.connections.is_empty());
            assert_eq!((snapshot.upload_total, snapshot.download_total), (13, 27));
        }
    }

    #[test]
    fn connection_notes_allow_concurrent_snapshots_and_close() {
        use super::super::connection_notes::Phase;
        let registry = Arc::new(FlowRegistry::new(true));
        let context = FlowContext {
            registry: registry.clone(),
            generation: 1,
            inbound: "test".into(),
            scope: "root".into(),
            protocol: "fixture".into(),
        };
        std::thread::scope(|scope| {
            scope.spawn(|| {
                for _ in 0..1000 {
                    registry.snapshot(0);
                }
            });
            for _ in 0..1000 {
                let notes = registry.start_notes().unwrap();
                let guard = context.register(
                    "tcp",
                    &NetLocation::from_str("fixture.test:443", None)
                        .unwrap()
                        .into(),
                    vec![],
                    "all",
                    FlowInfo {
                        notes: Some(notes.clone()),
                        ..Default::default()
                    },
                );
                notes.event(Phase::Setup, format_args!("outbound ready"));
                drop(guard);
            }
        });
        assert!(registry.snapshot(0).connections.is_empty());
    }
    #[test]
    fn sniffed_udp_protocol_is_separate_from_inbound_proxy_type() {
        let context = FlowContext {
            registry: Arc::new(FlowRegistry::default()),
            generation: 1,
            inbound: "local".into(),
            scope: "default".into(),
            protocol: "Socks5".into(),
        };
        for protocol in [
            None,
            Some(crate::rules::Protocol::Stun),
            Some(crate::rules::Protocol::Dtls),
        ] {
            let guard = context.register(
                "udp",
                &NetLocation::from_str("192.0.2.1:443", None).unwrap().into(),
                vec!["DIRECT".into()],
                "calls",
                FlowInfo {
                    sniff_protocol: protocol,
                    ..Default::default()
                },
            );
            let metadata = serde_json::to_value(&guard.entry.metadata).unwrap();
            assert_eq!(metadata["network"], "udp");
            assert_eq!(metadata["type"], "Socks5");
            assert_eq!(
                metadata["sniffProtocol"],
                protocol.map_or("", |p| p.as_str())
            );
        }
    }

    #[test]
    fn metadata_keeps_wire_restored_sniffed_and_effective_targets_separate() {
        let context = FlowContext {
            registry: Arc::new(FlowRegistry::default()),
            generation: 1,
            inbound: "local".into(),
            scope: "tls/default".into(),
            protocol: "Socks5".into(),
        };
        let guard = context.register(
            "tcp",
            &NetLocation::from_str("override.example:8443", None)
                .unwrap()
                .into(),
            vec!["exit".into(), "outbound".into()],
            "match all",
            FlowInfo {
                source: Some("192.0.2.1:1234".parse().unwrap()),
                original: Some(NetLocation::from_str("198.18.0.1:443", None).unwrap()),
                restored_host: Some("restored.example".into()),
                sniff_host: Some("sniffed.example".into()),
                fake_dns: true,
                ..Default::default()
            },
        );
        let metadata = &guard.entry.metadata;
        assert_eq!(metadata.source_ip, "192.0.2.1");
        assert_eq!(metadata.source_port, "1234");
        assert_eq!(metadata.shoes_original_destination, "198.18.0.1:443");
        assert_eq!(metadata.host, "restored.example");
        assert_eq!(metadata.sniff_host, "sniffed.example");
        assert_eq!(metadata.remote_destination, "override.example:8443");
        assert_eq!(metadata.dns_mode, "fake-ip");
    }
    #[test]
    fn close_transfers_totals_and_cancel_all_does_not_block_new_flows() {
        let guard = test_guard();
        let registry = guard.registry.clone();
        guard.entry.counters.upload(13);
        guard.entry.counters.download(27);
        registry.cancel_all();
        assert!(guard.entry.cancel.is_cancelled());
        let snapshot = registry.snapshot(0);
        assert_eq!((snapshot.upload_total, snapshot.download_total), (13, 27));
        assert_eq!(snapshot.connections.len(), 1);
        drop(guard);
        let snapshot = registry.snapshot(0);
        assert_eq!((snapshot.upload_total, snapshot.download_total), (13, 27));
        assert!(snapshot.connections.is_empty());
        let context = FlowContext {
            registry,
            generation: 2,
            inbound: "new".into(),
            scope: "root".into(),
            protocol: "Socks5".into(),
        };
        let new = context.register(
            "udp",
            &NetLocation::from_str("test.example:443", None)
                .unwrap()
                .into(),
            Vec::new(),
            "all",
            FlowInfo::default(),
        );
        assert!(!new.entry.cancel.is_cancelled());
    }
}
