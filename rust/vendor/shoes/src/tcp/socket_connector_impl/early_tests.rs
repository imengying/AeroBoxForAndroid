use super::*;
use crate::tcp::carrier_dialer::EarlyDataOutcome;
use rustls::{NamedGroup, client::ClientSessionStore, pki_types::ServerName};
use serde_json::json;
use std::{process::Stdio, sync::atomic::AtomicUsize, time::Duration};
use tokio::io::{AsyncBufReadExt, BufReader};

#[derive(Debug)]
struct Tickets {
    cache: rustls::client::ClientSessionMemoryCache,
    count: AtomicUsize,
    arrived: tokio::sync::Notify,
}
impl Tickets {
    async fn received(&self, before: usize) {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let notified = self.arrived.notified();
                if self.count.load(Ordering::SeqCst) > before {
                    return;
                }
                notified.await;
            }
        })
        .await
        .expect("server did not provide a real resumption ticket");
    }
}
impl ClientSessionStore for Tickets {
    fn set_kx_hint(&self, name: ServerName<'static>, group: NamedGroup) {
        self.cache.set_kx_hint(name, group);
    }
    fn kx_hint(&self, name: &ServerName<'_>) -> Option<NamedGroup> {
        self.cache.kx_hint(name)
    }
    fn set_tls12_session(
        &self,
        name: ServerName<'static>,
        value: rustls::client::Tls12ClientSessionValue,
    ) {
        self.cache.set_tls12_session(name, value);
    }
    fn tls12_session(
        &self,
        name: &ServerName<'_>,
    ) -> Option<rustls::client::Tls12ClientSessionValue> {
        self.cache.tls12_session(name)
    }
    fn remove_tls12_session(&self, name: &ServerName<'static>) {
        self.cache.remove_tls12_session(name);
    }
    fn insert_tls13_ticket(
        &self,
        name: ServerName<'static>,
        value: rustls::client::Tls13ClientSessionValue,
    ) {
        self.cache.insert_tls13_ticket(name, value);
        self.count.fetch_add(1, Ordering::SeqCst);
        self.arrived.notify_one();
    }
    fn take_tls13_ticket(
        &self,
        name: &ServerName<'static>,
    ) -> Option<rustls::client::Tls13ClientSessionValue> {
        self.cache.take_tls13_ticket(name)
    }
}

#[tokio::test]
#[ignore = "requires AEROBOX_ECH_PEER built from the pinned ECH Go peer"]
async fn quic_early_ech_accept_reject_rotate_failure_cancellation_and_deadline_with_go() {
    tokio::time::timeout(Duration::from_secs(45), async {
        for case in ["accept", "early-reject", "rotate", "reject", "badpublic", "drop", "timeout", "network"] {
            let mode = if matches!(case, "early-reject" | "drop" | "timeout" | "network") { "accept" } else { case };
            let dir = tempfile::tempdir().unwrap();
            let mut child = tokio::process::Command::new(std::env::var_os("AEROBOX_ECH_PEER").unwrap())
                .args(["quic", mode]).env("AEROBOX_ECH_EARLY_DATA", "1")
                .env("AEROBOX_PEER_CERT_DIR", dir.path()).stdout(Stdio::piped()).stderr(Stdio::inherit())
                .kill_on_drop(true).spawn().unwrap();
            let port: u16 = BufReader::new(child.stdout.take().unwrap()).lines()
                .next_line().await.unwrap().unwrap().parse().unwrap();
            let target = NetLocation::from_str(&format!("127.0.0.1:{port}"), None).unwrap();
            let config: ResolvedClientConfig = crate::config::test_support::from_json(json!({
                "address":target.to_string(), "transport":"quic", "dial_options":{"connect_timeout":"3s"},
                "quic_settings":{"verify":true,"sni_hostname":"secret.test","alpn_protocols":["h3"],
                    "options":{"ech":{"config":std::fs::read_to_string(dir.path().join("initial-config.pem")).unwrap()},
                    "root_certificates":[std::fs::read_to_string(dir.path().join("ca.pem")).unwrap()]}},
                "protocol":{"type":"tuic","uuid":"d9ad4eab-f118-492b-a99b-e0e27332b4b2","password":"unused","zero_rtt_handshake":true}
            })).unwrap();
            let network = crate::network_tasks::NetworkLifetime::default();
            let mut connector = network.scope(async { SocketConnectorImpl::from_config(&config, Some(&target)).unwrap() }).await;
            let tickets = Arc::new(Tickets { cache: rustls::client::ClientSessionMemoryCache::new(16), count: AtomicUsize::new(0), arrived: Default::default() });
            let TransportConfig::Quic { ech: Some(ech), .. } = &mut connector.transport else { panic!("missing ECH"); };
            Arc::make_mut(&mut ech.base).resumption = rustls::client::Resumption::store(tickets.clone());
            let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
            let target: ResolvedLocation = target.into();
            let first = network.scope(connector.connect_quic_early(&resolver, &target)).await.unwrap();
            assert!(first.early.is_none(), "{case}: first connection must have no ticket");
            let first = first.completion.await.unwrap();
            assert_eq!(first.early_data, EarlyDataOutcome::NotAttempted);
            let (mut send, mut recv) = first.carrier.connection.open_bi().await.unwrap();
            send.write_all(b"seed").await.unwrap();
            let mut echoed = [0; 4]; recv.read_exact(&mut echoed).await.unwrap(); assert_eq!(&echoed, b"seed");
            send.finish().unwrap(); drop((send, recv));
            tickets.received(0).await;
            first.carrier.connection.close(0_u32.into(), b"reconnect using ticket");
            drop(first);

            std::fs::write(dir.path().join("hold-handshake"), []).unwrap();
            if matches!(case, "rotate" | "reject" | "badpublic") { std::fs::write(dir.path().join("switch"), []).unwrap(); }
            if case == "early-reject" { std::fs::write(dir.path().join("reject-early"), []).unwrap(); }
            if case == "timeout" { connector.dial_options.connect_timeout = Some(crate::dial_options::DialDuration(Duration::from_millis(80))); }
            let pending = network.scope(connector.connect_quic_early(&resolver, &target)).await.unwrap();
            let early = pending.early.as_ref().unwrap_or_else(|| panic!("{case}: real ticket did not permit early data")).clone();
            let (mut send, mut recv) = early.connection.open_bi().await.unwrap();
            send.write_all(b"early payload").await.unwrap();
            if case == "drop" {
                drop(pending);
                assert!(early.connection.close_reason().is_some(), "unpolled completion must close its early leg");
            } else if matches!(case, "timeout" | "network") {
                if case == "network" { network.cancel(); }
                let error = pending.completion.await.err().expect("cancelled/expired setup succeeded");
                assert_eq!(error.kind(), if case == "timeout" { std::io::ErrorKind::TimedOut } else { std::io::ErrorKind::Interrupted });
                assert!(early.connection.close_reason().is_some());
            } else {
                std::fs::remove_file(dir.path().join("hold-handshake")).unwrap();
                let result = network.scope(pending.completion).await;
                if matches!(case, "reject" | "badpublic") {
                    assert!(result.is_err(), "{case}: rejection must not replay");
                    assert!(early.connection.close_reason().is_some());
                } else {
                    let confirmed = result.unwrap_or_else(|e| panic!("{case}: {e}"));
                    assert_eq!(confirmed.early_data, if case == "accept" { EarlyDataOutcome::Accepted } else { EarlyDataOutcome::Rejected });
                    if case == "accept" {
                        let mut echoed = [0; 13]; recv.read_exact(&mut echoed).await.unwrap(); assert_eq!(&echoed, b"early payload");
                        send.finish().unwrap();
                    } else {
                        assert!(send.write_all(b"must fail").await.is_err());
                        let (mut retry_send, mut retry_recv) = confirmed.carrier.connection.open_bi().await.unwrap();
                        retry_send.write_all(b"confirmed payload").await.unwrap();
                        let mut echoed = [0; 17]; retry_recv.read_exact(&mut echoed).await.unwrap(); assert_eq!(&echoed, b"confirmed payload");
                        retry_send.finish().unwrap();
                    }
                    if case == "rotate" { assert_ne!(confirmed.carrier.connection.stable_id(), early.connection.stable_id()); }
                    else { assert_eq!(confirmed.carrier.connection.stable_id(), early.connection.stable_id()); }
                    confirmed.carrier.connection.close(0_u32.into(), b"done");
                }
            }
            drop((send, recv, early, connector));
            network.cancel(); network.wait().await;
            child.kill().await.unwrap(); child.wait().await.unwrap();
        }
    }).await.unwrap();
}
