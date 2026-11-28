//! Integration checks for the packet lifecycle used by BBRv2.
use super::*;
use crate::congestion::{Bbr2, Bbr2Config, Bbr2State};

fn state(connection: &Connection) -> Bbr2State {
    connection
        .congestion_state()
        .clone_box()
        .into_any()
        .downcast::<Bbr2>()
        .unwrap()
        .state()
}

fn bbr2_pair() -> (Pair, ConnectionHandle, ConnectionHandle) {
    let factory = Arc::new(Bbr2Config::default());
    let mut server = server_config();
    Arc::make_mut(&mut server.transport).congestion_controller_factory(factory.clone());
    let mut client = client_config();
    Arc::make_mut(&mut client.transport).congestion_controller_factory(factory);
    let mut pair = Pair::new(Default::default(), server);
    pair.latency = Duration::from_millis(10);
    let (a, b) = pair.connect_with(client);
    (pair, a, b)
}

#[test]
fn bbr2_handshake_stream_transfer_and_key_discard() {
    let _guard = subscribe();
    let (mut pair, client, server) = bbr2_pair();
    let s = pair.client_streams(client).open(Dir::Uni).unwrap();
    let data = vec![0x5a; 96 * 1024];
    assert_eq!(
        pair.client_send(client, s).write(&data).unwrap(),
        data.len()
    );
    pair.client_send(client, s).finish().unwrap();
    pair.drive();
    assert_eq!(pair.server_streams(server).accept(Dir::Uni), Some(s));
    let mut recv = pair.server_recv(server, s);
    let mut chunks = recv.read(false).unwrap();
    let mut received = Vec::new();
    while let Some(chunk) = chunks.next(usize::MAX).unwrap() {
        received.extend_from_slice(&chunk.bytes);
    }
    let _ = chunks.finalize();
    assert_eq!(received, data);
    pair.drive();
    let stats = state(pair.client_conn_mut(client));
    assert!(stats.bandwidth_hi > 0);
    assert!(
        stats.tracked_packets < 100,
        "discarded handshake samples must not accumulate"
    );
}

#[test]
fn bbr2_lost_mtu_probes_are_excluded_from_delivery_and_loss_model() {
    let _guard = subscribe();
    let factory = Arc::new(Bbr2Config::default());
    let mut server = server_config();
    Arc::make_mut(&mut server.transport).congestion_controller_factory(factory.clone());
    let mut client = client_config();
    Arc::make_mut(&mut client.transport).congestion_controller_factory(factory);
    let mut pair = Pair::new(Default::default(), server);
    pair.mtu = 1200;
    pair.latency = Duration::from_millis(10);
    let (client, _) = pair.connect_with(client);
    pair.drive();
    let connection = pair.client_conn_mut(client);
    assert!(connection.stats().path.lost_plpmtud_probes > 0);
    assert_eq!(connection.stats().path.congestion_events, 0);
    let stats = state(connection);
    assert_eq!(stats.inflight_hi, None);
    assert!(stats.tracked_packets < 100);
}

#[test]
fn bbr2_runtime_controller_switch_ignores_old_samples() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    pair.latency = Duration::from_millis(10);
    let (client, _) = pair.connect();
    let stream = pair.client_streams(client).open(Dir::Uni).unwrap();
    pair.client_send(client, stream).write(&[1; 4096]).unwrap();
    pair.drive_client();
    let now = pair.time;
    pair.client_conn_mut(client)
        .set_congestion_controller(now, Arc::new(Bbr2Config::default()));
    assert_eq!(state(pair.client_conn_mut(client)).bandwidth_hi, 0);
    assert_eq!(state(pair.client_conn_mut(client)).bytes_in_flight, 0);
    pair.drive();
    pair.client_send(client, stream).write(&[2; 4096]).unwrap();
    pair.drive();
    assert!(state(pair.client_conn_mut(client)).bandwidth_hi > 0);
}
