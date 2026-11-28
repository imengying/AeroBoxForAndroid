use super::*;
use std::collections::{BTreeMap, BTreeSet};

const MTU: u64 = 1200;
fn controller(now: Instant) -> Bbr2 {
    Bbr2::new(Arc::new(Bbr2Config::default()), now, MTU as u16)
}
fn send(c: &mut Bbr2, now: Instant, id: u64) {
    c.on_packet_sent(now, id, MTU, c.state().bytes_in_flight);
}
fn ack(c: &mut Bbr2, now: Instant, sent: Instant, ids: &[u64]) {
    c.on_feedback_start(now);
    for &id in ids {
        c.on_packet_acked(now, id, sent, MTU);
    }
    c.on_feedback_end(now);
}

#[test]
fn reordered_and_duplicate_feedback_only_counts_each_packet_once() {
    let t = Instant::now();
    let mut c = controller(t);
    for id in 0..10 {
        send(&mut c, t + Duration::from_millis(id), id);
    }
    ack(&mut c, t + Duration::from_millis(50), t, &[7, 3, 3, 6]);
    assert_eq!(c.state().bytes_in_flight, 7 * MTU);
    let rate = c.state().bandwidth_hi;
    ack(&mut c, t + Duration::from_millis(60), t, &[3, 6, 7]);
    assert_eq!(c.state().bytes_in_flight, 7 * MTU);
    assert_eq!(c.state().bandwidth_hi, rate);
    ack(
        &mut c,
        t + Duration::from_millis(65),
        t,
        &[0, 1, 2, 4, 5, 8, 9],
    );
    assert_eq!(c.state().bytes_in_flight, 0);
    assert_eq!(c.state().tracked_packets, 0);
}

#[test]
fn loss_late_ack_discard_and_untracked_mtu_probe_do_not_create_samples() {
    let t = Instant::now();
    let mut c = controller(t);
    for id in 1..=5 {
        send(&mut c, t, id);
    }
    c.on_feedback_start(t + Duration::from_millis(50));
    c.on_packet_acked(t, 2, t, MTU);
    c.on_packet_lost(t, 1, MTU);
    c.on_packet_lost(t, 1, MTU);
    c.on_feedback_end(t + Duration::from_millis(50));
    c.on_packet_discarded(3);
    c.on_packet_discarded(4);
    assert_eq!(c.state().bytes_in_flight, MTU);
    // 6 represents an excluded MTU probe: its ACK/loss must not enter the model.
    ack(&mut c, t + Duration::from_millis(80), t, &[1, 3, 4, 6]);
    c.on_feedback_start(t);
    c.on_packet_lost(t, 6, 1500);
    c.on_feedback_end(t);
    assert_eq!(c.state().bytes_in_flight, MTU);
    ack(&mut c, t + Duration::from_millis(90), t, &[5]);
    assert_eq!(c.state().tracked_packets, 0);
}

#[test]
fn clone_for_migration_clears_old_packet_history_and_resets_rate() {
    let t = Instant::now();
    let mut c = controller(t);
    for id in 0..10 {
        send(&mut c, t, id);
    }
    let mut moved = c.clone();
    moved.on_path_reset(t);
    ack(&mut moved, t + Duration::from_millis(50), t, &[0, 1, 2, 3]);
    assert_eq!(moved.state().bytes_in_flight, 0);
    assert_eq!(moved.state().bandwidth_hi, 0);
    send(&mut moved, t, 10);
    assert_eq!(moved.state().bytes_in_flight, MTU);
    assert_eq!(c.state().bytes_in_flight, 10 * MTU);
}

#[test]
fn validated_ecn_reduces_once_per_flight_without_fake_loss() {
    let t = Instant::now();
    let mut c = controller(t);
    for id in 0..10 {
        send(&mut c, t, id);
    }
    c.on_feedback_start(t);
    c.on_packet_acked(t + Duration::from_millis(50), 0, t, MTU);
    c.on_ecn_feedback(t, 0, 1);
    c.on_feedback_end(t + Duration::from_millis(50));
    let hi = c.state().inflight_hi.expect("CE must establish a bound");
    assert!(hi < 10 * MTU);
    assert_eq!(c.state().bytes_in_flight, 9 * MTU);
    c.on_feedback_start(t);
    c.on_packet_acked(t + Duration::from_millis(55), 1, t, MTU);
    c.on_ecn_feedback(t, 0, 1);
    c.on_feedback_end(t + Duration::from_millis(55));
    assert_eq!(c.state().inflight_hi, Some(hi), "one reduction per flight");
}

#[test]
fn persistent_congestion_reaches_four_packet_minimum() {
    let t = Instant::now();
    let mut c = controller(t);
    for id in 0..10 {
        send(&mut c, t, id);
    }
    c.on_feedback_start(t);
    for id in 0..10 {
        c.on_packet_lost(t, id, MTU);
    }
    c.on_congestion_event(t, t, true, 10 * MTU);
    c.on_feedback_end(t + Duration::from_millis(1000));
    assert_eq!(c.window(), 4 * MTU);
    assert_eq!(c.state().bytes_in_flight, 0);
}

#[test]
fn application_limited_low_rate_does_not_replace_bandwidth_estimate() {
    let t = Instant::now();
    let mut c = controller(t);
    for id in 0..30 {
        let sent = t + Duration::from_millis(id * 10);
        send(&mut c, sent, id);
        ack(&mut c, sent + Duration::from_millis(10), sent, &[id]);
    }
    let before = c.state().bandwidth_hi;
    for id in 30..50 {
        let sent = t + Duration::from_millis(300 + (id - 30) * 200);
        c.on_application_limited(sent);
        send(&mut c, sent, id);
        ack(&mut c, sent + Duration::from_millis(100), sent, &[id]);
    }
    assert_eq!(c.state().bandwidth_hi, before);
}

#[derive(Clone, Copy)]
struct Arrival {
    sent: Instant,
    lost: bool,
}
struct LinkResult {
    phases: BTreeSet<&'static str>,
    delivered: u64,
    lost: u64,
    min_bound: u64,
    final_rate: u64,
    max_tracked: usize,
}

// Deterministic packet/link simulation: a serialized bottleneck, 40ms propagation,
// finite queue, pacing, packet-timed rounds, ACK batches, timed loss reports and
// a bandwidth step. No sockets, sleeps, threads or external fixture dependencies.
fn simulate(seconds: u64, congested: bool) -> LinkResult {
    let base = Instant::now();
    let mut c = controller(base);
    let mut arrivals = BTreeMap::<(u64, u64), Arrival>::new();
    let mut next_send_us = 0;
    let mut link_free_us = 0u64;
    let mut next_id = 0;
    let mut result = LinkResult {
        phases: BTreeSet::new(),
        delivered: 0,
        lost: 0,
        min_bound: u64::MAX,
        final_rate: 0,
        max_tracked: 0,
    };
    for now_us in (0..seconds * 1_000_000).step_by(100) {
        let now = base + Duration::from_micros(now_us);
        let mut due = Vec::new();
        // Receiver ACKs every 5ms, deliberately combining several packets.
        if now_us % 5000 == 0 {
            while arrivals
                .first_key_value()
                .is_some_and(|((when, _), _)| *when <= now_us)
            {
                due.push(arrivals.pop_first().unwrap());
            }
        }
        if !due.is_empty() {
            c.on_feedback_start(now);
            for ((_, id), event) in due {
                if event.lost {
                    c.on_packet_lost(now, id, MTU);
                    result.lost += MTU;
                } else {
                    c.on_packet_acked(now, id, event.sent, MTU);
                    result.delivered += MTU;
                }
            }
            c.on_feedback_end(now);
        }
        let capacity = if congested && now_us >= 12_000_000 && now_us < 20_000_000 {
            300_000
        } else {
            900_000
        };
        let serialization_us = MTU * 1_000_000 / capacity;
        if now_us >= next_send_us && c.state().bytes_in_flight + MTU <= c.window() {
            let queue_packets = link_free_us.saturating_sub(now_us) / serialization_us;
            let lost = congested && (queue_packets >= 24 || next_id % 149 == 148);
            let arrival_us = if lost {
                now_us + 150_000
            } else {
                link_free_us = link_free_us.max(now_us) + serialization_us;
                link_free_us + 40_000
            };
            send(&mut c, now, next_id);
            arrivals.insert((arrival_us, next_id), Arrival { sent: now, lost });
            next_id += 1;
            let rate = c.pacing_rate_bytes().unwrap();
            next_send_us = now_us + (MTU * 1_000_000).div_ceil(rate);
        }
        let state = c.state();
        result.phases.insert(state.phase);
        result.min_bound = result.min_bound.min(state.inflight_hi.unwrap_or(u64::MAX));
        result.max_tracked = result.max_tracked.max(state.tracked_packets);
        assert!(c.window() >= 4 * MTU && c.window() <= 16 * 1024 * 1024);
        assert!(c.pacing_rate_bytes().unwrap() > 0);
    }
    result.final_rate = c.state().bandwidth_hi;
    result
}

#[test]
fn paced_bottleneck_reaches_probe_bw_and_periodic_probe_rtt() {
    let result = simulate(25, false);
    assert!(result.phases.contains("bbr_startup"), "{:?}", result.phases);
    assert!(
        result.phases.iter().any(|p| p.starts_with("bbr_probe_bw")),
        "{:?}",
        result.phases
    );
    assert!(
        result.phases.contains("bbr_probe_rtt"),
        "{:?}",
        result.phases
    );
    assert!(
        result.delivered > 5_000_000,
        "delivered {}",
        result.delivered
    );
    assert_eq!(result.lost, 0);
    assert!(
        result.final_rate > 200_000 && result.final_rate < 1_800_000,
        "rate {}",
        result.final_rate
    );
    assert!(result.max_tracked < 4096, "retained {}", result.max_tracked);
}

#[test]
fn queue_overflow_and_capacity_step_establish_bbr2_inflight_bound() {
    let result = simulate(30, true);
    assert!(result.lost > 0);
    assert!(
        result.min_bound < u64::MAX,
        "BBRv2 must learn a loss-limited inflight bound"
    );
    assert!(
        result.delivered > 4_000_000,
        "delivered {}",
        result.delivered
    );
    assert!(
        result.phases.iter().any(|p| p.starts_with("bbr_probe_bw")),
        "{:?}",
        result.phases
    );
    assert!(result.max_tracked < 4096);
}

#[test]
fn mtu_growth_clamps_window_immediately_and_preserves_four_packet_floor() {
    let t = Instant::now();
    let mut config = Bbr2Config::default();
    config
        .initial_window_packets(100)
        .max_window_bytes(64 * 1024);
    let mut c = Bbr2::new(Arc::new(config), t, 1200);
    assert!(c.window() <= 64 * 1024);
    c.on_mtu_update(1452);
    assert!(
        c.window() <= 64 * 1024,
        "MTU rescaling must not await the next ACK to enforce its ceiling"
    );
    c.on_mtu_update(u16::MAX);
    assert_eq!(c.window(), 4 * u64::from(u16::MAX));
    assert_eq!(c.initial_window(), 4 * u64::from(u16::MAX));
}

#[test]
fn losses_from_replaced_controller_do_not_trigger_persistent_congestion() {
    let now = Instant::now();
    let mut c = controller(now);
    let window = c.window();
    c.on_feedback_start(now);
    for old_id in 0..10 {
        c.on_packet_lost(now, old_id, MTU);
    }
    c.on_congestion_event(now, now, true, 10 * MTU);
    c.on_feedback_end(now);
    assert_eq!(c.window(), window);
    assert_eq!(c.state().inflight_hi, None);
    send(&mut c, now, 10);
    ack(&mut c, now + Duration::from_millis(20), now, &[10]);
    assert!(c.state().bandwidth_hi > 0);
}

#[test]
fn sustained_ecn_does_not_exponentially_starve_the_minimum_window() {
    let t = Instant::now();
    let mut c = controller(t);
    let mut next = 0;
    for flight in 0..100 {
        let sent = t + Duration::from_millis(flight * 40);
        let ids: Vec<_> = (next..next + 4).collect();
        for &id in &ids {
            send(&mut c, sent, id);
        }
        next += 4;
        let now = sent + Duration::from_millis(20);
        c.on_feedback_start(now);
        for id in ids {
            c.on_packet_acked(now, id, sent, MTU);
        }
        c.on_ecn_feedback(now, 0, 4);
        c.on_feedback_end(now);
        assert!(c.window() >= 4 * MTU);
    }
    assert!(
        c.pacing_rate_bytes().unwrap() >= 10_000,
        "a minimum-window flow must retain useful pacing under sustained CE"
    );
}
