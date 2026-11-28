//! BBRv2 for Quinn, based on Cloudflare's Rust port of Google QUICHE.
//!
//! Uses an independent delivery sampler and the BBRv2 inflight/bandwidth bounds.
//! See `SOURCES.md` for the fixed upstream sources, licenses and local changes.

use super::{Controller, ControllerFactory, ControllerMetrics};
use crate::Instant;
use std::{any::Any, sync::Arc, time::Duration};

mod upstream;
use upstream::{Acked, CongestionControl, Lost, RecoveryStats, RttStats, bbr2::BBRv2};

/// Configuration for BBRv2. All sizes are bytes except packet counts named below.
#[derive(Clone, Debug)]
pub struct Bbr2Config {
    initial_window_packets: u64,
    max_window_bytes: u64,
    initial_rtt: Duration,
}

impl Default for Bbr2Config {
    fn default() -> Self {
        Self {
            initial_window_packets: 10,
            max_window_bytes: 16 * 1024 * 1024,
            initial_rtt: Duration::from_millis(333),
        }
    }
}

impl Bbr2Config {
    /// Set the initial window in packets, clamped to at least four packets.
    pub fn initial_window_packets(&mut self, packets: u64) -> &mut Self {
        self.initial_window_packets = packets.clamp(4, 1024);
        self
    }
    /// Bound the congestion window and associated per-packet memory.
    /// The protocol minimum of four current MTUs takes precedence.
    pub fn max_window_bytes(&mut self, bytes: u64) -> &mut Self {
        self.max_window_bytes = bytes.clamp(64 * 1024, 256 * 1024 * 1024);
        self
    }
    /// Initial RTT used before delivery samples are available.
    pub fn initial_rtt(&mut self, rtt: Duration) -> &mut Self {
        self.initial_rtt = rtt.clamp(Duration::from_millis(1), Duration::from_secs(60));
        self
    }
}

impl ControllerFactory for Bbr2Config {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(Bbr2::new(self, now, current_mtu))
    }
}

/// Current BBRv2 state and model bounds. `None` means the bound is not yet known.
#[derive(Clone, Debug)]
pub struct Bbr2State {
    /// Startup, drain, one of the four ProbeBW phases, or ProbeRTT.
    pub phase: &'static str,
    /// Packet-timed round count.
    pub round: u64,
    /// Measured minimum RTT, including receiver ACK delay.
    pub min_rtt: Duration,
    /// Short-term bandwidth bound in bytes per second.
    pub bandwidth_lo: Option<u64>,
    /// Maximum measured bandwidth in bytes per second.
    pub bandwidth_hi: u64,
    /// Short-term inflight bound in bytes.
    pub inflight_lo: Option<u64>,
    /// Long-term inflight bound in bytes.
    pub inflight_hi: Option<u64>,
    /// Bytes tracked by this controller, excluding MTU probes and discarded paths.
    pub bytes_in_flight: u64,
    /// Number of retained delivery-sampling slots.
    pub tracked_packets: usize,
}

/// BBRv2 congestion control with per-packet delivery-rate sampling.
#[derive(Clone, Debug)]
pub struct Bbr2 {
    config: Arc<Bbr2Config>,
    model: BBRv2,
    mtu: u16,
    last_sent: Option<u64>,
    batch_prior_flight: u64,
    acked: Vec<Acked>,
    lost: Vec<Lost>,
    ecn_ce: u64,
    ecn_recovery_end: Option<u64>,
    persistent_congestion: bool,
    stats: RecoveryStats,
}

impl Bbr2 {
    fn new(config: Arc<Bbr2Config>, now: Instant, mtu: u16) -> Self {
        let mtu = mtu.max(1);
        let mss = u64::from(mtu);
        let maximum = config.max_window_bytes.max(4 * mss);
        let max_packets = maximum / mss;
        let mut model = BBRv2::new(
            config.initial_window_packets.min(max_packets),
            max_packets,
            mss,
            config.initial_rtt,
            None,
        );
        model.limit_cwnd(maximum);
        model.set_initial_time(now);
        Self {
            config,
            model,
            mtu,
            last_sent: None,
            batch_prior_flight: 0,
            acked: Vec::new(),
            lost: Vec::new(),
            ecn_ce: 0,
            ecn_recovery_end: None,
            persistent_congestion: false,
            stats: RecoveryStats::default(),
        }
    }

    /// Inspect model behavior without downcasting internal implementation types.
    pub fn state(&self) -> Bbr2State {
        let (lo, hi) = self.model.inflight_bounds();
        let (bw_lo, bw_hi) = self.model.bandwidth_bounds();
        Bbr2State {
            phase: self.model.state_str(),
            round: self.model.round_count(),
            min_rtt: self.model.min_rtt(),
            bandwidth_lo: bw_lo.map(|b| b.to_bytes_per_second()),
            bandwidth_hi: bw_hi.to_bytes_per_second(),
            inflight_lo: (lo != u64::MAX).then_some(lo),
            inflight_hi: (hi != u64::MAX).then_some(hi),
            bytes_in_flight: self.model.bytes_in_flight(),
            tracked_packets: self.model.tracked_packets(),
        }
    }
}

impl Controller for Bbr2 {
    fn pacing_rate_bytes(&self) -> Option<u64> {
        Some(
            self.model
                .pacing_rate(self.model.bytes_in_flight(), &RttStats)
                .to_bytes_per_second()
                .max(1),
        )
    }

    fn on_packet_sent(&mut self, now: Instant, packet_id: u64, bytes: u64, _in_flight: u64) {
        if bytes == 0 || self.last_sent.is_some_and(|last| packet_id <= last) {
            return;
        }
        self.last_sent = Some(packet_id);
        self.model.on_packet_sent(
            now,
            self.model.bytes_in_flight(),
            packet_id,
            bytes,
            true,
            &RttStats,
        );
    }

    fn on_feedback_start(&mut self, _now: Instant) {
        debug_assert!(self.acked.is_empty() && self.lost.is_empty());
        self.batch_prior_flight = self.model.bytes_in_flight();
        self.ecn_ce = 0;
        self.persistent_congestion = false;
    }

    fn on_packet_acked(&mut self, _now: Instant, packet_id: u64, sent: Instant, _bytes: u64) {
        if self.model.contains_packet(packet_id) {
            self.acked.push(Acked {
                pkt_num: packet_id,
                time_sent: sent,
            });
        }
    }

    fn on_packet_lost(&mut self, _now: Instant, packet_id: u64, bytes: u64) {
        if self.model.contains_packet(packet_id) {
            self.lost.push(Lost {
                packet_number: packet_id,
                bytes_lost: bytes,
            });
        }
    }

    fn on_ecn_feedback(&mut self, _now: Instant, _ect: u64, ce: u64) {
        self.ecn_ce = self.ecn_ce.saturating_add(ce);
    }

    fn on_feedback_end(&mut self, now: Instant) {
        // Quinn enumerates ascending packet numbers. Keep the adapter robust to
        // independent spaces, reordered test inputs, and accidental duplicates.
        self.acked.sort_unstable_by_key(|p| p.pkt_num);
        self.acked.dedup_by_key(|p| p.pkt_num);
        self.lost.sort_unstable_by_key(|p| p.packet_number);
        self.lost.dedup_by_key(|p| p.packet_number);
        self.lost.retain(|p| {
            self.acked
                .binary_search_by_key(&p.packet_number, |a| a.pkt_num)
                .is_err()
        });
        let largest_acked = self.acked.last().map(|p| p.pkt_num);
        if !self.acked.is_empty() || !self.lost.is_empty() {
            // Each ACK/loss/discard explicitly removes its packet; a value of 0
            // prevents space-local least_unacked from dropping another space's samples.
            self.model.on_congestion_event(
                true,
                self.batch_prior_flight,
                now,
                &self.acked,
                &self.lost,
                0,
                &RttStats,
                &mut self.stats,
            );
        }
        if self.ecn_ce != 0
            && largest_acked
                .is_some_and(|acked| self.ecn_recovery_end.is_none_or(|end| acked > end))
        {
            self.model.on_explicit_congestion(self.batch_prior_flight);
            self.ecn_recovery_end = self.last_sent;
        }
        if self.persistent_congestion && !self.lost.is_empty() {
            self.model.on_persistent_congestion();
        }
        self.acked.clear();
        self.lost.clear();
    }

    fn on_packet_discarded(&mut self, packet_id: u64) {
        self.model.on_packet_neutered(packet_id);
    }

    fn on_application_limited(&mut self, now: Instant) {
        self.model.mark_application_limited(now);
    }

    fn on_path_reset(&mut self, now: Instant) {
        // A clone for a fresh path must not retain old-path packet state or rate
        // samples. Other Quinn controllers keep their original clone behavior.
        *self = Self::new(self.config.clone(), now, self.mtu);
    }

    fn on_congestion_event(
        &mut self,
        _now: Instant,
        _sent: Instant,
        persistent: bool,
        _lost_bytes: u64,
    ) {
        // Per-packet feedback supplies all real loss/ECN events. The aggregate
        // callback contributes only Quinn's RFC 9002 persistent-congestion signal.
        self.persistent_congestion |= persistent;
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.mtu = new_mtu.max(1);
        self.model.update_mss(u64::from(self.mtu));
        self.model
            .limit_cwnd(self.config.max_window_bytes.max(4 * u64::from(self.mtu)));
    }
    fn window(&self) -> u64 {
        self.model.get_congestion_window()
    }
    fn metrics(&self) -> ControllerMetrics {
        ControllerMetrics {
            congestion_window: self.window(),
            ssthresh: None,
            pacing_rate: self.pacing_rate_bytes().map(|rate| rate.saturating_mul(8)),
        }
    }
    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }
    fn initial_window(&self) -> u64 {
        (self.config.initial_window_packets * u64::from(self.mtu))
            .min(self.config.max_window_bytes.max(4 * u64::from(self.mtu)))
    }
    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

#[cfg(test)]
mod tests;
