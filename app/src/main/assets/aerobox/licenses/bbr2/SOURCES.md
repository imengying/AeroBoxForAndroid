# BBRv2 sources and local adaptations

This is a Rust BBRv2 controller with its own delivery sampler and bandwidth /
inflight bounds. It does not call or alias Quinn's BBRv1 implementation. The
algorithm has STARTUP, DRAIN, ProbeBW DOWN/CRUISE/REFILL/UP, and ProbeRTT modes.
No new Cargo dependency, C/C++ code, native crypto backend, or proc macro is used.

## Fixed sources and licenses

- Cloudflare quiche **0.24.6**, commit
  **020a43a0a5eed76f57dd3ce5012149aa576c594d** (2025-09-03):
  [source tree](https://github.com/cloudflare/quiche/tree/020a43a0a5eed76f57dd3ce5012149aa576c594d/quiche/src/recovery).
  `upstream/bbr2.rs` and `upstream/bbr2/*.rs` come from
  `quiche/src/recovery/gcongestion/bbr2.rs` and `bbr2/*.rs`.
  `upstream/bbr/{bandwidth_sampler,windowed_filter}.rs` come from
  `quiche/src/recovery/gcongestion/bbr/`; `upstream/bandwidth.rs` comes from
  `quiche/src/recovery/bandwidth.rs`. The small compatibility types and optional
  parameter definitions in `upstream/mod.rs` were extracted from
  `quiche/src/recovery/gcongestion/mod.rs`.
- The copied Rust files preserve Cloudflare's BSD-2-Clause notices and the
  Chromium authors' notices. `LICENSE-CLOUDFLARE` is quiche's `COPYING`.
  `LICENSE` is the Chromium BSD-3-Clause license. Retain both notices in source
  and binary distributions; the header notices have their original years.
- B2ON parameter cross-check: Android commit
  `7206146effd0ac3602eb5b96ad5986e5af5ced5e`, sing-box `v1.14.4`,
  cronet-go `0d28acc44093df24b2526dea3d6ffefd6b0a54f0`, Naive/Chromium 150
  `72a06c9fca0e2d228588c7f3074bf7efff3ff686`.
  [Bbr2Params](https://github.com/SagerNet/naiveproxy/blob/72a06c9fca0e2d228588c7f3074bf7efff3ff686/src/net/third_party/quiche/src/quiche/quic/core/congestion_control/bbr2_misc.h),
  [flag defaults](https://github.com/SagerNet/naiveproxy/blob/72a06c9fca0e2d228588c7f3074bf7efff3ff686/src/net/third_party/quiche/src/quiche/common/quiche_protocol_flags_list.h).
  These are parameter/reference sources, not compiled dependencies.

## Algorithm adaptations

The quiche 0.24.6 default settings contain some explicitly BBRv3-labelled
experiments. This controller uses the fixed QUICHE B2ON defaults: startup pacing
2.885, startup/drain CWND gain 2, drain pacing 1/2.885, ProbeBW UP 1.25 / DOWN
0.91 / CRUISE 1, ProbeBW CWND gain 2, 2% loss threshold, beta 0.3, 15% inflight
headroom, three rounds with <25% bandwidth growth to leave STARTUP. Startup and
ProbeUP loss-event thresholds are eight and two, respectively. Loss adaptation
uses the default bandwidth-low mode. BBRv3-specific ProbeUP queue rounds and
2.25 CWND gain are disabled. ProbeRTT uses 0.5 BDP, a 10-second filter period and
a 200-ms hold. Minimum CWND is four packets (rather than quiche's initial ten).
As in the fixed Google source, the ProbeRTT timer also starts when inflight
reaches the four-packet minimum, so small-BDP paths can complete a probe.

This is **not a claim of bit-for-bit Cronet scheduling parity**. It uses the
mature Rust algorithm, Quinn's packet loss detection, the packet's raw RTT
(including peer ACK delay), and the following explicit local choices:

1. All protocol byte counters and round counters use `u64`, including on
   Android armeabi-v7a/x86. Rate calculations use `u128` intermediates and
   saturation; `usize` is reserved for container indices and lengths.
2. Ordinary enum matching replaces `enum_dispatch`. The original sampler's
   parameterized tests are expanded to plain standard-library tests.
3. Delivery samples use unique connection-wide packet identities, not QUIC's
   independently numbered Initial / Handshake / Data spaces. ACK batches also
   contain the losses detected by that ACK, and validated ECN, before the model
   changes modes. Actual in-flight bytes are model prior-flight minus actual
   delivered/lost bytes, not a guessed congestion-window or datagram size.
4. The sender explicitly signals application limitation. A batch reducing
   flight to zero alone does not postpone ProbeRTT. This avoids the false-idle
   behavior discussed in
   [quiche issue 2496](https://github.com/cloudflare/quiche/issues/2496).
5. The overestimate-avoidance sampler and corrected A0 selection are enabled,
   even though B2ON can select avoidance separately through BSAO. ACK/send
   slopes bound ACK compression; application-limited samples cannot lower the
   bandwidth maximum.
6. Probe starts use a distinct SplitMix64 stream per controller, with [0, 1s)
   jitter and a 0/1 round offset, filling quiche 0.24.6's fixed-delay TODO.
   This generator only desynchronizes probes; it is not cryptography.
7. QUICHE B2ON's imported model does not process ECN itself. Validated CE applies
   a conservative beta reduction to CWND, pacing, bandwidth-low and inflight
   bounds, at most once per sent flight, without fabricating lost packets.
   The decrease keeps a floor of min(current estimate, four MTUs/minRTT), so
   persistent CE cannot exponentially starve a minimum-window flow.
   This is an explicit local ECN policy following
   [RFC 9002 section 7.3.2](https://www.rfc-editor.org/rfc/rfc9002.html#section-7.3.2),
   not a claim to implement TCP BBRv2 DCTCP ECN alpha or L4S.
8. Quinn persistent congestion clamps CWND to four MTUs. A new path resets
   sampling and model estimates. The default maximum CWND is 16 MiB, configurable
   within 64 KiB–256 MiB. MTU changes rescale packet-based quantities while
   respecting the configured byte ceiling.
9. Discarded packets are neutered, never counted as delivered or lost. Missing
   or duplicate loss reports do not increment total lost bytes. A BTreeMap stores
   only live samples: an old packet in another QUIC number space cannot pin an
   ever-growing VecDeque of consumed slots. A 100,000-packet regression covers
   this boundary. ACKed-byte growth in the optional ProbeUP slope branch uses
   QUICHE's `delta * probe_up_bytes` subtraction, fixing the Rust port's remainder.

## Scope relative to Android

The fixed Android editor exposes `bbr2` for Naive/QUIC, selected as `B2ON` in
Cronet. Its TUIC choices are `cubic`, `new_reno`, `bbr`. The fixed sing-box
`v1.14.4` depends on sing-quic `7e0a5869a5f4`; that source's `tuic/client.go`
rejects TUIC `bbr2`. A shared native Rust factory accepting TUIC `bbr2` is an
extension, not a previously supported Android setting. `bbr` retains BBRv1;
`bbr2` constructs `Bbr2Config`.

## Verification boundary

The standalone tests exercise the algorithm/adapter without TLS or sockets.
The separate Quinn integration tests cover real packet-builder/ACK/loss hooks,
handshake key discard, stream transfer, excluded MTU probes, and runtime
controller changes. Passing only the standalone suite does not establish full
Quinn integration, Android ABI execution, real WAN fairness, or Cronet parity.
Consult the staging validation log for actual executed results; tests are never
considered passed merely because their source exists.
