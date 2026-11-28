Independent Go sing-mux interoperability peer (test tooling only).

```sh
cd tests/fixtures/mux-peer
CGO_ENABLED=0 go build -tags debug -trimpath -o /tmp/aerobox-mux-peer .
cd ../../..
AEROBOX_MUX_PEER=/tmp/aerobox-mux-peer cargo test --lib all_mux_protocols_exchange_tcp_and_udp_with_go_sing_mux -- --ignored
```

Exercises smux, yamux and h2mux, padding enabled/disabled, concurrent streams,
flow control, TCP echo and connected UDP framing against the independent
SagerNet implementation pinned in go.mod/go.sum. The peer listens on loopback,
only echoes input, and is killed when its Rust test completes or fails.

The additional `brutal` argument enables the pinned sing-mux bandwidth exchange
(server upload 800000 B/s, receive 500000 B/s). Its upstream `debug` build tag
allows the reference **server** to continue when the test host has no TCP Brutal
kernel module. `reject` keeps Brutal disabled and exercises the official remote
rejection. Production Rust retains normal wire checks; local kernel failure is
reported as debug fallback, matching the upstream client.

`AEROBOX_MUX_EVENTS` optionally records carrier accepts and business TCP/UDP
streams. The Rust `h2mux::brutal::interop_tests` matrix checks three mux codecs,
padding on/off, first control exchange, carrier reuse and remote rejection,
including 0/3/16384/65535-byte UDP payloads. This does not prove the kernel module's
congestion behavior; the real module requires a separate capable test host.
