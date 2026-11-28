# Pinned Naive reference

This local interoperability tool uses the same Cronet wrapper and native library
versions as the original Android core. Its Go/Cronet dependencies are test-only;
the Android application still contains the Rust implementation only.

The wrapper is pinned to `0d28acc44093df24b2526dea3d6ffefd6b0a54f0`; its
[Naive source](https://github.com/SagerNet/cronet-go/tree/0d28acc44093df24b2526dea3d6ffefd6b0a54f0)
pins [Chromium 150.0.7871.63](https://github.com/SagerNet/naiveproxy/tree/72a06c9fca0e2d228588c7f3074bf7efff3ff686).
`go.mod` and `go.sum` keep these reference versions fixed.

Run builds from the repository root under the shared resource limit:

```sh
python3 rust/scripts/run-bounded-build.py -- go build \
  -C rust/tests/reference/naive-profile-peer -tags with_purego -p 1 \
  -o /tmp/aerobox-naive-profile-peer .
```

The `native` mode needs `libcronet.so` from the pinned `lib/linux_amd64` module in
`LD_LIBRARY_PATH`. Start `-mode serve -output /absolute/new/capture-dir -requests 2`
and read its first JSON line for the port and generated CA path. Then run the same
binary with `-mode native -port PORT -ca CA_PATH -requests 2`. Both tunnels exchange
65,537 bytes using the original client. The observer independently decodes TLS,
HTTP/2 frames and HPACK. It saves `client-tls.bin` and `capture.json`, including
HEADERS priority and dynamic-table reuse. Only public test certificates are saved.

To capture the production Rust path, set `AEROBOX_NAIVE_PROFILE_PEER` to that binary
and `AEROBOX_NAIVE_PROFILE_OUTPUT` to another new absolute directory, then run:

```sh
python3 rust/scripts/run-bounded-build.py -- cargo test --locked \
  --manifest-path rust/vendor/shoes/Cargo.toml --lib \
  production_naive_tls_h2_matches_independent_reference_observer -- --ignored
python3 rust/tests/reference/naive-profile-peer/compare.py \
  /absolute/cronet-capture /absolute/rust-capture /absolute/comparison.json
```

The comparison preserves cipher/signature/group order, key-share shapes, TLS
extension contents, H2 settings/windows, CONNECT encoding, priority, header values
and table reuse. It checks the allowed forms of random fields and ignores their
values and the shuffled TLS extension order. It does not claim equivalence of
packet timing, the random-order distribution, QUIC/H3, or every Chromium behavior.

`rust/tests/tls-options` additionally exercises the production Naive verifier,
TLS 1.2/1.3 handshakes, session resumption and rejection after certificate expiry.
The independent H2/H3 transfer peer remains in
`rust/vendor/shoes/tests/fixtures/naive-peer`; its ignored tests use the production
TLS configuration and test bulk data, padding, FIN and QUIC receive windows.

## QUIC capture

Build the independent observer with the existing fixture's pinned dependencies:

```sh
python3 rust/scripts/run-bounded-build.py -- go build \
  -C rust/vendor/shoes/tests/fixtures/naive-peer -p 1 -o /tmp/aerobox-naive-peer .
AEROBOX_NAIVE_CAPTURE=/absolute/new/cronet-quic /tmp/aerobox-naive-peer
```

Read its ready JSON, then invoke the original client using `-mode native -quic
-port PORT -ca CA_PATH -requests 2` and the same pinned Cronet library path above.
The QUIC certificate name is `naive.test`; the fixture resolver maps it to IPv4
loopback. The observer decrypts authenticated QUIC v1 Initial packets and
reassembles CRYPTO bytes into `client-hello.bin`. It also saves datagrams, H3
SETTINGS, critical stream IDs, QPACK bytes and decoded CONNECT fields. Stream
termination records distinguish a clean FIN from Cronet's explicit reset after
reading its echo; timeouts and truncated frames fail the observation.

For the production Rust connector, choose another fresh absolute output directory:

```sh
export AEROBOX_NAIVE_PEER=/tmp/aerobox-naive-peer
export AEROBOX_NAIVE_CAPTURE=/absolute/new/rust-quic
python3 rust/scripts/run-bounded-build.py -- cargo test --locked \
  --manifest-path rust/vendor/shoes/Cargo.toml --lib \
  production_naive_h3_with_independent_reference_observer -- --ignored
python3 rust/tests/reference/naive-profile-peer/compare-quic.py \
  /absolute/new/cronet-quic /absolute/new/rust-quic /absolute/quic-comparison.json
```

The Rust test uses the production socket connector, TLS verifier, QUIC settings,
Naive client and padding. It verifies two 65,537-byte echoes over one connection
and checks that the observer received both request FINs. Another ignored test,
`production_naive_h3_rejects_wrong_root_and_hostname`, exercises the production
connector's certificate rejection against the independent server.

The comparator checks TLS fields separately from QUIC transport parameters and
compares CONNECT semantics. Its report retains remaining transport, SETTINGS,
header order and QPACK differences. The observer advertises zero QPACK capacity;
requests therefore use static/literal fields. The synthetic TLS record envelope
used by the reusable parser is never treated as a captured QUIC record.

The client also accepts dynamic response fields with a 64 KiB QPACK table and
up to 100 blocked streams. To exercise that production path, use another new
capture directory and run
`production_naive_h3_decodes_independent_dynamic_qpack -- --ignored` with the same
Cargo command above. The independent Go observer sends a response referencing a
dynamic `padding` entry, delivers the encoder instruction in fragments, and
reuses that entry for the second tunnel. It waits for a Section Acknowledgement
before echoing each payload and records the feedback in `capture.json`.

`production_naive_h3_waits_for_final_response_after_informational_heads` adds a
`100 Continue` before each dynamic final response. The fixed Cronet Naive wrapper
also accepts this sequence; it rejects `103 Early Hints`, so 103 is covered by
the shared H3 state-machine tests rather than counted as original Naive parity.
Set `AEROBOX_NAIVE_INFORMATIONAL=1` on the observer for the 100 response exercise.
For Android global VPN captures, `AEROBOX_NAIVE_CAPTURE_TARGET=host:port` selects
the test CONNECT target and rejects background probe connections. ClientHello
reassembly retains original Initial keys per connection, including packets whose
wire DCID has changed to a server-assigned CID; `accepted-connection.json`
identifies the selected peer. The fixture remains a local test observer.

Naive uses separate UDP endpoints for zero-length connection IDs, so parallel
connections and GOAWAY replacements retain distinct four-tuples. The independent
window test checks the advertised windows, 100 bidirectional/103 unidirectional
incoming streams and zero-length source CID. These checks do not establish
complete Chromium equivalence: outgoing dynamic QPACK, remaining QUIC extensions,
H3 settings/encoding and packet timing still differ.
