# Independent legacy TLS renegotiation peer

This is test-only code based on the existing TLS1.2 fixture and pinned
MetaCubeX/uTLS v1.8.7. It is separate from that fixture. It enables the same
server entry point for TLS1.0/1.1 and preserves uTLS's PRF, CBC implicit/explicit
IV behavior, key exchange, client authentication, and Finished verification.
The small patch adds RFC5746 server initiation/binding plus controlled faults;
it must never be shipped as a production TLS server.

Status: source prepared and gofmt/static patch/hash checks only. No Go build,
self-test, capture or Rust interoperability result is claimed here.

Build and self-test under the shared memory/serialization lock:

```sh
python3 scripts/run-bounded-build.py -- python3 tests/reference/legacy-renegotiation-peer/build.py --test
```

`build.py --root /absolute/source-root` also works when this module is still in
an isolated stage. It checks the cached official uTLS files and LICENSE hash,
copies them to `target/reference-utls-legacy-renegotiation`, applies a zero-fuzz
patch, checks the proposed hashes, and builds
`target/reference-peers/legacy-renegotiation`. It does not replace the existing
TLS1.2 reference. `--prepare-only` does no compilation. No cache/target cleanup
is performed. Compilation remains the parent agent's responsibility.

The reference self-test source covers 102 valid version/profile/cipher/mTLS
cases, 90 fault/repeat cases, 18 fragmented/consistent-no-EMS cases, 27 known
upstream permissive-policy cases, and 6 upstream old-epoch receive-limit cases.
They are serial, have deadlines, reject timeouts as proof of protocol rejection,
and use at most a 65537-byte echo plus bounded TLS buffers. These counts describe
planned cases, not passing results.

Run a single independent peer:

```sh
target/reference-peers/legacy-renegotiation --fixtures crates/aerobox-crypto/tests/fixtures --version 1.0 --suite 0xc013 --mutual --mode valid --hellos /tmp/legacy-client-hellos.json
```

`--version` is `1.0`, `1.1` or `1.2`; default1.2. Default cipher is c013 for old
versions, c02f for1.2. Four CBC-SHA suites c013/c014/002f/0035 are supported in
all versions. c02f/c030/009c/009d/cca8 are accepted only for1.2. The peer validates
this before reading fixtures. CLI unknown modes fail early.

Standard output is newline-delimited JSON:

1. `{"phase":"ready","port":N,"version":769,"cipher":49171,"mode":"valid","exporter_label":"aerobox-renegotiation","max_echo_bytes":1048576}`
2. A terminal `phase=complete|error` result with negotiated version/cipher/ALPN,
   completed handshake count, client cert count, echo byte count, event trace,
   and any error. An injected failure is explicitly `phase=error`, even though
   the process can exit successfully after writing the diagnostic JSON.

The TLS application protocol remains compatible with the earlier fixture:

1. Client completes initial TLS handshake at the requested version/suite.
2. Server writes ASCII `initial` followed by32 exporter bytes.
3. Client writes exactly ASCII `ack`.
4. Server sends HelloRequest and performs a full, fresh authenticated handshake.
5. Server writes ASCII `renewed` followed by32 new exporter bytes; they must differ.
6. Client sends up to1MiB; server echoes it. Use65537 bytes to cross record and
   TLS1.0 1/n-1 splitting boundaries. Client sends close_notify, then reads server
   close_notify. Socket lifetime is bounded20s; accept is bounded30s.

The exporter uses label `aerobox-renegotiation`, no context, length32. It calls
uTLS's internal key-schedule exporter only for fixture comparison, because the
public Go API intentionally disallows exporters with renegotiation enabled.
This is not permission to expose old-version/renegotiated exporters in the
Rust product. Rust tests may compare where allowed or just check epoch changes.

Modes:

| Mode | Behavior / Rust expectation |
| --- | --- |
| valid | Both full handshakes succeed; fresh exporter and data/close succeed |
| fragment | Server handshake plaintext is split into at most97-byte records, including after HelloRequest; success |
| inflight | Writes `old-data` (8 bytes) under the old outgoing record epoch immediately before server CCS; client reads it before `renewed`; success |
| inflight-fragment | Both preceding behaviors; success |
| no-ems | Both initial and renewed handshakes omit EMS; record/Finished still valid; follow explicit Rust profile policy |
| bad-binding | Corrupt client half of returned RFC5746 binding; reject |
| bad-server-binding | Corrupt server half (offset12); reject |
| short-binding / omit-binding | Truncate to12 / omit binding; reject |
| initial-no-binding | No secure binding in first handshake; later renegotiation must be rejected by Rust |
| initial-nonempty | Nonempty binding in first handshake; reject |
| changed-certificate | Renewed leaf differs but uses same RSA key; reject |
| changed-alpn | h2 becomes http/1.1; reject by Rust continuity policy |
| changed-version | Mutate only authenticated ServerHello.vers (1.0→1.1;1.1→1.0;1.2→1.1), retain current record header/key epoch; reject |
| ems-downgrade | Initial EMS, renewed no EMS; reject |
| bad-finished | Corrupt renewed server Finished proof; reject |
| early-data | Application bytes after server CCS but before verified Finished; reject and never deliver `unverified` |
| repeat | Send second HelloRequest after renewed marker; reject |

`--mutual` requires the exact public RSA fixture during renegotiation and still
verifies its CertificateVerify proof. That leaf has serverAuth EKU, so this
fixture uses an explicit leaf pin rather than pretending it passes clientAuth
chain purpose checks. Strict clientAuth chain verification was separately
covered by the Android11 peer. The old and new fixture behavior stays explicit.

Known reference limits: pinned uTLS's client accepts changed ALPN/EMS and an
initial missing secure binding; its client also rejects valid old-epoch data
while its handshake flag is false. Dedicated self-tests characterize these
limits; they are not acceptable Rust behavior. The trace records old-data
before CCS and early-data after CCS. Rust integration must separately assert
its stronger policy and its correct old-epoch acceptance. The patch changes no
client verification logic to manufacture a favorable reference result.

Parent validation still required: build/self-tests; Rust matrix across all
versions and both Edge/QQ; every fault with appropriate alert/permanent failed
state; correct old/new CBC IV and sequence transitions; input record fragmentation;
normal TLS1.2 fixture regressions; bounded32-bit builds. Original/proposed hashes
are in upstream.json, and BSD copyright/conditions are retained in UTLS-LICENSE.
