# Fixed uTLS HRR construction reference

This independent module uses `github.com/metacubex/utls v1.8.7`, the same module/sums as the frozen `browser-profile-reference` tool. It sends an actual uTLS ClientHello, supplies a synthetic TLS1.3 HelloRetryRequest, captures the actual second ClientHello, and then returns EOF. It does **not** authenticate a server or complete a TLS handshake. `handshake_complete` must be false and the expected EOF is recorded separately from any construction/validation failure.

The default matrix is Edge85 and QQ11.1, with both `cookie-only` and `cookie-group` (P256/23) HRRs. HRRs always select cipher 0x1301, echo the actual session ID, select TLS1.3 and contain `aerobox-cookie`. Cookie-only leaves shares unchanged; group+cookie replaces them with P256. Optional Chrome133 is supported for comparison, without claiming identical extension distributions across profiles. Android11 is not a TLS1.3 profile and is deliberately not included.

Capture JSON retains the complete first/second handshake bytes, each flight's actual TLS records, all outbound bytes (including compatibility CCS), the full HRR and its record, before/after extension objects and their emitted lengths, source/profile/case/mode, and error fields. `normalize.py` is an exact copy of the frozen first-flight normalizer; `analyze.py` feeds each separate flight into it and checks the unnormalized bytes independently. GREASE equality classes are evidence, not a cross-process full-hex comparison contract.

## Run after the parent schedules the shared lock

From the main workspace, while this tool is still staged:

```sh
python3 scripts/run-bounded-build.py -- python3 target/browser-hrr-reference-stage/files/tests/reference/browser-hrr-reference/capture.py --root /home/Code/core --test --output-dir target/browser-hrr-reference-stage/evidence/captures
```

The runner uses `CGO_ENABLED=0`, `GOMAXPROCS=1`, `GOMEMLIMIT=256MiB`, `-p=1`, `-mod=readonly` and `GOPROXY=off`. It does not manage the lock itself: always invoke it through the shared runner. Compiled output goes to `target/reference-peers/browser-hrr-reference`; raw and validated JSON go to the explicitly supplied evidence directory. Environment HOME/GOPATH and the existing Go module cache must be available inside the bounded job, as for the other reference tools. Do not start a second build while another job owns the lock.

Direct binary arguments after compilation:

```text
--profiles edge,qq             # optional chrome
--modes cookie-only,cookie-group
--samples 16                 # 1..256 default-name samples per pair
--cases default,no_sni_verify_name,ipv4,alpn_custom
```

With no `--cases`, each profile/mode also tests direct h2, h2+HTTP/1.1, DNS lengths 63/127/191/253 and every attainable second-flight unpadded length in 255/256/507/508/511/512. Unattainable boundaries have explicit skip reasons. These boundaries adjust a valid DNS SNI only; no malformed extension padding is used to force a target.

## Fixed source semantics

`handshake_client_tls13.go:421–435` chooses Cookie's new **object** index by `Intn(len(Extensions)-2)`. For Edge there are 17 original objects, so indices 0..14 are possible; QQ has 18, so 0..15. The final GREASE and padding object are excluded. The SNI object still occupies a slot when IPv4 or no-SNI makes its emitted length zero. Count objects, then project to emitted wire positions; a random-sample test cannot require observing every allowed slot. `analyze.py` checks every observed slot is permitted, checks original objects remain in order and that the wire insertion position agrees with emitted lengths.

For cookie-only, fixed upstream leaves the complete key-share extension unchanged, including GREASE. For a group-changing HRR, upstream replaces it with the requested real group only. The validator checks exact retained bytes or a single real P256 SEC1 point, plus the group/share GREASE relationship and distinct GREASE extension identifiers. All non-cookie/non-padding/non-key-share extensions must preserve order and bytes.

`u_tls_extensions.go:1115` applies BoringSSL padding to the whole handshake length excluding the record header. For `256 <= unpadded < 512`, the padding extension occupies `max(512-unpadded, 5)` bytes. Consequently unpadded 508..511 yields lengths 513..516, and 512 adds no padding. Both flights are checked. The actual extension-object padding length can change after HRR even if its object position does not.

## Validation status

At handoff, Go sources are formatted but **not compiled or executed**. The Python validator has synthetic unit tests for both HRR forms, all allowed Edge object slots, omitted SNI, padding boundaries and malformed evidence. These tests validate the analyzer only; they do not establish real uTLS capture or Rust interoperability. The parent must run the Go capture/tests under the shared lock, inspect retained error fields, compare against the Rust increment, and then run authenticated cookie-HRR handshakes using the independent TLS profile peer. Existing tools, frozen stages, main sources and dependency caches are not modified by this stage.
