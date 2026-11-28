# Production TLS stream validation

This small Rust 2024 crate compiles the actual kernel's TLS stream, handshake,
record deframer, connection and synchronous I/O adapters. Only the carrier
trait and socket-control types are minimal test scaffolding. It avoids rebuilding
the entire protocol kernel while developing TLS I/O changes.

```sh
AEROBOX_TLS12_RENEGOTIATION_PEER="$PWD/target/reference-peers/tls12-renegotiation" \
  CARGO_TARGET_DIR="$PWD/crates/aerobox-crypto/target" \
  python3 scripts/run-bounded-build.py -- cargo test --offline --locked \
  --manifest-path crates/aerobox-crypto/validation/tls-stream/Cargo.toml --test interop -- --test-threads=1
```

Build the independent peer using `tests/reference/tls12-renegotiation-peer/build.py`.
The two tests cover 14 combinations of streaming/record-preserving reads,
short reads/writes with Pending readiness, cancelled reads/writes, renegotiation
driven by a writer, old-epoch data, fragmented records, bad Finished, and early
new-epoch application data. Full protocol-kernel regressions remain necessary.
