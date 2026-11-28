# HTTP transport regression checks

This small host crate compiles the production HTTP/2 session, stream transport,
header validation and WebSocket early-data validation sources directly. It tests
configured PING timeouts, incoming-traffic idle detection, defaults, and repeated
headers against independent HTTP/1 and HTTP/2 wire peers. Small adapters provide
unrelated runtime types; no protocol implementation is copied into this crate.

Run from the repository root under the shared build limit:

```sh
python3 rust/scripts/run-bounded-build.py -- cargo +1.100.0 test --locked \
  --manifest-path rust/tests/http2-transport/Cargo.toml --test keepalive --test headers
```

Full WebSocket upgrade assertions remain in the runtime's existing
`websocket/early_tests.rs` tests. App-to-JNI configuration checks are in
`android/tests/config-contract/`.
