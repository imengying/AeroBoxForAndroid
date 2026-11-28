# Naive interoperability peer

Test-only Go peer using independent HTTP/2 and HTTP/3 implementations and a
small Naive padding-v1 decoder. It echoes CONNECT payloads, validates Basic
authentication and emits an ephemeral localhost certificate. It does not
forward to the internet and is never linked into the Rust kernel.

```
CGO_ENABLED=0 go build -o /tmp/aerobox-naive-peer .
AEROBOX_NAIVE_PEER=/tmp/aerobox-naive-peer cargo test --manifest-path ../../../Cargo.toml naive_http2_and_http3_with_independent_go_peer -- --ignored
```

This checks protocol compatibility; it does not establish Chromium fingerprint
equivalence.
