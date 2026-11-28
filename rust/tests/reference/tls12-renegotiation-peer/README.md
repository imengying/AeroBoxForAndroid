# TLS 1.2 renegotiation reference

This **test-only** server is a minimal patch to MetaCubeX/uTLS v1.8.7. Its
existing TLS cryptography, transcripts and record keys remain independent of
the Rust implementation. The patch adds a server HelloRequest entry point,
stores the preceding Finished values, checks the client binding, and returns
the RFC5746 server binding. Fault flags alter binding, certificate, EMS, ALPN,
Finished and application-record timing. It must not be deployed as a TLS server.

The driver pins disposable public client certificate fixtures (their EKU is for
server authentication); the existing TLS CertificateVerify still proves key
possession. A test-only exporter bypasses Go's API prohibition on exporters
when renegotiation is enabled to compare the independent key schedules.

```sh
python3 scripts/run-bounded-build.py -- python3 tests/reference/tls12-renegotiation-peer/build.py
AEROBOX_TLS_FIXTURES="$PWD/crates/aerobox-crypto/tests/fixtures" CGO_ENABLED=0 \
  python3 scripts/run-bounded-build.py -- go -C tests/reference/tls12-renegotiation-peer test -mod=readonly -p=1 -count=1 -v .
AEROBOX_TLS12_RENEGOTIATION_PEER="$PWD/target/reference-peers/tls12-renegotiation" \
  python3 scripts/run-bounded-build.py -- cargo test --offline --locked \
  --manifest-path crates/aerobox-crypto/Cargo.toml --test tls12_renegotiation -- --include-ignored --test-threads=1
```

The reference self-test covers 90 combinations of standard/preset Chrome133
clients, five cipher suites and nine valid/fault modes. Rust additionally tests
ALPN continuity, EMS downgrade, repeated requests, opt-in policy, old-epoch
application records, cached Chrome ClientHello bytes, and ticket resumption
followed by a fresh authenticated handshake. TLS 1.0/1.1 and other browser
profiles are separate work.

Sources: [RFC5746](https://www.rfc-editor.org/rfc/rfc5746.html),
[RFC7627](https://www.rfc-editor.org/rfc/rfc7627.html),
[pinned uTLS](https://github.com/MetaCubeX/utls/tree/v1.8.7).
