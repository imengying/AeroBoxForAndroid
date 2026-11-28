# Independent ML-DSA certificate and TLS fixtures

This test-only generator uses Go's `crypto/mldsa` and `crypto/x509`; no Go or
OpenSSL code is linked into the Android core. The accepted run used Go 1.27.3
and OpenSSL 3.5.7. The Rust implementation uses the vendored RustCrypto ML-DSA.

The generator creates nine CA/intermediate/leaf chains: each of ML-DSA-44,
ML-DSA-65 and ML-DSA-87 with a classical issuer, a classical leaf, or an all-PQ
chain. It also creates wrong-EKU leaves, independently re-signed AlgorithmIdentifier
NULL cases, and independent TLS 1.3 CertificateVerify messages and signatures.
All private keys are disposable test fixtures. Output must be a new directory.

Run from the repository root with the project's bounded build wrapper:

```sh
python3 scripts/run-bounded-build.py -- sh -c '
  set -eu
  cd tests/reference/mldsa-chain-reference
  CGO_ENABLED=0 GOTOOLCHAIN=local GOWORK=off GOPROXY=off go build -mod=readonly -p=1 -trimpath -o ../../../target/mldsa-chain-reference .
  ../../../target/mldsa-chain-reference -output ../../../target/mldsa-chain-fixtures
'
```

Set `AEROBOX_MLDSA_FIXTURES` to the absolute generated directory and
`AEROBOX_OPENSSL_REFERENCE` to the reference `openssl` executable. Then run:

```sh
python3 scripts/run-bounded-build.py -- cargo test --offline --locked \
  --manifest-path crates/aerobox-crypto/Cargo.toml --test mldsa_chain \
  -- --include-ignored --test-threads=1 --nocapture
```

Repeat with `--release` before `--test`. The four external tests check full
certificate authentication, default-provider isolation, strict DER, and eleven
real TLS 1.3 connections per mode. Each connection transfers 65,537 application
bytes in each direction and verifies authenticated closure. The test uses a
fixed validation time inside the fixture validity interval. Native reference
server logs are written into the fixture directory.

These tests do not establish a Chromium ClientHello, H2/H3 wire match, Android
device behavior, or an ML-DSA client signing-key implementation.
