This test-only peer witnesses the Android kernel's 3DES record budget through a real Go-standard-library TLS1.2 ECDHE_RSA/3DES connection. It has no module dependencies and does not change the existing CBC or TLS-profile peers.

`--mode partial` accepts exactly 511 × 16,384 plaintext bytes: the Finished record consumes five blocks and each full record consumes 2,051 eight-byte blocks, leaving 510 blocks. `--mode exact` additionally accepts 4,059 plaintext bytes, whose MAC and one-byte padding consume exactly those final 510 blocks. Both modes require the underlying transport to truncate without TLS close_notify after the local Rust cipher fails. A bare transport EOF is converted into a distinct error before Go TLS can accept it as a clean EOF. Any extra or missing plaintext, wrong byte, partial wire record, extra CBC block, unexpected suite, or clean close_notify fails the witness.

Only 16 KiB of application input and at most 64 KiB of incomplete wire input are retained. The peer returns byte counts, SHA256, CBC block and record counts, negotiated parameters and its RFC5705 exporter. Go's exporter requires TLS1.2 Extended Master Secret. Rust verifies the ordinary fixture trust/hostname, exact certificate and exporter before starting its upload. The public certificate/key fixtures are passed with `--fixtures`; the fixed clock is 2030-01-01.

Build and self-test under the repository's shared bounded-build lock, with `CGO_ENABLED=0 GOMAXPROCS=1 GOMEMLIMIT=256MiB GOTOOLCHAIN=local GOPROXY=off`. From this module directory:

```
AEROBOX_TLS_FIXTURES=/absolute/path/to/crates/aerobox-crypto/tests/fixtures go test -mod=readonly -p=1 -count=1 -timeout=5m -v .
go build -mod=readonly -p=1 -trimpath -o /absolute/path/to/target/reference-peers/android-browser-tdes-budget .
```

Run the Rust `android_browser_tdes_budget` ignored integration tests serially in dev and release with `AEROBOX_ANDROID_BROWSER_TDES_BUDGET_PEER` set to that executable. Each run exercises four live connections: buffered/unbuffered × partial/exact. The failed multi-fragment write requests more than 8 MiB cumulatively, but correctly accepts fewer plaintext bytes because the budget includes MAC and padding; even the partial case sends 8,391,184 encrypted wire bytes including record headers and explicit IVs, plus the plaintext handshake. No production budget is overridden.
