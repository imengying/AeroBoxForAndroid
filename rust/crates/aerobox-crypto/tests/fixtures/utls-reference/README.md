# Fixed uTLS ClientHello reference

This is an independent Go test tool. It is never compiled or linked into the
Rust kernel, JNI library, or AAR. `go.mod` pins `github.com/metacubex/utls v1.8.7`
with `go.sum`; this is the version used by the Android app's sing-box v1.14.4.
There is no absolute filesystem replacement or dependency on a local checkout.

Run from this directory with Go 1.26 and Python 3:

```sh
CGO_ENABLED=0 GOMAXPROCS=2 go run -mod=readonly . > captures.json
python3 normalize.py captures.json > normalized-captures.json
CGO_ENABLED=0 GOMAXPROCS=2 go run -mod=readonly . negotiate > negotiation.json
```

`captures.json` contains 14 configuration cases for each of Android 11 OkHttp
and Chrome 133. The fake socket captures the actual first record written by
uTLS and then returns EOF: **this proves wire construction, not a successful
server handshake**. The small ALPN wrapper reproduces sing-box v1.14.4's rule
of replacing an existing extension without adding a missing one. The tool is
otherwise directly using the pinned uTLS library, not importing all sing-box.

`normalized-captures.json` removes random session IDs, client randoms, key share
bytes and ECH ciphertext. It preserves cipher/extension order, field lengths,
GREASE relationships, and the relationship between hybrid and standalone
X25519 public keys. Chrome's middle extension order and GREASE ECH length are
random by design, so this file is one permitted sample, not a fixed byte string
to compare without normalization rules. Android's `random_and_session_id_zeroed_hex`
is a complete deterministic record for each captured configuration.

`negotiation.json` has 16 **completed** in-memory client/server handshakes and
four-byte echo exchanges with Go's standard TLS server. They demonstrate
Android TLS 1.0/1.1/1.2, overridden min/max/cipher/group settings, client
certificate authentication, and lack of resumption despite an explicit cache.
The public certificate fixtures in the parent directory are used with a fixed
2030 verification time; `AEROBOX_CRYPTO_FIXTURES` can override that directory.
No deployed credentials or signing keys are needed.

The ECH capture cases use a fixed **test-only** X25519 key to encode a valid
ECHConfigList. Android's profile lacks an ECH extension: v1.8.7 ignores an
internal serialization error and emits an invalid offer. Capturing that offer
must not be described as usable ECH support. REALITY's missing early X25519 key
is established from the fixed sing-box source, rather than this standalone
test program. See `docs/android11-chrome133-wire-audit.md` for those boundaries.

Provenance: captures generated on 2026-11-20 using the pinned published module;
the initial local v1.8.7 reference produced the same Android normalized fields.
The complete Rust browser fingerprint implementation remains separate work.
