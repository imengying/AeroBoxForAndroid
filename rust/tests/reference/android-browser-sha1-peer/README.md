# Android browser ECDSA-SHA1 reference

This executable independently tests the handshake-signature capabilities needed
by the Android application's `safari`/Safari16 and `ios`/iOS14 fingerprint
choices. It adds no Apple-platform application and is not linked into Android.
The product implementation remains Rust. The Go peer and OpenSSL-generated
certificates are test references only.

The peer is restricted to TLS1.2 and ECDHE_ECDSA/AES128-GCM (`c02b`). It uses
MetaCubeX uTLS v1.8.7 with one documented fixture shim: before any handshake,
`defaultSupportedSignatureAlgorithms` becomes `[ECDSAWithSHA1]`, forcing the
CertificateRequest to advertise only `0203`. The server certificate's public
`SupportedSignatureAlgorithms` field independently restricts ServerKeyExchange
to the same scheme. Upstream Go SHA1 transcript hashing, ECDSA signing and
verification, Finished, EMS/exporter and application cryptography are unchanged.
This is explicit test policy rather than unmodified upstream behavior.

The shim is process-global and one-way; each executable process serves one
connection. It must not be imported into the ordinary peer or product library.
No existing `apple-cbc` source, executable or uTLS staging tree is modified.
`upstream.json` pins the original module commit, relevant source hashes,
BSD-style license and exact shim. `build.py` verifies those hashes and creates
a separate `target/reference-utls-android-browser-sha1` tree.

Fixtures come from `crates/aerobox-crypto/src/android_browser/sha1-fixtures.json`,
generated independently with OpenSSL. P-256/P-384/P-521 leaf certificates use
SHA256 certificate signatures, `localhost`, and both serverAuth/clientAuth.
Their CA is the only trusted root. The peer validates the selected strong
server fixture before listening, requires and verifies the full client chain
for mTLS, and checks the exact expected client certificate. Every fixture's
key curve and SPKI must match its leaf. The weak-certificate flag selects a
SHA1-signed leaf under that same CA only for client rejection tests; no verifier
is disabled and no insecure trust flag is set.

A bounded observer examines both directions before ChangeCipherSpec, preserving
all bytes. It asserts actual `0203` ServerKeyExchange and, for mTLS, a single
`0203` CertificateRequest entry followed by `0203` CertificateVerify. Normal
TLS code still verifies the signatures; the observer adds evidence of the
selected algorithm. EMS and the opaque OCSP transport fixture are also checked.
OCSP transport is not a claim of responder validity or revocation checking.

The application exchange sends `ABS1`, 32 exporter bytes and 65,537 server
payload bytes. The client simultaneously sends 65,537 bytes. Completion reports
both payload SHA256 hashes, exporter, actual signature IDs, authenticated chain
counts, curves and close_notify. Socket deadlines are 45 seconds, payloads are
capped at 1 MiB, and plaintext observation buffers are capped at 128 KiB. A bare
TCP EOF cannot satisfy the expected authenticated close.

The reference self-test covers all 3 server curves × (none + 3 client curves),
using a normal validating Go client with the same explicit signature policy.
Additional tests exercise fragmented/malformed observer input and reject the
three SHA1-signed leaf chains. The Rust integration test adds both Android
profile providers, producing 24 successes and 21 mandatory failures: 3 ordinary
provider refusals and 2 profiles × 3 server curves × (wrong name, wrong root,
SHA1-signed leaf).

Build and run only under the shared bounded build wrapper, after overlaying the
browser provider/fixture stage and this stage into the validation root:

```sh
python3 scripts/run-bounded-build.py -- python3 tests/reference/android-browser-sha1-peer/build.py --root . --test
AEROBOX_ANDROID_BROWSER_SHA1_PEER=/absolute/validation/root/target/reference-peers/android-browser-sha1 python3 scripts/run-bounded-build.py -- cargo test --offline --locked --manifest-path crates/aerobox-crypto/Cargo.toml --test android_browser_sha1 -- --ignored --test-threads=1 --nocapture
```

Source or test names do not assert execution. Parent validation logs must record
actual dev/release runs before integration. Complete ClientHello browser layouts,
TLS1.0/1.1 and other cipher suites are outside this reference's scope.
