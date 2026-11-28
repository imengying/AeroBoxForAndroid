# Android11 independent TLS peer

Test-only Go **1.26** standard-library `crypto/tls` server. It is not linked into
the Rust kernel, AAR or APK. No third-party modules, downloaded keys or runtime
dependencies are needed. Existing project RSA/P-256 public test fixtures are
loaded from `crates/aerobox-crypto/tests/fixtures`; validation time is fixed to
2030-01-01, as in the existing protocol fixtures. For mTLS the peer issues an
explicit clientAuth certificate using the existing test private key and returns
that certificate in its initial JSON. The original RSA/P-256 certificates have
only serverAuth EKU and cannot pass normal client-certificate verification.

Source is prepared but **has not been compiled or executed**. Build only through
the parent's common bounded build lock; reuse its Go cache and target directory:

```sh
python3 scripts/run-bounded-build.py -- bash -c \
  'cd tests/reference/android11-peer && go build -o ../../../target/android11-peer .'
```

Invoke from the project root, for example:

```sh
target/android11-peer --version 1.0 --suite 0xc013 --mutual rsa --bytes 65537
```

The flags are:

- `--version`: exactly `1.0`, `1.1` or `1.2`; min=max.
- `--suite`: one decimal or `0x`-prefixed suite ID; min=max plus this singleton
  suite prevent silent negotiation of another protocol/cipher.
- `--mutual`: `none`, `rsa`, or `ecdsa`. The latter two require, chain-verify and
  pin the generated clientAuth certificate, including its proof of key
  possession. The corresponding existing private key remains unchanged. A merely
  present client certificate or a serverAuth-only certificate does not pass.
- `--bytes`: default 65,537 application bytes each direction, bounded to 1 MiB.
- `--ocsp`: defaults true; send and confirm transport of the fixed bytes
  `AeroBox Android11 opaque OCSP transport fixture`. These bytes exercise TLS
  CertificateStatus/OCSP plumbing only; they are not a signed revocation result.
- `--rsa-sha1`: restrict a TLS1.2 ECDHE_RSA certificate to the real PKCS#1
  SHA-1 scheme (0x0201), for validating the dedicated Android11 verifier. It is
  rejected for other versions or suites. Old 1.0/1.1 RSA always uses MD5/SHA-1.
  This isolated test module sets `godebug tlssha1=1`, because Go 1.25+ otherwise
  disables TLS1.2 SHA-1. An external `GODEBUG=tlssha1=0` override makes that test
  fail; it does not silently choose another signature.
- `--fixtures`: override the existing DER certificate/key fixture directory.

The intended minimum cipher matrix is:

| Version | Cipher IDs |
| --- | --- |
| 1.0 and 1.1 | c013, c014, 002f, 0035 (the four Android11 CBC suites) |
| 1.2 | c02b, c02c, cca9, c02f, c030, cca8, c013, c014, 009c, 009d, 002f, 0035 |

The peer can also select c009/c00a to exercise the explicit provider's ECDSA-CBC
mapping, which is implemented but not advertised by the fixed Android11 profile.
The server certificate follows the cipher: P-256 ECDSA or RSA. RSA and ECDSA mTLS
can be requested independently of that server key.

## Single-connection protocol

1. stdout emits one JSON line `{"phase":"ready","port":PORT}`. Connect to
   `127.0.0.1:PORT` with SNI/verification name `localhost` and trust the selected
   existing server certificate. With mTLS this JSON also contains
   `client_certificate_der_hex`; use those decoded DER bytes as the client
   certificate with the existing `rsa-key.der` or `ecdsa-key.der` private key.
   No ALPN or session resumption is expected.
2. After TLS completes, the server sends `AB11` (4 bytes), a 32-byte TLS exporter,
   then the configured number of server-pattern bytes. The exporter label is
   `aerobox android11 exporter`, with the 11-byte context
   `00 61 6e 64 72 6f 69 64 31 31 00` and length 32. The Rust side should derive
   and compare the same exporter. Server byte i is `(i * 29 + 7) % 251`.
3. Concurrently send exactly `--bytes` client-pattern bytes; client byte i is
   `(i * 17 + 3) % 251`. Both sides read/write concurrently. The peer verifies
   every byte, not just its length.
4. After reading the complete known server response, send TLS close_notify
   without prematurely destroying the TCP read half. The peer requires an
   authenticated close_notify, then sends its own close_notify. The client reads
   the clean TLS EOF. The peer's TCP wrapper converts bare TCP EOF into a distinct
   failure, preventing Go's usual leniency from counting truncation as success.
5. stdout emits a final `phase=complete` JSON line with version, cipher, group,
   certificate counts, data hashes, exporter, EMS/OCSP status and close-notify
   evidence. Any failed condition emits `phase=error` and exits nonzero. Accept
   and connection operations have 45-second deadlines.

EMS is checked twice: plaintext ServerHello extension 23 must have an empty body,
and Go's key exporter must succeed. OCSP negotiation and the exact plaintext
CertificateStatus payload are captured before ChangeCipherSpec. The observer
does not alter TLS bytes and caps both buffers. Session tickets are disabled;
TLS1.2-only AEAD suites are rejected before opening a listener for legacy versions.
