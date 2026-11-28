# Android browser-fingerprint CBC test peer

This executable is an independent Go reference for the CBC cipher suites used
by the Android app's `ios` and `safari` TLS fingerprint choices. There is no
iOS application or Apple-platform build in this project.

It reuses the existing Android11 reference server's authenticated test protocol:
strict server certificates, optional required RSA/ECDSA client certificates,
EMS exporter agreement, OCSP transport, duplex 65,537-byte payloads and
authenticated close_notify. The reference is test-only and is not linked into
the Android product. The added cipher registry is not presented as unmodified
upstream uTLS behavior.

The fixed upstream is MetaCubeX uTLS v1.8.7. `upstream.json` pins the relevant
upstream sources, license and fixture shim. The shim enables uTLS's existing
AES256/SHA2 implementations and adds them to both server preference lists.
For ECDHE-ECDSA/3DES (`c008`), upstream has only a fake advertised constant; the
shim explicitly combines upstream ECDSA key agreement with Go's existing
3DES-CBC/SHA1 primitives. It does not change certificate checks, TLS PRFs,
Finished verification or application framing. The ordinary TLS API exposes no
curve ID in this pinned version, so the reference report does not claim one.

Suites: TLS1.2 `c023/c024/c027/c028/003c/003d`, and TLS1.0/1.1/1.2
`c008/c012/000a`. Reference self-tests establish actual handshakes and verify
data for all 15 version/suite combinations. The Rust interop tests exercise
client-auth combinations and the full reference protocol separately.

Build only through the shared bounded build wrapper:

```sh
python3 scripts/run-bounded-build.py -- python3 tests/reference/apple-cbc-peer/build.py --root . --test
```

Test names and source are not a claim that the tests have run. The parent
stage's logs record execution and failures. Product dependencies remain Rust;
this Go executable and offline OpenSSL vector generator are reference tools.
