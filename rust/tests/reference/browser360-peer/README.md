Independent 360 7.5 non-EMS TLS reference peer

Status: frozen candidate, gofmt/static review only. This child did not compile,
execute Go tests, or establish any TLS connection. This is test-only Go code;
no Go or native crypto is linked into the Android Rust product.

Pinned dependency: github.com/metacubex/utls v1.8.7, commit
f7d52c22f3a8d2f510ad1470f75cb6c3fe26aa37, with exact go.mod/go.sum.
No EnableWeakCiphers, registration shim, module replacement or patched TLS
library is used. The default upstream implementation really supports these
13 suites: c00a c014 0035 c007 c009 c023 c011 c013 c027 0005 002f 003c 000a.
Three SHA2-CBC suites c023/c027/003c require TLS1.2; the other ten support
TLS1.0/1.1/1.2. The six FAKE suites plus default-disabled 003d are rejected by
CLI validation, as are TLS1.3 and out-of-range payloads.

The peer listens only on 127.0.0.1. It authenticates the client's certificate
with normal Go x509 chain/EKU verification when mTLS is selected, then pins
the exact generated clientAuth leaf. Existing RSA/P256 public fixture keys
are reused solely for test data. The fixed clock is 2030-01-01. Server
certificates, hostname, strong chain policy, OCSP staple transport, Finished,
actual negotiated version/suite and ALPN http/1.1 are validated. Resumption
is disabled. ServerHello is independently parsed and must omit EMS. Both
endpoints must refuse the non-EMS exporter; no application-level substitute
exporter bytes are sent. Bare TCP EOF is mapped to a distinct error so only
an authenticated TLS close_notify counts as io.EOF.

Run builds/tests only under the parent's shared memory/serialization wrapper.
Use the project-private GOPATH/GOMODCACHE/GOCACHE configured by the parent;
never depend on the externally cleared global module cache. The go.sum pins
all downloads. Example commands from the composed source root (after setting
AEROBOX_TLS_FIXTURES to its absolute crates/aerobox-crypto/tests/fixtures path):

  python3 scripts/run-bounded-build.py -- env CGO_ENABLED=0 GOMAXPROCS=1 GOMEMLIMIT=256MiB GOTOOLCHAIN=local go -C tests/reference/browser360-peer test -mod=readonly -p=1 -parallel=1 -count=1 -timeout=5m -v .
  python3 scripts/run-bounded-build.py -- env CGO_ENABLED=0 GOMAXPROCS=1 GOMEMLIMIT=256MiB GOTOOLCHAIN=local go -C tests/reference/browser360-peer build -mod=readonly -p=1 -trimpath -o /absolute/output/browser360 .

CLI (one connection, then exit):

  browser360 --fixtures /absolute/fixtures --version 1.2 --suite 0xc011 --mutual rsa --bytes 65537

--version: 1.0/1.1/1.2. --suite: decimal or 0x-prefixed real ID.
--mutual: none/rsa/ecdsa. --bytes: 1..1048576, default65537.
--ocsp: true by default. --rsa-sha1 explicitly forces TLS1.2 ECDHE_RSA SHA1;
this is an existing implemented 360 signature, not a weak certificate chain.
Default server ALPN is http/1.1, offered by the fixed 360 template.

Standard output is newline JSON:
1. phase=ready, port and (for mTLS) client_certificate_der_hex.
2. phase=complete with version, cipher, ALPN, client certificates/verified
   chains, bytes_each_direction, independent SHA256 payload hashes,
   exporter_rejected=true, ems=false, server_hello_observed=true,
   ocsp, close_notify_received=true and resumed=false.
On failure phase=error and a diagnostic precede a nonzero process exit.

Application exchange: client sends N bytes ((i*17+3)%251). Server writes
ASCII B360 then N bytes ((i*29+7)%251), concurrently with reading the client.
After exact data checks, the client sends close_notify and waits for the
server close_notify. The old AB11+exporter protocol is intentionally not used.
Socket lifetime is bounded45s, accept45s. Parser memory is capped128KiB per
record/handshake observer; application memory is capped by --bytes.

Planned Go selftests: TestFixed360DefaultRealSuites performs 99 successful
fixed-uTLS 360 handshakes (33 version/suite choices x none/rsa/ecdsa mTLS),
using localhost TCP, never net.Pipe. All subtests are serial and clean up the
server before changing fixture flags. After authenticating, the test sets
its uTLS exporter policy to RenegotiateNever only to distinguish non-EMS
refusal from the library's separate renegotiation exporter refusal; this
cannot alter the already sent ClientHello. The server always keeps its
original default Never policy. Other tests cover15 unsupported suite/version
choices, a real EMS handshake rejected before application output, and bare
TCP EOF rejection. These numbers describe source coverage, not passing runs.

Rust integration in target/360-profile-stage consumes AEROBOX_360_TLS_PEER:
browser360_interop declares99 full successes and66 name/root negatives;
the native asynchronous production test declares42 connections with stream
and preserved-record reads. It also verifies actual first-record lengths:
TLS1.0 RC4 is unsplit; TLS1.0 CBC remains1/n-1. Test roots and certificates
remain unchanged. Reference first-flight and renegotiation tests are separate.
