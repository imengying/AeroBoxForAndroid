# TUIC / UoT independent reference peer

Fixed App dependencies: sing-box v1.14.4's sing-quic 7e0a5869a5f4,
quic-go v0.61.0-sing-box-mod.12, sing 5dc452e537bf, and x/exp 746e56fc9e2f
(as selected by the fixed App module graph). No replacement protocol
implementation is used: the server is sing-quic's TUIC Service. Its ordinary TCP
handler recognizes sing UoT v2's exact magic destination and parses the stream
with sing/common/uot; this is independent of the Rust implementation.

```
CGO_ENABLED=0 GOMAXPROCS=1 GOMEMLIMIT=256MiB go test ./...
CGO_ENABLED=0 GOMAXPROCS=1 GOMEMLIMIT=256MiB go build -o /tmp/aerobox-tuic-peer-bin .
AEROBOX_PEER_CERT_DIR=/tmp/tuic-certs /tmp/aerobox-tuic-peer-bin accept uot-only
```

First stdout line is its local UDP port. Files: ca.pem (an independent CA; the
server sends a separate Ed25519 leaf) and events.jsonl. TLS name
localhost or tuic.test; ALPN h3; UUID d9ad4eab-f118-492b-a99b-e0e27332b4b2;
password test-password. Modes accept, reject, reject-after-first, disabled.
The reject-after-first mode keeps TLS ticket keys but disables early data for
subsequent QUIC connections. The optional uot-only flag refuses native TUIC UDP,
so an accidentally wrong converter cannot pass by sending COMMAND_PACKET.
Ordinary TCP still echoes. UoT packet events record destination, length and hash,
never payload; TCP close events record total bytes and hash. TLS handshake events
report actual resumed / used_0rtt state. AEROBOX_TUIC_HANDSHAKE_DELAY_MS (0..1000)
adds a bounded test-only server handshake delay to make early writes observable
on loopback. Native UDP has a 30-second association timeout; the self-test verifies
that an empty packet does not expire or recreate the association.
A test must warm tickets, close only the connection and keep client TLS config
before asserting actual early data. Merely choosing accept is not evidence of
0-RTT. Ctrl-C/SIGTERM closes the service.

Its Go code is solely an independent test counterpart and is never linked into
the kernel. The Rust ignored test uses AEROBOX_TUIC_PEER to locate the binary;
scripts/test-interop.sh builds and runs it alongside the other independent peers.
