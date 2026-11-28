# Independent simple-obfs peer

Test-only Go executable; no Go code is linked into AeroBox. Build with
`CGO_ENABLED=0 go build -mod=readonly -o /tmp/aerobox-obfs-peer .`.

`gost/http/conn.go` and `gost/tls/conn.go` are unmodified MIT-licensed files from
go-gost/x v0.32.0, commit `78568861776242d6eaba92fc448256639eb8931f`, paths
`listener/obfs/http/conn.go` and `listener/obfs/tls/conn.go`. The upstream license
is retained in `gost/LICENSE`. Only these two connection implementations are
vendored to avoid building GOST's unrelated listeners, metrics and servers.
`wrap.go` exposes the upstream private connection type; it changes no framing.

The first argument selects `http`, `tls`, `ws`, `wsmux`, `quic` or `udp`; the optional second argument is a
Shadowsocks cipher. Without a cipher the peer echoes transport bytes. With a
cipher it delegates Shadowsocks to the pinned SagerNet implementation and
echoes decrypted application bytes. The listening port is printed to stdout.

The HTTP fixture limits its first reads to the header and declared body length:
the upstream GOST implementation discards bytes prefetched past that body.
The TLS echo writes at most 8 KiB at a time because GOST's initial response
can contain only one record. The upstream files themselves remain unmodified.

WebSocket framing uses Gorilla; Xray mux uses the pinned sing-vmess server.
`AEROBOX_PEER_TLS=1` enables a freshly generated local certificate, written to
`AEROBOX_PEER_CERT_DIR/ca.pem`. Tests trust only that CA and verify that an
incorrect server name is rejected. These are test fixture credentials.

QUIC uses the pinned SagerNet quic-go fork and h3 ALPN, with raw bidirectional
streams as in the Android transport. It writes its CA and connection count to
`AEROBOX_PEER_CERT_DIR`. Sending `close` on stdin closes established sessions
and prints `closed`; tests wait for stream failure before retrying. The `udp`
mode runs only native Shadowsocks UDP, to prove plugin configuration does not
redirect UDP into a QUIC handshake. These modes require a cipher argument.

The UDP echo handler uses sing's PacketReadWaiter with MTU 65535: the older
ReadPacket copy path reports EOF for an empty packet, while its default waiter
allocation can truncate larger payloads. Neither workaround modifies SS bytes.
