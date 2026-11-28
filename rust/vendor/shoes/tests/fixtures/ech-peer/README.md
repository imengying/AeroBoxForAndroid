# Independent ECH reference peer

This test executable uses Go's `crypto/tls` ECH server API and the same pinned
`github.com/sagernet/quic-go v0.61.0-sing-box-mod.12` as `obfs-peer`. It is never
linked into the Rust kernel or included in an AAR. The module requires Go 1.26.3;
the initial fixture validation used the installed Go 1.27.3 toolchain. No custom
Go TLS patches are used.

```sh
CGO_ENABLED=0 go build -mod=readonly -trimpath -o /tmp/aerobox-ech-peer .
CGO_ENABLED=0 go test -mod=readonly -count=1 -v .
mkdir -p /tmp/aerobox-ech-rotate
AEROBOX_PEER_CERT_DIR=/tmp/aerobox-ech-rotate /tmp/aerobox-ech-peer tcp rotate
```

Arguments are `tcp|quic` and `accept|rotate|reject|badpublic`. All PEM and stats
files exist before stdout's first line, which contains the numeric listening
port on `127.0.0.1`. Diagnostics use stderr. Stop the process with SIGTERM or
SIGINT. Each run creates new keys and certificates; give each process its own
directory.

Both transports use TLS 1.3 with the private server name `secret.test`. ALPN is
`h3`. The QUIC application is a raw bidirectional byte-stream echo, without HTTP/3
framing. Multiple concurrent streams are supported. The server only echoes after
TLS reports `ECHAccepted=true`; a client silently falling back to plaintext SNI
will not obtain application data. The fixture self-test exchanges 65,537 bytes
on every successful TCP/QUIC scenario, including the post-rotation connection.

| Mode | Client's initial config | Server behavior |
| --- | --- | --- |
| `accept` | `config.pem` | Decrypts config ID 2 and presents the trusted `secret.test` certificate. |
| `rotate` | `config-old.pem` | Has no key for config ID 1. Presents trusted `public.test`, sends ID 2 as authenticated retry config, and accepts a new connection using that config. |
| `reject` | `config.pem` | Has no ECH keys. Presents trusted `public.test`, rejects ECH, and offers no retry config. |
| `badpublic` | `config-old.pem` | Same retry key as `rotate`, but the `public.test` certificate is signed by an untrusted CA. Clients must reject before trusting retry configs. Connecting directly with `config.pem` still succeeds against the trusted inner certificate. |

`accept` and `rotate` both load only the current private key; the mode chooses
which config is published in `initial-config.pem`. Config ID 1's private key is
never installed in the server or written to disk. ECH uses X25519,
HKDF-SHA256, and AES-128-GCM, with RFC 9849 ECHConfig encoding. Every certificate
has a separate Ed25519 key; the private and public certificate SANs do not
overlap.

Files written to `AEROBOX_PEER_CERT_DIR`:

| File | Contents |
| --- | --- |
| `ca.pem` | The only trusted test CA. Use as the client's root store. |
| `secret.pem` | Leaf certificate for `secret.test`, signed by `ca.pem`. |
| `public.pem` | Separate leaf certificate for `public.test`; untrusted issuer in `badpublic` mode. |
| `config.pem` | Current ECHConfigList (ID 2), in an `ECH CONFIGS` PEM block. |
| `config-old.pem` | Unavailable ECHConfigList (ID 1), in the same PEM format. |
| `initial-config.pem` | Mode-appropriate initial config, as shown in the table. |
| `handshakes.jsonl` | One record per TLS `VerifyConnection` callback, with `id`, `server_name`, `ech_accepted`, `tls_parameters_seen`, `tls_version`, and `alpn`. |
| `stats.json` | Atomically replaced snapshot with counts and all handshake records. |

`stats.json` has `attempts`, `ech_accepted`, `ech_rejected`, `connections`,
`streams`, `echoed_bytes`, `tcp_handshake_errors`, and a `handshakes` array.
Each attempt is inserted after ECH decryption is attempted; until the standard
library's `VerifyConnection` callback runs, its `tls_parameters_seen` is false.
Use the callback values for authoritative `ECHAccepted` and server identity.
Those callbacks also observe QUIC ECH rejection attempts, which never reach
`quic.Listener.Accept`. They precede receipt of client Finished, so
`connections` separately counts completed, ECH-accepted connections.

A successful rotation yields two attempts, one rejection with `public.test`,
one acceptance with `secret.test`, and one completed connection. A bad public
certificate yields a rejection observation and zero completed connections;
an explicit positive-control connection using `config.pem` then succeeds.
Counters can advance just after a client receives the final echoed bytes;
poll the atomic snapshot when checking `echoed_bytes`.

The Go self-test checks all eight transport/mode combinations, authenticates
retry configurations and rejection certificates using the stock Go client,
and verifies that `badpublic` still has a usable trusted inner certificate.
Rust interoperability tests must run separately using the built executable.
