# AeroBox Android runtime (shoes fork)

This copy of [shoes](https://github.com/cfal/shoes/) is maintained as AeroBox's
embedded Android runtime. The application scope is defined in
[the repository development guide](../../../docs/rust.md). The original upstream
pages under `docs/` are historical reference material; their protocol lists and
standalone release instructions do not describe this trimmed fork.

## Product protocols and shared transports

The Android app uses Shadowsocks/SS2022, VMess, VLESS (including Vision/REALITY),
Trojan, AnyTLS, Hysteria2, TUIC, Naive, SOCKS and HTTP. TLS, WebSocket,
HTTP/HTTPUpgrade/gRPC, multiplexing, UDP over TCP, DNS, routing and the TUN IP stack
remain available for those protocols.

WireGuard, Snell, Sudoku, XHTTP and ShadowTLS implementations and their dedicated
tests are removed. Shared HTTP/3 handling used by Naive lives in
`src/http3_transport.rs`; the TLS Hello parser used by Vision and TLS handling
lives in `src/tls_hello.rs`.

## Integration and validation

[`aerobox-android`](../../crates/aerobox-android/) owns JNI and calls
[`embedding::EmbeddedCore`](src/embedding.rs). Kotlin owns Android VpnService,
TUN descriptors and network callbacks. See [the Android build
instructions](../../../docs/rust.md).

The `shoes` command and remaining server-side helpers are retained as local
protocol interoperability peers. They are not an additional Android product.
Default App checks do not run this library's complete test suite. Use
[the retained test guide](tests/README.md) to select checks for code being changed.

Dependency versions and fork patches stay pinned in `Cargo.lock` and `Cargo.toml`.
Keep [dependency notices](THIRD_PARTY_NOTICES.md) and [source provenance](DEPENDENCIES.md)
with the vendored source; this cleanup does not upgrade dependencies.
