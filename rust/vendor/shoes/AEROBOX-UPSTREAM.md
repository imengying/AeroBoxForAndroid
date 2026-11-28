# AeroBox vendored source

Upstream: https://github.com/cfal/shoes
Revision: 7680938b96a245a21d9e481ad009205b956e4436 (2026-11-16)
Archive: https://codeload.github.com/cfal/shoes/tar.gz/7680938b96a245a21d9e481ad009205b956e4436
License: MIT; upstream LICENSE retained.

This maintained copy is linked into the AeroBox CLI and Android JNI library.
Native crypto backends have been replaced with explicit AeroBox RustCrypto
providers and local patches for rustls, Quinn, rcgen, BLAKE3 and related crates.
The upstream license and notices are retained.

AeroBox additions include the embedded lifecycle controller, platform socket
protection/DNS integration, Android borrowed TUN support, strict configuration
conversion, native Shadowsocks/SOCKS UDP, UoT v1/v2, Android stream transports,
SMUX/YAMUX/H2MUX client pooling, Naive HTTP/3, negotiated HY2 bandwidth,
and conditional DNS routing. These changes are tracked by the parent repository.

Protocol support is being validated incrementally. The repository README and
Android migration document describe remaining scope. Server-side ACME issuance
is deliberately unavailable in this Android-focused build; configured file
certificates remain supported. Test-only reference peers are separate programs
and are not runtime dependencies.
