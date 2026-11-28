# AeroBox Android Rust sources

This directory is part of the AeroBox Android repository. The scope is the
features exposed by the original Android sing-box application. Rust 2024 owns
protocols, packet processing and cryptography; Kotlin owns the Android platform
and UI. Product TLS/QUIC uses the explicit Rust crypto provider.

- `crates/aerobox-config`: validates and translates the Android configuration.
- `crates/aerobox-android`: JNI, runtime lifecycle, probes and diagnostics.
- `vendor/shoes`: protocol, DNS, routing and TUN runtime.
- `crates/aerobox-crypto`, `crates/aerobox-primitives`: Rust cryptography.
- `crates/aerobox-fingerprint`: the Android app's TLS fingerprint options.

Kotlin platform sources live in `../app/src/main/kotlin/com/aerobox/core/native/`.
Build the app with Gradle from the repository root; it builds the Rust JNI
libraries automatically. See [development instructions](../docs/rust.md) and
[integration status](../docs/rust-integration.md).

The standalone core was imported from commit
`4c312077739ec7e2e94ac9cef1e29437f1ce017e`.
`docs/` contains historical implementation and verification notes, not a new
feature roadmap. Old absolute paths and AAR instructions describe earlier builds.
Original third-party licenses remain alongside vendored source.
