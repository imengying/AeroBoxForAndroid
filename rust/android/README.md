# Android integration

The platform bridge is compiled directly from the app's Kotlin sources. Gradle
`:app:buildRustNative` runs `build.sh` and packages the generated JNI libraries;
there is no intermediate AAR. See [development](../../docs/rust.md).

The native host is `../crates/aerobox-android`. It owns runtime cancellation,
network updates, platform DNS completion and bounded diagnostics. TUN descriptors
are borrowed from Kotlin and duplicated by Rust; each side closes its own copy.
The protocol runtime and cryptography remain Rust implementations.

`tests/` contains focused platform callback and session checks.
`../scripts/test-kotlin-*.sh` compile the real app bridge files against test
platforms. `../scripts/check-apk-config.sh` checks the real APK's Kotlin generator
through its packaged JNI library on an Android emulator.
