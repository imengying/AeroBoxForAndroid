# Rust + Kotlin Android builds

The `rust` branch contains the application, Kotlin JNI callbacks, Rust core and
patched Rust dependencies in one repository. CI checks out this repository once.
No external core checkout, AAR, repository variable or core token is required.

The toolchain is JDK 25, Android SDK 37.2, Build Tools 37.0.0, NDK 30.0.16248370,
Gradle Wrapper 9.8.2, and the exact Rust version in `rust/rust-toolchain.toml`.
`.github/scripts/build-rust-core.sh` installs the four Android Rust targets and
runs `:app:buildRustNative`. The same task runs automatically when an APK needs
native libraries. Cargo uses locked dependencies and builds the ABIs sequentially.
The normal/build dependency audit and shared-library audit run for each ABI.

`run-regression-tests.sh` runs the App's Rust configuration checks, Android host
lifecycle/DNS/probe/connection tests and Kotlin tests under the same resource
limit. Vendored protocol/library suites are not part of the default gate. Run a
relevant protocol suite only when its implementation changes; ordinary App work
does not require compiling the full kernel test binary or repeating device checks.
`rust/scripts/test-android-platform.sh` runs the focused native host tests.
`:app:testRustPlatform` runs the
actual Kotlin platform classes with mocked Android/JNI boundaries: VPN lifecycle,
system DNS, connection ownership and standalone probe network handover. The four
individual tasks are also available for focused checks. They use the wrapper's
Kotlin compiler; device validation remains separate.
Before signing,
both workflows audit each packaged APK's JNI names, signatures and platform
callbacks after R8. Removed JNI methods also cause the audit to fail if retained.

Kotlin bridge sources are compiled directly in the app. Their JNI entry points
and callbacks are retained by `app/proguard-rules.pro`; BBRv2 notices are included
in `app/src/main/assets/aerobox/licenses/bbr2/`.

`rust/scripts/run-bounded-build.py` serializes build commands and limits the entire
process group to 5 GiB RAM and 1 GiB swap. Hosted Ubuntu's passwordless sudo starts
the systemd scope. The same entry point covers Gradle tests, lint and packaging.
Native build inputs, the application commit, library hashes and memory logs are
retained with build logs. Rust and Kotlin always come from the same checkout.

For local builds, run the commands in [docs/rust.md](../docs/rust.md). JVM tests do
not require native binaries. Use `-PAEROBOX_ABIS=x86_64` for an emulator or
`-PAEROBOX_ABIS=arm64-v8a` for a phone; the default is all four original ABIs.
Rust defaults to the optimized release profile; `AEROBOX_RUST_PROFILE=dev` is
available as a Gradle property for local debugging. Only the selected ABIs are
packaged. Native changes invalidate the Gradle task and are rebuilt by Cargo;
Kotlin-only edits reuse its generated libraries.

Routing assets remain SRS files prepared by `prepare-geo-assets.sh`. Existing
version derivation, v3 signing, release signing secrets, beta signing and APK
publication remain in the workflows. No remote workflow or publication is needed
for local validation.
