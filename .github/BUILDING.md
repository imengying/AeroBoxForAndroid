# Rust Android CI

The `rust` branch builds the Kotlin app with `aerobox-core.aar`. It does not
download or build a Go runtime. The core remains in its own repository and is
checked out once at `.rust-core` for CI.

Configure these repository variables before running either workflow:

| Variable | Value |
| --- | --- |
| `AEROBOX_CORE_REPOSITORY` | The actual Rust core GitHub `owner/repository`. There is no default or placeholder repository. |
| `AEROBOX_CORE_REF` | The full 40-character commit SHA reviewed together with this app's Kotlin bridge. Branch names and tags are rejected. |

The CI workflow also accepts `core_repository` and `core_ref` dispatch inputs;
each nonempty input overrides its corresponding variable. Tag releases use the
repository variables. A private core requires a read-only `AEROBOX_CORE_TOKEN`
secret with access to that repository; otherwise checkout uses `github.token`.
Fork pull requests cannot access private-repository secrets. Missing source
configuration fails before installing build dependencies.

The current local core checkout has no Git remote. This change supplies the CI
contract but cannot select or verify an online core repository on its behalf.

Both workflows keep JDK 25, Android SDK 37.2, NDK 30.0.16248370 and Gradle 9.8.2.
The Rust toolchain comes from the selected core's `rust-toolchain.toml`. The build
script installs its four Android standard-library targets and calls the core's
existing `android/build-aar.sh`, which first runs `android/build.sh all`, then
compiles the Kotlin bridge and packages all four JNI libraries. The core's
dependency and shared-library checks remain part of each ABI build.

The existing `scripts/run-bounded-build.py` serializes the ABI builds and enforces
5 GiB RAM / 1 GiB swap limits. Hosted Ubuntu's passwordless sudo is used to create
its systemd scope. Only explicit build inputs are forwarded; signing secrets are
not available to that step. There is no fallback to an unbounded build. The
resulting AAR's required entries are checked, and its SHA-256, exact core commit,
toolchain and memory logs are retained with build logs.

Gradle reads the AAR from `-PAEROBOX_CORE_AAR=...`, then `AEROBOX_CORE_AAR` in the
environment, then the local sibling path
`../core/target/android/aerobox-core.aar`. A missing archive is an immediate
configuration error. Local developers build the sibling core first; CI exports
the archive from its pinned checkout. No kernel sources are copied into the app.

Routing assets remain SRS data and are downloaded into `app/src/main/assets/rules`.
They are inputs accepted by the Rust core, independent of the removed Go build.
The existing tag-derived app version, v3 signing, release signing secrets, beta
signing and APK publication steps are retained. Automatic beta builds now follow
the `rust` branch. Editing these files locally does not trigger a publication.

The CI scripts have undergone shell syntax, YAML/embedded-shell parsing and
reference checks locally. The app has also passed local Gradle compilation,
focused existing JVM checks and an emulator smoke test using the local AAR.
The Rust native libraries were reused unchanged. Remote CI and publication have
not been run; the online core repository still needs to be configured.
