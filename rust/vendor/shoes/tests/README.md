# Runtime tests retained for AeroBox Android

The default application checks live in `.github/scripts/run-regression-tests.sh`
at the Android repository root. They cover configuration, the JNI/runtime
boundary and Kotlin behavior. Run protocol tests only when changing that code.

This directory retains routing/allocation checks, protocol interoperability
fixtures and shared test helpers. Standalone CLI process tests, external-network
smoke tests, privileged Linux network tests, stress/throughput benchmarks and
integration suites for protocols absent from the Android app have been removed.
Memory-release and allocation checks remain because they protect mobile resource
usage.

For a protocol change, select its target and module from the parent
`Cargo.toml` (one job on small hosts). Integration and optional-peer targets
require their named feature and may require an explicitly supplied peer binary.
The vendored `shoes` command is retained as a protocol test peer; Android embeds
the library through `aerobox-android`.

`fixtures/` and `support/` are shared by retained library and interoperability
tests. Keep them with the corresponding tests. This directory is not a second
application test gate or a requirement to run the entire vendored test suite.
