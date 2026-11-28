#!/usr/bin/env bash
set -euo pipefail
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$project_dir/rust"
# Default checks cover the App boundary. Run protocol-specific suites only
# when changing that implementation; vendored library suites are not a gate.
cargo test --locked -p aerobox-config
bash scripts/test-android-platform.sh
cd "$project_dir"
./gradlew --no-daemon --max-workers=1 -Pkotlin.compiler.execution.strategy=in-process \
  --stacktrace :app:testDebugUnitTest :app:testRustPlatform
