#!/usr/bin/env bash
set -euo pipefail
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
gradle_lib="${AEROBOX_KOTLIN_LIB:-/opt/gradle-9.8.2/lib}"
if ! compgen -G "$gradle_lib/kotlin-compiler-embeddable-*.jar" >/dev/null; then
  printf 'Set AEROBOX_KOTLIN_LIB to a directory containing the Kotlin compiler and dependencies.\n' >&2
  exit 2
fi
stdlib=("$gradle_lib"/kotlin-stdlib-*.jar)
mapfile -d '' sources < <(rg --files -0 "$project_dir/android/tests/session-lifecycle" -g '*.kt')
output_dir="$project_dir/target/android-kotlin-lifecycle"
mkdir -p "$output_dir"
java -Xmx256m -cp "$gradle_lib/*" org.jetbrains.kotlin.cli.jvm.K2JVMCompiler \
  -no-stdlib -no-reflect -jvm-target 1.8 \
  -classpath "${stdlib[0]}" -d "$output_dir/session-tests.jar" \
  "${sources[@]}" \
  "$project_dir/../app/src/main/kotlin/com/aerobox/core/native/RustVpnSession.kt" \
  "$project_dir/../app/src/main/kotlin/com/aerobox/core/native/VpnPlatformCallbacks.kt" \
  "$project_dir/../app/src/main/kotlin/com/aerobox/core/native/PhysicalNetwork.kt"
java -cp "$output_dir/session-tests.jar:${stdlib[0]}" com.aerobox.core.native.TestsKt
