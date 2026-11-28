#!/usr/bin/env bash
set -euo pipefail
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$project_dir"
rust_channel="$(python3 - <<'PY'
import tomllib
with open('rust/rust-toolchain.toml', 'rb') as source:
    print(tomllib.load(source)['toolchain']['channel'])
PY
)"
rustup toolchain install "$rust_channel" --profile minimal --no-self-update
rustup target add --toolchain "$rust_channel" \
  aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android
sudo --non-interactive env \
  "PATH=$PATH" "JAVA_HOME=$JAVA_HOME" \
  "ANDROID_SDK_ROOT=$ANDROID_SDK_ROOT" "ANDROID_NDK_HOME=$ANDROID_NDK_HOME" \
  "CARGO_HOME=${CARGO_HOME:-$HOME/.cargo}" "RUSTUP_HOME=${RUSTUP_HOME:-$HOME/.rustup}" \
  "GRADLE_USER_HOME=${GRADLE_USER_HOME:-$HOME/.gradle}" \
  python3 rust/scripts/run-bounded-build.py -- ./gradlew \
  --no-daemon --max-workers=1 -Pkotlin.compiler.execution.strategy=in-process :app:buildRustNative
mkdir -p build-logs
{
  printf 'Application and Rust source commit: %s\nRust toolchain: %s\n' "$(git rev-parse HEAD)" "$rust_channel"
  sha256sum app/build/generated/rust/jniLibs/*/libaerobox.so
} | tee build-logs/rust-core-provenance.log
