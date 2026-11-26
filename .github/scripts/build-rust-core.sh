#!/usr/bin/env bash
set -euo pipefail

: "${GITHUB_WORKSPACE:?GITHUB_WORKSPACE is required}"
: "${GITHUB_ENV:?GITHUB_ENV is required}"
: "${ANDROID_SDK_ROOT:?ANDROID_SDK_ROOT is required}"
: "${ANDROID_NDK_HOME:?ANDROID_NDK_HOME is required}"
: "${JAVA_HOME:?JAVA_HOME is required}"
: "${AEROBOX_CORE_REF:?AEROBOX_CORE_REF is required}"

core_dir="${GITHUB_WORKSPACE}/.rust-core"
for source in rust-toolchain.toml android/build-aar.sh android/build.sh scripts/verify-kotlin.sh scripts/run-bounded-build.py; do
  if [[ ! -f "${core_dir}/${source}" ]]; then
    echo "::error::The selected Rust core is missing ${source}." >&2
    exit 2
  fi
done
core_commit="$(git -C "$core_dir" rev-parse HEAD)"
if [[ "$core_commit" != "${AEROBOX_CORE_REF,,}" ]]; then
  echo "::error::Rust core checkout does not match AEROBOX_CORE_REF." >&2
  exit 2
fi

rust_channel="$(python3 - "$core_dir/rust-toolchain.toml" <<'PY'
import re
import sys
import tomllib
with open(sys.argv[1], 'rb') as source:
    channel = tomllib.load(source)['toolchain']['channel']
if not isinstance(channel, str) or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', channel):
    raise SystemExit('Rust core must pin an exact stable toolchain in rust-toolchain.toml')
print(channel)
PY
)"
rustup toolchain install "$rust_channel" --profile minimal --no-self-update
rustup target add --toolchain "$rust_channel" \
  aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android

# setup-gradle installs the same version as gradle-wrapper.properties. Its lib
# directory supplies the compiler already used by the core's verify-kotlin.sh.
gradle_launcher="$(readlink -f "$(command -v gradle)")"
export AEROBOX_KOTLIN_LIB="$(dirname "$(dirname "$gradle_launcher")")/lib"
export AEROBOX_ANDROID_JAR="${ANDROID_SDK_ROOT}/platforms/android-37.2/android.jar"
if [[ ! -f "$AEROBOX_ANDROID_JAR" ]] || ! compgen -G "$AEROBOX_KOTLIN_LIB/kotlin-compiler-embeddable-*.jar" >/dev/null; then
  echo "::error::Android 37.2 and the installed Gradle Kotlin compiler are required." >&2
  exit 2
fi

export RUSTUP_TOOLCHAIN="$rust_channel"
export CARGO_HOME="${CARGO_HOME:-${HOME}/.cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-${HOME}/.rustup}"
export AEROBOX_BUILD_PROFILE=release
export ANDROID_API_LEVEL=31

# The existing core runner holds one build lock and caps RAM at 5 GiB (plus
# 1 GiB swap). Hosted Ubuntu permits sudo; no unbounded fallback is provided.
# Only build inputs are forwarded, not repository/signing tokens.
sudo --non-interactive env \
  "PATH=$PATH" "JAVA_HOME=$JAVA_HOME" \
  "CARGO_HOME=$CARGO_HOME" "RUSTUP_HOME=$RUSTUP_HOME" "RUSTUP_TOOLCHAIN=$RUSTUP_TOOLCHAIN" \
  "ANDROID_NDK_HOME=$ANDROID_NDK_HOME" "ANDROID_API_LEVEL=$ANDROID_API_LEVEL" \
  "AEROBOX_BUILD_PROFILE=$AEROBOX_BUILD_PROFILE" \
  "AEROBOX_KOTLIN_LIB=$AEROBOX_KOTLIN_LIB" "AEROBOX_ANDROID_JAR=$AEROBOX_ANDROID_JAR" \
  python3 "$core_dir/scripts/run-bounded-build.py" -- bash "$core_dir/android/build-aar.sh"

aar_path="$core_dir/target/android/aerobox-core.aar"
python3 - "$aar_path" <<'PY'
from pathlib import Path
import sys
import zipfile
aar = Path(sys.argv[1])
if not aar.is_file():
    raise SystemExit('Rust build did not produce aerobox-core.aar')
with zipfile.ZipFile(aar) as archive:
    required = {'classes.jar', 'AndroidManifest.xml', 'proguard.txt'}
    required.update(f'jni/{abi}/libaerobox.so' for abi in ('arm64-v8a', 'armeabi-v7a', 'x86_64', 'x86'))
    missing = required - set(archive.namelist())
    if missing:
        raise SystemExit(f'Rust AAR is missing required entries: {sorted(missing)}')
    if any(archive.getinfo(name).file_size == 0 for name in required):
        raise SystemExit('Rust AAR contains an empty required entry')
PY

mkdir -p "$GITHUB_WORKSPACE/build-logs"
{
  printf 'Rust core commit: %s\nRust toolchain: %s\n' "$core_commit" "$rust_channel"
  sha256sum "$aar_path"
} | tee "$GITHUB_WORKSPACE/build-logs/rust-core-provenance.log"
printf 'AEROBOX_CORE_AAR=%s\n' "$aar_path" >> "$GITHUB_ENV"
