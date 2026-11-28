#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
ndk_dir="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-/opt/android-sdk/ndk/30.0.16248370}}"
ndk_tools="$ndk_dir/toolchains/llvm/prebuilt/linux-x86_64/bin"
api_level="${ANDROID_API_LEVEL:-31}"
profile="${AEROBOX_BUILD_PROFILE:-release}"
if (( $# > 1 )); then
  for current_abi in "$@"; do bash "$project_dir/android/build.sh" "$current_abi"; done
  exit 0
fi
abi="${1:-all}"
if [[ "$abi" == all ]]; then
  for current_abi in arm64-v8a armeabi-v7a x86_64 x86; do
    bash "$project_dir/android/build.sh" "$current_abi"
  done
  exit 0
fi
case "$abi" in
  arm64-v8a) target=aarch64-linux-android; clang_target=aarch64-linux-android ;;
  armeabi-v7a) target=armv7-linux-androideabi; clang_target=armv7a-linux-androideabi ;;
  x86_64) target=x86_64-linux-android; clang_target=x86_64-linux-android ;;
  x86) target=i686-linux-android; clang_target=i686-linux-android ;;
  *) printf 'Unknown Android ABI: %s\n' "$abi" >&2; exit 2 ;;
esac
linker="$ndk_tools/$clang_target$api_level-clang"
if [[ ! -x "$linker" ]]; then
  printf 'Android NDK linker missing: %s\nSet ANDROID_NDK_HOME to an installed NDK.\n' "$linker" >&2
  exit 2
fi
target_dir="${AEROBOX_TARGET_DIR:-$project_dir/target/android-cargo}"
jni_dir="${AEROBOX_JNI_DIR:-$project_dir/../app/build/generated/rust/jniLibs}"
linker_key="CARGO_TARGET_${target^^}_LINKER"
linker_key="${linker_key//-/_}"
env "$linker_key=$linker" CARGO_TARGET_DIR="$target_dir" \
  cargo build --locked --manifest-path "$project_dir/crates/aerobox-android/Cargo.toml" \
  --lib --target "$target" --profile "$profile"
output_profile="$profile"
if [[ "$profile" == dev ]]; then output_profile=debug; fi
mkdir -p "$jni_dir/$abi"
cp -- "$target_dir/$target/$output_profile/libaerobox.so" \
  "$jni_dir/$abi/libaerobox.so"
# Keep debug metadata in Cargo's artifact; package a compact loadable library.
if [[ "${AEROBOX_STRIP:-1}" == 1 ]]; then
  "$ndk_tools/llvm-strip" --strip-debug "$jni_dir/$abi/libaerobox.so"
fi
python3 "$project_dir/scripts/verify-pure-rust.py" --target "$target" \
  --library "$jni_dir/$abi/libaerobox.so"
printf 'Built %s\n' "$jni_dir/$abi/libaerobox.so"
