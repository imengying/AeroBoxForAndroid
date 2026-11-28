#!/usr/bin/env bash
# Compile a small Android entry point against the actual app, then run its JNI validator.
set -euo pipefail
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
apk="${1:?usage: check-apk-config.sh APK [ADB_SERIAL]}"
apk="$(realpath "$apk")"
serial="${2:-emulator-5554}"
sdk="${ANDROID_SDK_ROOT:-/opt/android-sdk}"
gradle_lib="${AEROBOX_KOTLIN_LIB:-/opt/gradle-9.8.2/lib}"
android_jar="$sdk/platforms/android-37.2/android.jar"
classes="$project_dir/app/build/intermediates/compile_app_classes_jar/debug/bundleDebugClassesToCompileJar/classes.jar"
output="$project_dir/build/config-contract"
mkdir -p "$output/dex"
stdlib=("$gradle_lib"/kotlin-stdlib-*.jar)
java -Xmx256m -cp "$gradle_lib/*" org.jetbrains.kotlin.cli.jvm.K2JVMCompiler \
  -no-stdlib -no-reflect -jvm-target 17 -classpath "$classes:$android_jar:${stdlib[0]}" \
  -d "$output/probe.jar" "$project_dir/rust/android/tests/config-contract/ConfigContract.kt"
"$sdk/build-tools/37.0.0/d8" --lib "$android_jar" --classpath "$classes" \
  --classpath "${stdlib[0]}" --min-api 31 --output "$output/dex" "$output/probe.jar"
adb=("$sdk/platform-tools/adb" -s "$serial")
abi="$("${adb[@]}" shell getprop ro.product.cpu.abi | tr -d '\r')"
python3 - "$apk" "$output/libaerobox.so" "$abi" <<'PY'
from pathlib import Path
import sys, zipfile, lzma
with zipfile.ZipFile(sys.argv[1]) as archive:
    Path(sys.argv[2]).write_bytes(archive.read(f'lib/{sys.argv[3]}/libaerobox.so'))
    rules = Path(sys.argv[2]).parent / 'rules'
    rules.mkdir(exist_ok=True)
    for name in ('geoip-cn', 'geosite-cn', 'geosite-category-ads-all'):
        (rules / f'{name}.srs').write_bytes(lzma.decompress(archive.read(f'assets/rules/{name}.srs.xz')))
PY
device_dir=/data/local/tmp/aerobox-config-contract
"${adb[@]}" shell mkdir -p "$device_dir/storage"
"${adb[@]}" push "$output/rules" "$device_dir/storage/" >/dev/null
"${adb[@]}" push "$output/dex/classes.dex" "$device_dir/probe.dex" >/dev/null
"${adb[@]}" push "$output/libaerobox.so" "$device_dir/libaerobox.so" >/dev/null
"${adb[@]}" push "$apk" "$device_dir/app.apk" >/dev/null
"${adb[@]}" shell "CLASSPATH=$device_dir/probe.dex:$device_dir/app.apk LD_LIBRARY_PATH=$device_dir app_process /system/bin com.aerobox.validation.ConfigContractKt $device_dir/storage"
"${adb[@]}" shell rm -rf "$device_dir"
