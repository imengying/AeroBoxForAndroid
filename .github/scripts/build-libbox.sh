#!/usr/bin/env bash
set -euo pipefail

: "${GITHUB_WORKSPACE:?GITHUB_WORKSPACE is required}"
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"
: "${ANDROID_NDK_HOME:?ANDROID_NDK_HOME is required}"
: "${GOMOBILE_VERSION:?GOMOBILE_VERSION is required}"
: "${LIBBOX_BUILD_TAGS:?LIBBOX_BUILD_TAGS is required}"
: "${SING_BOX_VERSION:?SING_BOX_VERSION is required}"

# Install gomobile / gobind (same version as SFA official)
go install github.com/sagernet/gomobile/cmd/gomobile@"${GOMOBILE_VERSION}"
go install github.com/sagernet/gomobile/cmd/gobind@"${GOMOBILE_VERSION}"
export PATH="$(go env GOPATH)/bin:${PATH}"

# Clone sing-box source at the resolved stable tag
git clone --depth 1 --branch "${SING_BOX_VERSION}" \
  https://github.com/SagerNet/sing-box.git "${RUNNER_TEMP}/sing-box"
cd "${RUNNER_TEMP}/sing-box"

SING_VERSION="${SING_BOX_VERSION#v}"
echo "Building libbox ${SING_VERSION} with tags: ${LIBBOX_BUILD_TAGS}"
if [[ ",${LIBBOX_BUILD_TAGS}," == *",with_clash_api,"* ]]; then
  echo "::error::with_clash_api should not be present in LIBBOX_BUILD_TAGS after the runtime-log patch"
  exit 1
fi

# Current sing-box upstream treats `PlatformLogWriter != nil` as a reason to enable
# extra services automatically. AeroBox only uses PlatformLogWriter for runtime log
# callbacks, and does not depend on the Clash API gRPC surface or cache-file side
# effects. Keep these patches explicit and fail loudly if upstream refactors the
# target blocks.
python3 "${GITHUB_WORKSPACE}/.github/scripts/patch-sing-box-box-go.py"

echo "--- patched box.go PlatformLogWriter conditions ---"
grep -n "needCacheFile\\|needClashAPI" box.go
python3 - <<'PY'
from pathlib import Path

text = Path("box.go").read_text()
forbidden = [
    "\tif experimentalOptions.CacheFile != nil && experimentalOptions.CacheFile.Enabled || options.PlatformLogWriter != nil {\n",
    "\tif experimentalOptions.ClashAPI != nil || options.PlatformLogWriter != nil {\n",
]
for old in forbidden:
    if old in text:
        raise SystemExit(
            "PlatformLogWriter still affects needCacheFile/needClashAPI in patched box.go"
        )
print("--- remaining PlatformLogWriter references ---")
for line_no, line in enumerate(text.splitlines(), 1):
    if "PlatformLogWriter" in line:
        print(f"{line_no}:{line}")
PY

cp "${GITHUB_WORKSPACE}/.github/libbox/urltest_export.go" experimental/libbox/urltest_export.go
gofmt -w experimental/libbox/urltest_export.go
echo "--- added experimental/libbox/urltest_export.go ---"
sed -n '1,200p' experimental/libbox/urltest_export.go

# Build with gomobile bind directly (no need to patch build_libbox)
mkdir -p "${GITHUB_WORKSPACE}/app/build/libbox"
gomobile bind -v \
  -o "${GITHUB_WORKSPACE}/app/build/libbox/libbox.aar" \
  -target android \
  -androidapi 31 \
  -javapkg=io.nekohasekai \
  -libname=box \
  -trimpath \
  -buildvcs=false \
  -ldflags "-X github.com/sagernet/sing-box/constant.Version=${SING_VERSION} -s -w -buildid= -checklinkname=0" \
  -tags "${LIBBOX_BUILD_TAGS}" \
  ./experimental/libbox

AAR_PATH="${GITHUB_WORKSPACE}/app/build/libbox/libbox.aar"
echo "--- libbox.aar built ---"
ls -lh "${AAR_PATH}"

STRIP_DIR="${RUNNER_TEMP}/aar_strip"
mkdir -p "${STRIP_DIR}"
unzip -q "${AAR_PATH}" -d "${STRIP_DIR}"
LLVM_STRIP="${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip"
if [ -x "${LLVM_STRIP}" ]; then
  find "${STRIP_DIR}/jni" -name '*.so' -exec "${LLVM_STRIP}" --strip-unneeded {} \;
  echo "--- .so sizes after strip ---"
  find "${STRIP_DIR}/jni" -name '*.so' -exec du -h {} \; | sort -h
  pushd "${STRIP_DIR}"
  zip -q -r "${AAR_PATH}" .
  popd
fi
