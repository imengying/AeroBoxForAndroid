#!/usr/bin/env bash
set -euo pipefail

SDK_ROOT="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-/usr/local/lib/android/sdk}}"
SDKMANAGER_BIN="${SDK_ROOT}/cmdline-tools/latest/bin/sdkmanager"

if [ ! -x "${SDKMANAGER_BIN}" ]; then
  SDK_ROOT="${HOME}/.android/sdk"
  SDKMANAGER_BIN="${SDK_ROOT}/cmdline-tools/latest/bin/sdkmanager"
fi

if [ ! -x "${SDKMANAGER_BIN}" ]; then
  TMP_DIR="$(mktemp -d)"
  mkdir -p "${SDK_ROOT}/cmdline-tools"
  curl -fLSs \
    "https://dl.google.com/android/repository/commandlinetools-linux-15641748_latest.zip" \
    -o "${TMP_DIR}/commandlinetools.zip"
  unzip -q "${TMP_DIR}/commandlinetools.zip" -d "${TMP_DIR}"
  rm -rf "${SDK_ROOT}/cmdline-tools/latest"
  mkdir -p "${SDK_ROOT}/cmdline-tools/latest"
  mv "${TMP_DIR}/cmdline-tools/"* "${SDK_ROOT}/cmdline-tools/latest/"
fi

echo "ANDROID_SDK_ROOT=${SDK_ROOT}" >> "${GITHUB_ENV}"
echo "ANDROID_HOME=${SDK_ROOT}" >> "${GITHUB_ENV}"
echo "${SDK_ROOT}/cmdline-tools/latest/bin" >> "${GITHUB_PATH}"
echo "${SDK_ROOT}/platform-tools" >> "${GITHUB_PATH}"

export ANDROID_SDK_ROOT="${SDK_ROOT}"
export ANDROID_HOME="${SDK_ROOT}"
export PATH="${SDK_ROOT}/cmdline-tools/latest/bin:${SDK_ROOT}/platform-tools:${PATH}"

"${SDKMANAGER_BIN}" --version
