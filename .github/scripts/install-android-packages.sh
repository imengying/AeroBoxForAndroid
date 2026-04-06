#!/usr/bin/env bash
set -euo pipefail

: "${ANDROID_SDK_ROOT:?ANDROID_SDK_ROOT is required}"
: "${ANDROID_NDK_VERSION:?ANDROID_NDK_VERSION is required}"

SDKMANAGER="${ANDROID_SDK_ROOT}/cmdline-tools/latest/bin/sdkmanager"
if [ ! -x "${SDKMANAGER}" ]; then
  echo "::error::sdkmanager not found at ${SDKMANAGER}"
  exit 1
fi

(
  set +o pipefail
  yes | "${SDKMANAGER}" --licenses >/dev/null
)
"${SDKMANAGER}" "platforms;android-36" "build-tools;36.0.0" "ndk;${ANDROID_NDK_VERSION}"
echo "ANDROID_NDK_HOME=${ANDROID_SDK_ROOT}/ndk/${ANDROID_NDK_VERSION}" >> "${GITHUB_ENV}"
