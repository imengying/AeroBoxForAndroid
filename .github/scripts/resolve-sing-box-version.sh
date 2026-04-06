#!/usr/bin/env bash
set -euo pipefail

SING_BOX_VERSION="$(
  curl -fsSL "https://api.github.com/repos/SagerNet/sing-box/releases/latest" \
    | grep '"tag_name":' \
    | sed -E 's/.*"([^"]+)".*/\1/'
)"

if [ -z "${SING_BOX_VERSION}" ]; then
  echo "::error::Failed to resolve latest sing-box version"
  exit 1
fi

echo "SING_BOX_VERSION=${SING_BOX_VERSION}" >> "${GITHUB_ENV}"
echo "Resolved sing-box version: ${SING_BOX_VERSION}"
