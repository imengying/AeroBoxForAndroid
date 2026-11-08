#!/usr/bin/env bash
set -euo pipefail

AEROBOX_SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SING_BOX_VERSION="$(cat "${AEROBOX_SCRIPT_DIR}/../sing-box-version")"
if [[ ! "${SING_BOX_VERSION}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "::error::Invalid pinned sing-box version" >&2
  exit 1
fi

if [[ -n "${GITHUB_ENV:-}" ]]; then
  echo "SING_BOX_VERSION=${SING_BOX_VERSION}" >> "${GITHUB_ENV}"
fi
export SING_BOX_VERSION
echo "Pinned sing-box version: ${SING_BOX_VERSION}"
