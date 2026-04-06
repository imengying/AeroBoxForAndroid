#!/usr/bin/env bash
set -euo pipefail

: "${GITHUB_WORKSPACE:?GITHUB_WORKSPACE is required}"

ASSET_DIR="${GITHUB_WORKSPACE}/app/src/main/assets/sing-box"
rm -rf "${ASSET_DIR}"
mkdir -p "${ASSET_DIR}"

get_latest_release() {
  curl -fsSL "https://api.github.com/repos/$1/releases/latest" \
    | grep '"tag_name":' \
    | sed -E 's/.*"([^"]+)".*/\1/'
}

GEOIP_TAG="$(get_latest_release "SagerNet/sing-geoip")"
GEOSITE_TAG="$(get_latest_release "SagerNet/sing-geosite")"
if [ -z "${GEOIP_TAG}" ] || [ -z "${GEOSITE_TAG}" ]; then
  echo "::error::Failed to resolve geo asset versions"
  exit 1
fi

echo -n "${GEOIP_TAG}" > "${ASSET_DIR}/geoip.version.txt"
echo -n "${GEOSITE_TAG}" > "${ASSET_DIR}/geosite.version.txt"

curl -fLSs "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs" \
  -o "${ASSET_DIR}/geoip-cn.srs"
curl -fLSs "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs" \
  -o "${ASSET_DIR}/geosite-cn.srs"
curl -fLSs "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs" \
  -o "${ASSET_DIR}/geosite-category-ads-all.srs"

xz -z -9 -f "${ASSET_DIR}/geoip-cn.srs"
xz -z -9 -f "${ASSET_DIR}/geosite-cn.srs"
xz -z -9 -f "${ASSET_DIR}/geosite-category-ads-all.srs"

echo "Bundled routing assets:"
ls -lh "${ASSET_DIR}"
