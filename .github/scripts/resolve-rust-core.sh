#!/usr/bin/env bash
set -euo pipefail

# No default repository exists yet. Both values must identify the reviewed core
# paired with this Kotlin bridge; never silently use another branch or core.
if [[ ! "${AEROBOX_CORE_REPOSITORY:-}" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
  echo "::error::Set AEROBOX_CORE_REPOSITORY to the Rust core's owner/repository (workflow input or repository variable)." >&2
  exit 2
fi
if [[ ! "${AEROBOX_CORE_REF:-}" =~ ^[0-9a-fA-F]{40}$ ]]; then
  echo "::error::Set AEROBOX_CORE_REF to the reviewed Rust core's full 40-character commit SHA (workflow input or repository variable)." >&2
  exit 2
fi
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"
printf 'repository=%s\nref=%s\n' "$AEROBOX_CORE_REPOSITORY" "${AEROBOX_CORE_REF,,}" >> "$GITHUB_OUTPUT"
