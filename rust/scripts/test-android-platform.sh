#!/usr/bin/env bash
set -euo pipefail
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$project_dir/target}"
cargo test --locked --manifest-path "$project_dir/crates/aerobox-android/Cargo.toml" \
  --lib --test lifecycle --test platform_dns
