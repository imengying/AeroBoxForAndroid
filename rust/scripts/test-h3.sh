#!/usr/bin/env bash
# Exercise the vendored H3 state machine with the production Rust crypto stack.
set -euo pipefail
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$project_dir/vendor/shoes/target}"
cargo test --locked --manifest-path "$project_dir/vendor/h3/h3/Cargo.toml" \
  --lib -- --test-threads=1 "$@"
