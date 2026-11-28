#!/usr/bin/env bash
# Run the vendored transport's own regression suite with Rust crypto only.
set -euo pipefail
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$project_dir/vendor/shoes/target}"
cargo test --offline --locked --manifest-path "$project_dir/vendor/quinn-proto/Cargo.toml" \
  --no-default-features --features rustls-rustcrypto,log,bloom \
  --config "patch.crates-io.rustls.path=\"$project_dir/vendor/rustls/rustls\"" \
  --config "patch.crates-io.rcgen.path=\"$project_dir/vendor/rcgen\"" \
  --config 'profile.dev.debug=1' --config 'profile.dev.incremental=false' \
  --lib -- --test-threads=1 "$@"
