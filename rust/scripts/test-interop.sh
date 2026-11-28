#!/usr/bin/env bash
# Reference peers are isolated test tools. The product contains only Rust.
set -euo pipefail
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
peer_dir="$project_dir/target/interop"
mkdir -p "$peer_dir"
for protocol in naive mux vmess obfs ech tuic; do
  (
    cd "$project_dir/vendor/shoes/tests/fixtures/$protocol-peer"
    if [[ "$protocol" == mux ]]; then
      CGO_ENABLED=0 go build -tags debug -mod=readonly -trimpath -o "$peer_dir/$protocol-peer" .
    else
      CGO_ENABLED=0 go build -mod=readonly -trimpath -o "$peer_dir/$protocol-peer" .
    fi
  )
done
CGO_ENABLED=0 go build -trimpath -o "$peer_dir/tls-fragment-peer" "$project_dir/vendor/shoes/tests/fixtures/tls-fragment-peer/main.go"
CGO_ENABLED=0 go build -trimpath -o "$peer_dir/cbc-peer" "$project_dir/crates/aerobox-crypto/tests/fixtures/cbc-peer/main.go"
export AEROBOX_CBC_PEER="$peer_dir/cbc-peer"
cargo test --locked --manifest-path "$project_dir/crates/aerobox-crypto/Cargo.toml" --test cbc_interop -- --ignored --test-threads=1
export AEROBOX_NAIVE_PEER="$peer_dir/naive-peer"
export AEROBOX_MUX_PEER="$peer_dir/mux-peer"
export AEROBOX_VMESS_PEER="$peer_dir/vmess-peer"
export AEROBOX_OBFS_PEER="$peer_dir/obfs-peer"
export AEROBOX_ECH_PEER="$peer_dir/ech-peer"
export AEROBOX_TUIC_PEER="$peer_dir/tuic-peer"
export AEROBOX_TLS_FRAGMENT_PEER="$peer_dir/tls-fragment-peer"
cargo test --locked --manifest-path "$project_dir/vendor/shoes/Cargo.toml" --lib -- \
  --ignored --test-threads=1 naive_http2_and_http3_with_independent_go_peer naive_http3_advertises_independent_windows_to_go_peer \
  all_mux_protocols_exchange_tcp_and_udp_with_go_sing_mux h2mux::brutal::interop_tests \
  vmess::interop_tests ss_plugin:: ech::tests::interop quic_client::tuic_uot_tests quic_client::early_tests \
  tcp::socket_connector_impl::early_tests \
  tls_fragment::tests::tls12_and_tls13_fragments_interoperate_with_independent_go_server
