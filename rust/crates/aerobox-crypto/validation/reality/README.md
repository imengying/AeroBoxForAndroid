# Production REALITY authentication validation

Compiles the kernel's actual authentication, certificate verification, ML-DSA,
and RustCrypto key-exchange modules. A minimal configuration/time bridge avoids
rebuilding the whole kernel while testing these modules independently.

```sh
AEROBOX_TLS_PROFILE_PEER="$PWD/target/reference-peers/tls-profile" \
  CARGO_TARGET_DIR="$PWD/crates/aerobox-crypto/target" \
  python3 scripts/run-bounded-build.py -- cargo test --offline --locked \
  --manifest-path crates/aerobox-crypto/validation/reality/Cargo.toml --test interop -- --test-threads=1
```

The Go reference at `tests/reference/tls-profile-peer` independently authenticates
metadata and checks the browser wrapper's standalone X25519 shape. Tests also
exercise generic independent hybrid/X25519 shares and reject invalid HMAC,
signatures, short IDs, Finished, and retries. It is never a product dependency.
