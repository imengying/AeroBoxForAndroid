# TLS record_size_limit reference peer

Test-only extension of the pinned legacy renegotiation server. Apply the complete fixture patch to fixed metacubex uTLS v1.8.7; production never links this Go module. `build.py --prepare-only` checks all original and patched hashes without compilation; use the repository shared build lock for `build.py --test`.

`--record-first` defaults to -2 (all new behavior disabled); -1 omits the first reply, or 0..65535 sends that exact initial limit. `--record-second` controls the renegotiated reply (-1 omits it). `--record-advertised` requires the exact client advertisement, default 16385. Low/out-of-range limits intentionally exercise client rejection.

The server authenticates/decrypts each old-version record and checks plaintext size after MAC/padding removal. The receive limit changes only on inbound CCS. Terminal JSON reports record counts and maximum plaintext per key epoch. Existing RFC5746 binding, mTLS, Finished, exporter, certificate and ALPN checks remain active. The hooks do not relax any authentication check.
