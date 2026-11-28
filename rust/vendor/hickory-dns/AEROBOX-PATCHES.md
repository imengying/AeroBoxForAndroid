# AeroBox RustCrypto support

The `hickory-net` and `hickory-resolver` packages add `tls-rustcrypto`,
`https-rustcrypto`, `quic-rustcrypto` and `h3-rustcrypto` features.
They select `aerobox-crypto` explicitly for rustls and the corresponding
`rustls-rustcrypto` feature on the local Quinn fork. Disable default/native
provider features in the final application's dependency graph.

This patch adds transport crypto selection. It does not add a RustCrypto
DNSSEC backend or change DNS message processing. Existing ring/AWS-LC
features remain available for other users of this local fork.

Validation and dependency-tree inspection use the independent project at
`crates/aerobox-crypto/validation/transport` in the repository root.
