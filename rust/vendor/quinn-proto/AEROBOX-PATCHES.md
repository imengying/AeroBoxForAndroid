# AeroBox RustCrypto support

This local fork adds `rustcrypto` and `rustls-rustcrypto` features to
quinn-proto and quinn. Callers must disable default features when selecting
this backend; upstream defaults and optional native backends are preserved.
When multiple provider features are enabled, the RustCrypto feature selects
the provider, but it cannot remove other Cargo dependencies enabled elsewhere.

`aerobox-crypto` implements TLS/QUIC through rustls. `aerobox-primitives`
supplies Retry AES-GCM, handshake-token HKDF/AEAD and stateless-reset HMAC.
The default endpoint/server constructors are enabled for this backend.

Independent validation that avoids upstream native crypto development
dependencies is in `crates/aerobox-crypto/validation/transport` at the
repository root. The provider's experimental status and limitations are
documented in `crates/aerobox-crypto/README.md`.

## Application-negotiated congestion control

`Controller::pacing_rate_bytes` and `on_packets_lost` provide optional hooks for
Hysteria Brutal. Existing controllers keep their original pacing behavior.
The fixed-rate pacer accounts for fractional bytes and uses the negotiated rate
without the default congestion-window gain. `set_congestion_controller` retains
RTT/MTU and updates only the connection's cloned transport config, so future path
resets use the selected controller without altering other connections.

Matching `quinn::Connection::set_congestion_controller` wakes the connection
driver after an application-level authentication response. These are local APIs;
they are not upstream Quinn APIs. Pacing and bandwidth-negotiation regression
tests accompany the changes.
