# Connection owner boundary

Run `bash scripts/test-kotlin-connection-owner.sh`. It compiles production
`ConnectionOwners.kt` with minimal Android API doubles. The tests verify exact
original IPv4/TCP and IPv6/UDP tuples (including a FakeIP destination), shared
UID package lists, input validation before Android calls, permission/Binder
failures, package result limits, and concurrent lookup isolation. The numeric
address double constructs addresses from bytes and cannot perform DNS.

These tests do not claim that Android returned a real device UID. Device checks
remain necessary for active VPN permissions, shared UIDs, package visibility,
app uninstall, and tuple reuse. Native cancellation/timeout and flow attribution
are covered separately in Rust.
