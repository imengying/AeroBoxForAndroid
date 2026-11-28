These JVM tests compile production `RustVpnSession.kt`, `VpnPlatformCallbacks.kt`
and `PhysicalNetwork.kt` with small substitutes for Android, the candidate-network
registry and JNI. Run `scripts/test-kotlin-lifecycle.sh`.
The script uses the Kotlin compiler distribution bundled with Gradle;
`AEROBOX_KOTLIN_LIB` overrides its location. It does not load the native library,
create a VPN, require an Android device, or invoke Cargo.

The checks cover serial refresh and event coalescing, changes during startup,
stopping an active worker and restarting, a failure callback that closes its own
session, and a start racing the first cancellation request. Latches establish
the relevant ordering; bounded waits fail if a worker becomes stuck.

Network checks feed real production state with available/capability/link/lost
events, including a new best without loss of the previous best and stale events
for that previous network. They verify complete link snapshots, reject VPN and
incomplete observations, and check that loss blocks new default bindings even
while a previous refresh is busy. The substituted ConnectivityManager getters
throw: production platform publication, default protect and DNS must use the
event snapshot without querying it. Service underlying-network updates must run
on the serialized worker after startup, and no update runs before TUN startup.

These substitutes validate production state/publication and session concurrency.
The Android parcel substitute models whole-object copying, rather than testing
the OS implementation. Android callback delivery and coroutine wait/cancellation,
`Network.bindSocket`, `VpnService.protect`, real JNI and TUN traffic
still require the native integration tests and device testing.
