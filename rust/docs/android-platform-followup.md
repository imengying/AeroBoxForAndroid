# Actual App migration and remaining platform contracts

The App migration is applied, without commits, in the isolated worktree
`/home/Code/AeroBoxForAndroid-rust`, branch `codex/rust-core-migration`, based on
7206146effd0ac3602eb5b96ad5986e5af5ced5e. There is no applicable AGENTS.md.
The original `/home/Code/AeroBoxForAndroid` worktree and its user's README.md
change (+16 lines) remain untouched. The migration changes eight App files.

The AAR API already covers start/check/stop/reload, TUN borrowed FD ownership,
network cancellation, protected and explicitly bound physical sockets, total
traffic counters, connection snapshots/close, log drain and concurrent per-node
URL tests. The patch preserves the SingBoxNative facade, so Application,
Settings, DataTransfer, VpnConfigResolver, SubscriptionRepository and the existing
VpnRepository call site need no mechanical renaming. The service changes the
returned platform type, replaces CommandServer with RustVpnSession, retains
operation/revision/state IDs and independent stop during synchronous JNI,
retains the traffic health/reconnect worker, and adds log draining. Its old TUN
controller, gomobile platform wrapper and resolver transport are removed in the
isolated worktree. The Gradle AAR path is overridable with
`-PAEROBOX_CORE_AAR=<path>`.

The following platform changes and device checks remain part of migration
acceptance. CI/Release workflows
still build libbox and also need an explicitly versioned Rust core checkout or
artifact source.

## System DNS: retain Android Private DNS and network-scoped policy

The original LocalResolverTransport.kt:27-73 uses
Android DnsResolver.rawQuery/query on DefaultNetworkMonitor.defaultNetwork,
FLAG_NO_RETRY, cancellation via CancellationSignal. Before this follow-up,
Platform exposed only dns_servers() and refresh_dns built controlled_bootstrap
from physical IP endpoints. Those direct UDP/TCP queries bypass Android's
platform resolver, including Private DNS. This affects even ordinary defaults: DnsConfigBuilder
always creates a `type:local` bootstrap server for named DoH/DoT/DoQ endpoints.
Do not silently fall back to raw physical port 53 after an Android resolver
failure or Private DNS validation failure.

The Rust platform/JNI integration is under validation. The Kotlin transport,
capability callback, exact network-epoch lookup and cancellation callbacks have
been implemented in this repository. Their public contract is:

```rust
#[derive(Clone, Copy, Debug)]
pub struct PlatformNetwork { pub generation: u64, pub handle: u64 }
pub struct PlatformDnsQuery {
    pub network: PlatformNetwork,
    pub message: Vec<u8>,
    pub deadline: tokio::time::Instant,
}
pub trait Platform {
    fn supports_system_dns(&self) -> bool { false }
    fn exchange_system_dns(self: Arc<Self>, query: PlatformDnsQuery)
        -> futures::future::BoxFuture<'static, io::Result<Vec<u8>>>;
    // Default returns Unsupported; existing non-Android clients preserve their
    // explicitly selected controlled resolver. Android opts in and fails closed.
}
```

The Android implementation uses callback-based completion rather than retaining
blocking JVM threads per query:

```kotlin
interface PlatformCallbacks {
    fun supportsSystemDns(): Boolean = false
    fun startDnsQuery(id: Long, generation: Long, networkHandle: Long, message: ByteArray)
    fun cancelDnsQuery(id: Long)
}
// A separate one-way completion entry; it only removes an in-flight token and
// sends its oneshot result. It must never acquire Host/start/stop locks.
@JvmStatic private external fun nativeDnsQueryComplete(
    id: Long, answer: ByteArray?, rcode: Int, errno: Int, message: String?
)
```

Contract and integration:

1. Rust validates 12..65535-byte DNS requests, creates a globally unique monotonic
   checked u64 ID, inserts a oneshot plus network/context epoch before calling
   Java, and limits concurrent queries (e.g. 64, or shared configured budget).
   Java Long preserves the u64 bit pattern. Completion may occur synchronously
   during startDnsQuery, so registration must precede dispatch; no Host lock is
   held across dispatch. Returning an error also removes the registration.
2. PhysicalNetworkRegistry exposes a checked `networkFor(generation, handle)`
   that uses exactly the inventory's physical/epoch validation. DNS does not
   bind a socket or change the default; the chosen Network is passed directly
   to DnsResolver.rawQuery with FLAG_NO_RETRY and an IO executor.
3. Kotlin maintains id -> CancellationSignal in a concurrent map. onAnswer /
   onError / cancel each claim the entry once. Cancel must always complete the
   Rust waiter even when Android omits its callback. A late/duplicate result is
   ignored after removal. Request IDs are never reused across start/stop.
4. Rust future owns a cancellation guard. Drop, deadline, network retirement or
   service stop removes the token and invokes cancelDnsQuery. JNI completion is
   the only documented exception to the normal no-reentrant-core callback rule;
   it cannot call any other core API. No Tokio runtime lock is held during Java.
5. `PlatformResolver` implements both lookup (A/AAAA strategy) and raw exchange
   using this same method, existing DNS validation, cache TTL/deadline semantics
   and generation retirement. Raw response keeps the actual DNS RCODE packet;
   Java transport errors/errno remain errors, never an invented NXDOMAIN.
   Reply ID, question, QR and payload bounds are validated before caching.
6. PlatformContext installs that resolver as both BOOTSTRAP and default system
   resolver for Android. Existing domain_resolver wrappers forward raw exchange,
   deadlines and retirement. Explicit DoH/DoT/DoQ/UDP servers retain their
   configured paths and socket protection. A changing physical epoch rejects
   in-flight stale results and clears resolver pools; it never silently retries
   via a network other than the requested one.
7. With platform DNS available, startup must not require a nonempty port-53
   endpoint list merely to permit the platform resolver; Private DNS networks
   may have no usable plain DNS. Preserve endpoint checks only where a raw
   physical resolver is explicitly selected. Do not let the lack of DNS delay
   bindable physical-network snapshots or explicit direct IP dialing.

The standalone Kotlin boundary suite (`scripts/test-kotlin-platform-dns.sh`)
passes seven groups covering synchronous completion, duplicate callbacks,
cancellation without an Android callback, epoch/close invalidation, the 64-query
limit, duplicate IDs, malformed messages, submission errors, stale responses,
unsigned IDs represented by Java Long, partial-submission cleanup, and delayed
invalidation notifications racing new-epoch requests. The bridge compiles against the
App's SDK 37.2; the existing five lifecycle worker tests also pass.

Native integration now covers deadline/drop, packet identity,
RCODE validation, retired cache access, and named resolver ECH/URLTest use of
platform DNS. Device checks remain: strict and automatic Private DNS, network
switch during query, IPv4/IPv6, DoH bootstrap and DNS hijack prevention.

## UID / package names: retrieve original TUN tuple, without protocol guessing

Original PlatformInterfaceWrapper.kt:28-58 calls getConnectionOwnerUid for TCP
or UDP, then PackageManager.getPackagesForUid. Failure becomes INVALID_UID / an
empty owner. Kotlin now implements the same lookup behind
`VpnPlatformCallbacks.connectionOwner`; standalone `PhysicalNetworkCallbacks`
keeps the default unknown result. Rust flow attribution is being integrated.
Default RouteConfigBuilder emits neither uid nor package matching; unsupported
owner-based rules must still be rejected.

```rust
pub struct ConnectionOwnerQuery {
    pub ip_protocol: u8, // exactly 6 (TCP) or 17 (UDP)
    pub source: std::net::SocketAddr,
    pub destination: std::net::SocketAddr,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ConnectionOwner {
    pub uid: u32,
    pub packages: Vec<String>, // sorted/deduped, nonempty entries, <=64
}
fn Platform::connection_owner(&self, query: ConnectionOwnerQuery)
    -> io::Result<Option<ConnectionOwner>> { Ok(None) }
```

Kotlin callback `connectionOwner(ipProtocol: Int, source: String, sourcePort: Int,
destination: String, destinationPort: Int): String` returns JSON null or
`{"uid":12345,"packages":["package.name"]}`. Parse literal addresses with
InetAddresses.parseNumericAddress, never getByName. Platform errors/INVALID_UID
mean unknown for diagnostics and do not crash an active connection. No package
name is treated as executable path. Keep all shared-UID package names instead
of inventing one exclusive owner; `process` can display the stable first package
and new uid/packages metadata preserves complete attribution.

Kotlin accepts only TCP/UDP, ports 1..65535 and same-family numeric IPv4/IPv6
addresses without a scope suffix. Package results are sorted and deduplicated,
limited to 64 distinct entries of at most 255 ASCII characters; each dot-separated
segment begins with a letter or underscore, followed by letters, digits,
underscores or dollar signs. Blank entries are omitted. Oversized or malformed
results return unknown rather than an incomplete shared-UID list. Android
permission/Binder exceptions also return unknown. Android documents that this
query requires the active VPN's visibility of the connection. See
[getConnectionOwnerUid](https://developer.android.com/reference/android/net/ConnectivityManager#getConnectionOwnerUid(int,%20java.net.InetSocketAddress,%20java.net.InetSocketAddress)).

Resolve ownership once for each TUN TCP connection / UDP association using the
original source/destination tuple BEFORE FakeIP restoration, sniffing, DNS or
outbound substitution. Using the resolved proxy/destination socket attributes
the Rust service, not the originating App. Bound Binder lookups on a blocking
worker semaphore and timeout; do not block Tokio network workers. Use flow ID
and generation to reject late results; avoid indefinite tuple caches because
ports are reused. Connections originate outside TUN (SOCKS/HTTP or probes) must
remain unknown unless their own inlet provides a reliable local socket tuple.

`scripts/test-kotlin-connection-owner.sh` passes six groups covering original
IPv4/TCP and IPv6/UDP tuples, unchanged FakeIP destinations, invalid arguments
rejected before Android calls, INVALID_UID, shared UID, package bounds,
permission/Binder exceptions and concurrent lookup isolation. The complete
bridge also compiles against SDK 37.2. Native checks still cover malformed JSON,
lookup cancellation at stop and reused source ports after a generation change.
Device checks remain with
two apps, shared UID where available, package uninstallation, and per-app VPN
include/exclude lists. The latter remains Android VpnService.Builder behavior
and is not replaced by owner lookup.

## Migration test commands and remaining semantics

The migration does not modify ConfigGenerator or relax converter validation. Check
reports `deferredRemoteRules`; those are fetched/decoded at start. TUN FD is
owned only by RustVpnSession + its native dup; no old controller runs alongside.
Session start/reload rebuilds TUN and resets totals; arbitrary outbound tag
stats are explicitly unsupported, while the current proxy+direct UI is mapped
to totals. Connections tracking stays bounded and always active; the old page
close tracking toggle no longer excludes existing flows.

The isolated App has passed `compileDebugKotlin` and all 138 JVM tests across
30 suites. `compileDebugKotlin` plus `assembleDebug` also passed using the formal
TUIC/network AAR, producing four ABI debug APKs. These APKs, the exact AAR hash,
App base revision, APK hashes and verification scope are preserved in
`target/android/app-baseline/tuic-network/`. This baseline predates system DNS
integration; rebuild it after the new native and Kotlin DNS paths are validated.

Gradle was run offline with one worker, Kotlin in-process, and a 768 MiB heap.
Release/R8 and real-device lifecycle/routing checks remain. No APK was installed
on a device and no App changes were committed or published.

## Native platform implementation validation (2026-11-20)

Rust now installs the platform system resolver without consulting dns_servers(),
including when the physical port-53 list is empty. Its cached lookups and raw
exchanges check the network epoch at first poll and after completion. Seven DNS
unit tests cover matching/length/QR/opcode/truncation, RCODE preservation, cached
and delayed futures across epochs, cancellation, deadlines, and the 64-query cap.
The JNI query dispatcher has six host tests for synchronous/duplicate completion,
drop/late results, submission failure, bounded capacity and malformed data.
An actual EmbeddedCore + StandaloneProbes integration test verifies named DNS
bootstrap, explicit upstream preservation, URLTest, cache invalidation, network
change and stop while DNS is pending. Android host lifecycle remains 10/10.

UID/package lookup starts at the TUN ingress, before asynchronous DNS/sniffing
and outbound handshakes; a movable RAII owner follows preparation into FlowEntry.
Routing failure, flow close, host retirement or network cancellation drops the
lookup. No tuple cache or new query is created at flow registration. At most four
blocking platform calls run process-wide, with 50 ms result deadlines; a timed-out
Binder call retains its capacity permit until it actually exits. Diagnostics
never delay forwarding. Metadata includes uid and all packages; process is the
stable first package, while processPath stays empty. Four Rust owner tests plus
an isolated real TCP/UDP ingress test cover original IPv4/IPv6 FakeIP tuples,
shared UID, JSON limits, cancellation/late replies and non-TUN attribution.

The 12 native focused tests and the final Android JNI cross-check pass. The
platform baseline passed 2849 kernel tests (34 external tests ignored by default)
and all 14 selected Go interoperability tests. Its four-ABI dev AAR was packaged
into four debug and four unsigned Release APKs; 138 JVM tests, R8, resource
shrinking and lintVital passed. Evidence and hashes are in
`target/android/app-platform/manifest.json`; AAR SHA256 is
`27776085b5da2a3a1f243193851ddc5dfbf7fff14ac0351c8af46cdd641ec441`.
Native optimized release, device Private DNS and UID checks remain outstanding.
This baseline predates the later legacy TLS, Naive window and TCP Brutal changes. Android resolver API reference:
https://developer.android.com/reference/android/net/DnsResolver

## Superseding legacy TLS/Naive/Brutal build (2026-11-21)

The current four-ABI dev AAR and eight APKs are archived in
`target/android/app-legacy-brutal/manifest.json`. AAR SHA256 is
`456af2a96ed6ba9800c286a198f61cf14412b792df5af7648a1be1a3839bc69b`.
The merged snapshot passes 2860 kernel tests, 16 independent protocol tests,
42 crypto tests and three independent Go crypto matrices. All 138 JVM tests
executed again and passed; Debug and unsigned Release builds passed, including
R8/resource shrinking and lintVital. Every APK's native library matches the
sealed AAR after NDK stripping; all Release DEX files preserve the 14 JNI
methods and eight platform callbacks. Debug signatures pass verification;
Release APKs contain no signing block. No device was attached.

The replaced platform APKs and AAR were removed after verifying their hashes;
their manifest and test evidence remain, with `app-platform/superseded.json`
identifying the replacement. Native optimization and actual Android VPN,
Private DNS, UID and network transition validation remain outstanding.
