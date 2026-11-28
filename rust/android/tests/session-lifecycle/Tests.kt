package com.aerobox.core.`native`
import android.net.*
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
private fun CountDownLatch.ready() { check(await(2, TimeUnit.SECONDS)) { "Timed out waiting for worker" } }
private fun eventually(predicate: () -> Boolean) {
    val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
    while (!predicate()) { check(System.nanoTime() < deadline) { "Worker did not settle" }; Thread.sleep(1) }
}
private fun physical(id: Int = 1): PhysicalNetwork {
    val state = PhysicalNetworkState()
    state.onAvailable(Network(id))
    state.onCapabilitiesChanged(Network(id), physicalCapabilities())
    state.onLinkPropertiesChanged(Network(id), physicalLinks())
    return checkNotNull(state.current)
}
private fun physicalCapabilities() = NetworkCapabilities()
    .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
    .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
private fun physicalLinks() = LinkProperties().apply {
    interfaceName = "wlan0"
    addDnsServer(java.net.InetAddress.getByName("192.0.2.53"))
    routes.add("0.0.0.0/0")
    privateDnsServerName = "dns.example"
}
private fun session(service: VpnService = VpnService(), onFailure: (Throwable) -> Unit = { throw AssertionError(it) }) =
    RustVpnSession(service, ConnectivityManager(), physical(), onFailure)
private fun burstChangesAreSerializedAndStopUnregisters() {
    RustCoreNative.reset()
    val session = session()
    session.startOrReloadService("{}")
    val entered = CountDownLatch(1)
    val release = CountDownLatch(1)
    RustCoreNative.onRefresh = {
        if (RustCoreNative.refreshes.get() == 1) { entered.countDown(); release.ready() }
    }
    PhysicalNetworkRegistry.latest.candidateChange()
    entered.ready()
    repeat(40) { if (it % 2 == 0) PhysicalNetworkRegistry.latest.candidateChange() else session.networkChanged(physical(2)) }
    release.countDown()
    eventually { RustCoreNative.refreshes.get() == 2 && RustCoreNative.inFlight.get() == 0 }
    check(RustCoreNative.maxInFlight.get() == 1)
    check(RustCoreNative.refreshThreads.all { it == "aerobox-network-refresh" })
    session.closeService()
    check(!PhysicalNetworkRegistry.latest.monitoring && PhysicalNetworkRegistry.latest.listener == null && !session.isRunning())
    PhysicalNetworkRegistry.latest.candidateChange()
    check(RustCoreNative.refreshes.get() == 2)
    session.startOrReloadService("{}")
    PhysicalNetworkRegistry.latest.candidateChange()
    eventually { RustCoreNative.refreshes.get() == 3 }
    session.close()
    check(PhysicalNetworkRegistry.latest.closed)
}
private fun startupChangesWaitForNativeAndCoalesce() {
    RustCoreNative.reset()
    val service = VpnService()
    val session = session(service)
    val entered = CountDownLatch(1)
    val release = CountDownLatch(1)
    val failure = AtomicReference<Throwable?>()
    RustCoreNative.onStart = { entered.countDown(); release.ready() }
    val starter = Thread {
        try { session.startOrReloadService("{}") } catch (e: Throwable) { failure.set(e) }
    }
    starter.start(); entered.ready()
    repeat(10) { PhysicalNetworkRegistry.latest.candidateChange(); session.networkChanged(physical(3)) }
    check(RustCoreNative.refreshes.get() == 0)
    check(service.networkUpdates.isEmpty())
    check(PhysicalNetworkRegistry.latest.selectedDefault == Network(3))
    release.countDown(); starter.join(2000)
    check(!starter.isAlive && failure.get() == null) { "Startup failed: ${failure.get()}" }
    check(RustCoreNative.refreshes.get() == 1)
    check(service.networkUpdates.single() == listOf(Network(3)))
    session.close()
}
private fun stopCancelsPendingWorkerAndRestartUsesFreshEpoch() {
    RustCoreNative.reset()
    val session = session()
    session.startOrReloadService("{}")
    val entered = CountDownLatch(1)
    val release = CountDownLatch(1)
    RustCoreNative.onRefresh = { entered.countDown(); release.await() }
    RustCoreNative.onStop = { release.countDown() }
    PhysicalNetworkRegistry.latest.candidateChange(); entered.ready()
    repeat(20) { PhysicalNetworkRegistry.latest.candidateChange() }
    session.closeService()
    check(RustCoreNative.inFlight.get() == 0 && !PhysicalNetworkRegistry.latest.monitoring)
    val previous = RustCoreNative.refreshes.get()
    RustCoreNative.onRefresh = {}; RustCoreNative.onStop = {}
    session.startOrReloadService("{}")
    PhysicalNetworkRegistry.latest.candidateChange()
    eventually { RustCoreNative.refreshes.get() == previous + 1 }
    session.close()
}
private fun failureCallbackMayCloseWithoutJoiningOrInterruptingItself() {
    RustCoreNative.reset()
    val closed = CountDownLatch(1)
    val failure = AtomicReference<Throwable?>()
    lateinit var session: RustVpnSession
    session = session {
        try { session.close() } catch (e: Throwable) { failure.set(e) }
        finally { closed.countDown() }
    }
    session.startOrReloadService("{}")
    RustCoreNative.onRefresh = { error("refresh failure") }
    PhysicalNetworkRegistry.latest.candidateChange(); closed.ready()
    check(failure.get() == null) { "Close failed: ${failure.get()}" }
    check(PhysicalNetworkRegistry.latest.closed && !session.isRunning())
}
private fun stopWinsWhenStartupRegistersAfterFirstCancellation() {
    RustCoreNative.reset()
    val session = session()
    val firstStop = CountDownLatch(1)
    val releaseStop = CountDownLatch(1)
    val stops = java.util.concurrent.atomic.AtomicInteger()
    val failure = AtomicReference<Throwable?>()
    RustCoreNative.onStop = {
        if (stops.incrementAndGet() == 1) { firstStop.countDown(); releaseStop.ready() }
    }
    val stopper = Thread {
        try { session.closeService() } catch (e: Throwable) { failure.set(e) }
    }
    stopper.start(); firstStop.ready()
    session.startOrReloadService("{}")
    check(PhysicalNetworkRegistry.latest.monitoring && PhysicalNetworkRegistry.latest.listener != null)
    releaseStop.countDown(); stopper.join(2000)
    check(!stopper.isAlive && failure.get() == null) { "Stop failed: ${failure.get()}" }
    check(!PhysicalNetworkRegistry.latest.monitoring && PhysicalNetworkRegistry.latest.listener == null && !session.isRunning())
    RustCoreNative.onStop = {}
    session.close()
}
private fun stopClosesNativeStartedAfterFirstStopCompleted() {
    RustCoreNative.reset()
    val session = session()
    val firstStopCompleted = CountDownLatch(1)
    val releaseStop = CountDownLatch(1)
    val stops = java.util.concurrent.atomic.AtomicInteger()
    val failure = AtomicReference<Throwable?>()
    RustCoreNative.afterStop = {
        if (stops.incrementAndGet() == 1) {
            // Native cleanup has finished, but closeService has not acquired
            // lifecycle yet. A startup can still register in this interval.
            firstStopCompleted.countDown()
            releaseStop.ready()
        }
    }
    val stopper = Thread {
        try { session.closeService() } catch (e: Throwable) { failure.set(e) }
    }
    try {
        stopper.start(); firstStopCompleted.ready()
        session.startOrReloadService("{}")
        check(RustCoreNative.isRunning()) { "Race setup did not start the native core" }
        releaseStop.countDown(); stopper.join(2000)
        check(!stopper.isAlive && failure.get() == null) { "Stop failed: ${failure.get()}" }
        // session.isRunning() also checks Kotlin's active flag and can hide a
        // live native core still owning its duplicated TUN and network tasks.
        check(!RustCoreNative.isRunning()) { "closeService returned with the native core still running" }
        check(!PhysicalNetworkRegistry.latest.monitoring && PhysicalNetworkRegistry.latest.listener == null)
    } finally {
        releaseStop.countDown()
        stopper.join(2000)
        RustCoreNative.afterStop = {}
        session.close()
    }
}
private fun bestNetworkWaitsForBothEventsAndIgnoresOldBest() {
    val state = PhysicalNetworkState()
    val old = Network(10)
    val next = Network(11)
    state.onAvailable(old)
    check(state.current == null)
    state.onCapabilitiesChanged(old, physicalCapabilities())
    check(state.current == null)
    state.onLinkPropertiesChanged(old, physicalLinks())
    check(state.current?.network == old)

    // Best matching callbacks need not deliver onLost(old) on this transition.
    state.onAvailable(next)
    check(state.current == null)
    state.onLinkPropertiesChanged(next, physicalLinks())
    check(state.current == null)
    state.onCapabilitiesChanged(old, physicalCapabilities())
    state.onLinkPropertiesChanged(old, physicalLinks())
    state.onLost(old)
    check(state.current == null)
    state.onCapabilitiesChanged(next, physicalCapabilities())
    check(state.current?.network == next)
    state.onLost(old)
    check(state.current?.network == next)
    state.onLost(next)
    check(state.current == null)
    state.onLinkPropertiesChanged(next, physicalLinks())
    state.onCapabilitiesChanged(next, physicalCapabilities())
    check(state.current == null)
}
private fun snapshotCopiesWholeLinksAndRejectsIncompleteOrVpn() {
    val state = PhysicalNetworkState()
    val network = Network(12)
    val caps = physicalCapabilities()
    val links = physicalLinks()
    state.onAvailable(network)
    state.onCapabilitiesChanged(network, caps)
    caps.removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
    state.onLinkPropertiesChanged(network, links)
    val original = checkNotNull(state.current)
    links.dnsServers.clear()
    links.routes.clear()
    links.privateDnsServerName = "changed.example"
    check(original.dnsServers().single().hostAddress == "192.0.2.53")
    state.onLinkPropertiesChanged(network, physicalLinks())
    check(original.hasSameConfiguration(state.current))
    state.onLinkPropertiesChanged(network, physicalLinks().apply { privateDnsServerName = "new.example" })
    check(!original.hasSameConfiguration(state.current))
    state.onLinkPropertiesChanged(network, physicalLinks().apply { routes.clear() })
    check(!original.hasSameConfiguration(state.current))
    state.onLinkPropertiesChanged(network, physicalLinks().apply { interfaceName = null })
    check(state.current == null)
    state.onLinkPropertiesChanged(network, physicalLinks())
    state.onCapabilitiesChanged(network, physicalCapabilities().addTransportType(NetworkCapabilities.TRANSPORT_VPN))
    check(state.current == null)
    state.onCapabilitiesChanged(network, caps)
    check(state.current == null)
    state.onCapabilitiesChanged(network, physicalCapabilities().removeCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET))
    check(state.current == null)
    state.onCapabilitiesChanged(network, physicalCapabilities())
    check(state.current?.network == network)
}
private fun realPlatformUsesPublishedSnapshotAndBlocksLossImmediately() {
    val service = VpnService()
    // Every synchronous CM getter throws: these are the production platform methods.
    val platform = VpnPlatformCallbacks(service, ConnectivityManager(), physical())
    Network.bindings.clear()
    check(platform.dnsServers() == "[\"192.0.2.53\"]")
    check(platform.protect(91))
    check(Network.bindings.toList() == listOf(1))
    platform.publishNetwork(null)
    val failure = runCatching { platform.protect(92) }.exceptionOrNull()
    check(failure is IllegalStateException && failure.message == "No physical network")
    check(service.protectCalls == 1 && Network.bindings.toList() == listOf(1))
    check(service.networkUpdates.isEmpty())
    platform.applyUnderlyingNetwork()
    check(service.networkUpdates.single().isEmpty())
    platform.publishNetwork(physical(2))
    check(platform.protect(93))
    check(Network.bindings.toList() == listOf(1, 2))
    service.allowProtect = false
    check(!platform.protect(94) && Network.bindings.toList() == listOf(1, 2))
    platform.close()
    check(runCatching { platform.protect(95) }.exceptionOrNull()?.message == "No physical network")
}
private fun lossDuringBusyRefreshBlocksProtectBeforeWorkerCatchesUp() {
    RustCoreNative.reset()
    val service = VpnService()
    val session = session(service)
    session.startOrReloadService("{}")
    val entered = CountDownLatch(1)
    val release = CountDownLatch(1)
    RustCoreNative.onRefresh = {
        if (RustCoreNative.refreshes.get() == 1) { entered.countDown(); release.ready() }
    }
    PhysicalNetworkRegistry.latest.candidateChange()
    entered.ready()
    val applied = service.networkUpdates.size
    session.networkChanged(null)
    check(PhysicalNetworkRegistry.latest.selectedDefault == null)
    check(service.networkUpdates.size == applied)
    check(runCatching { session.platform.protect(96) }.exceptionOrNull()?.message == "No physical network")
    release.countDown()
    eventually { RustCoreNative.refreshes.get() == 2 && RustCoreNative.inFlight.get() == 0 }
    check(service.networkUpdates.last().isEmpty())
    check(service.updateThreads.drop(1).all { it == "aerobox-network-refresh" })
    session.networkChanged(physical(3))
    eventually { RustCoreNative.refreshes.get() == 3 && RustCoreNative.inFlight.get() == 0 }
    check(service.networkUpdates.last() == listOf(Network(3)))
    check(session.platform.protect(97))
    session.close()
    val stoppedUpdates = service.networkUpdates.size
    session.networkChanged(physical(4))
    check(service.networkUpdates.size == stoppedUpdates)
    check(runCatching { session.platform.protect(98) }.exceptionOrNull()?.message == "No physical network")
}
private fun androidBindingFailureIsReportedFromWorker() {
    RustCoreNative.reset()
    val service = VpnService()
    val reported = CountDownLatch(1)
    val failure = AtomicReference<Throwable?>()
    val callbackThread = AtomicReference<String?>()
    val session = session(service) {
        failure.set(it)
        callbackThread.set(Thread.currentThread().name)
        reported.countDown()
    }
    session.startOrReloadService("{}")
    service.allowUnderlying = false
    session.networkChanged(physical(2))
    reported.ready()
    check(failure.get()?.message == "Cannot update physical network for VPN")
    check(callbackThread.get() == "aerobox-network-refresh")
    check(RustCoreNative.refreshes.get() == 0)
    session.close()
}
fun main() {
    val cases = listOf(
        ::burstChangesAreSerializedAndStopUnregisters,
        ::startupChangesWaitForNativeAndCoalesce,
        ::stopCancelsPendingWorkerAndRestartUsesFreshEpoch,
        ::failureCallbackMayCloseWithoutJoiningOrInterruptingItself,
        ::stopWinsWhenStartupRegistersAfterFirstCancellation,
        ::stopClosesNativeStartedAfterFirstStopCompleted,
        ::bestNetworkWaitsForBothEventsAndIgnoresOldBest,
        ::snapshotCopiesWholeLinksAndRejectsIncompleteOrVpn,
        ::realPlatformUsesPublishedSnapshotAndBlocksLossImmediately,
        ::lossDuringBusyRefreshBlocksProtectBeforeWorkerCatchesUp,
        ::androidBindingFailureIsReportedFromWorker,
    )
    for (test in cases) { test(); println("PASS ${test.name}") }
    println("${cases.size} lifecycle/network tests passed (native/Android boundaries mocked)")
}
