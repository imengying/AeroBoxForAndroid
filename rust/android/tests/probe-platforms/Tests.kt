package com.aerobox.core.`native`

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread

private class Fixture {
    val connectivity = ConnectivityManager().apply { select(Network(1)) }
    val platforms = StandaloneProbePlatforms(Context(), connectivity)
}
private fun CountDownLatch.ready() = check(await(3, TimeUnit.SECONDS)) { "test synchronization timed out" }
private fun rejects(block: () -> Unit) = check(runCatching(block).isFailure)

private fun overlappingCallsShareAndReleaseAfterLastUser() {
    val f = Fixture()
    f.platforms.use { first ->
        f.platforms.use { second ->
            check(first === second)
            check(second.protect(1))
        }
        check(PhysicalNetworkRegistry.instances.single().monitoring)
        check(PhysicalNetworkRegistry.instances.single().closes == 0)
    }
    check(PhysicalNetworkRegistry.instances.single().closes == 1)
    check(PlatformDnsQueries.instances.single().closes == 1)
}

private fun nextProbePublishesChangedNetworkWhileOldProbeIsBusy() {
    val f = Fixture()
    val entered = CountDownLatch(1)
    val release = CountDownLatch(1)
    val held = AtomicReference<PhysicalNetworkCallbacks>()
    val failure = AtomicReference<Throwable?>()
    val worker = thread {
        try {
            f.platforms.use { held.set(it); entered.countDown(); release.ready() }
        } catch (error: Throwable) { failure.set(error) }
    }
    try {
        entered.ready()
        f.connectivity.select(Network(2))
        f.platforms.use { current ->
            check(current === held.get())
            check(current.protect(2))
            check(Network.bindings.last() == 2) { "new probe remained bound to the previous physical network" }
            check(current.physicalNetworks() == "{\"default_handle\":2}")
            check(current.protectOnNetwork(2, 1, 2))
        }
        check(PhysicalNetworkRegistry.instances.single().closes == 0)
    } finally {
        release.countDown()
        worker.join(3000)
    }
    check(!worker.isAlive)
    failure.get()?.let { throw it }
    check(PhysicalNetworkRegistry.instances.single().closes == 1)
}

private fun missingOrVpnNetworkBlocksOldBindingsAndRecoveryUsesCurrentNetwork() {
    val f = Fixture()
    f.platforms.use { held ->
        for (network in listOf(null, Network(9))) {
            f.connectivity.select(network, physical = false)
            var dispatched = false
            rejects { f.platforms.use { dispatched = true } }
            check(!dispatched)
            check(PhysicalNetworkRegistry.instances.single().selected == null)
            rejects { held.protect(3) }
        }
        f.connectivity.select(Network(3))
        f.platforms.use { current ->
            check(current === held)
            check(current.protect(4))
            check(Network.bindings.last() == 3)
        }
        check(PhysicalNetworkRegistry.instances.single().monitoring)
    }
    check(PhysicalNetworkRegistry.instances.single().closes == 1)
}

private fun failuresReleaseTheirOwnReferenceAndLaterBatchStartsFresh() {
    val f = Fixture()
    lateinit var previous: PhysicalNetworkCallbacks
    rejects {
        f.platforms.use { outer ->
            previous = outer
            rejects { f.platforms.use { error("inner probe failed") } }
            check(PhysicalNetworkRegistry.instances.single().closes == 0)
            error("outer probe failed")
        }
    }
    check(PhysicalNetworkRegistry.instances.single().closes == 1)
    f.connectivity.select(Network(4))
    f.platforms.use { current ->
        check(current !== previous)
        check(current.protect(5))
        check(Network.bindings.last() == 4)
    }
    check(PhysicalNetworkRegistry.instances.size == 2)
    check(PhysicalNetworkRegistry.instances.all { it.closes == 1 })
}

private fun failedRegistrationReleasesResourcesAndCanRetry() {
    val f = Fixture()
    val failure = IllegalStateException("cannot register network callback")
    PhysicalNetworkRegistry.onStart = { throw failure }
    check(runCatching { f.platforms.use { error("must not dispatch") } }.exceptionOrNull() === failure)
    check(PhysicalNetworkRegistry.instances.single().closes == 1)
    check(PlatformDnsQueries.instances.single().closes == 1)
    PhysicalNetworkRegistry.onStart = {}
    f.platforms.use { check(it.protect(6)) }
    check(PhysicalNetworkRegistry.instances.size == 2)
    check(PhysicalNetworkRegistry.instances.all { it.closes == 1 })
}

fun main() {
    val cases = listOf(
        ::overlappingCallsShareAndReleaseAfterLastUser,
        ::nextProbePublishesChangedNetworkWhileOldProbeIsBusy,
        ::missingOrVpnNetworkBlocksOldBindingsAndRecoveryUsesCurrentNetwork,
        ::failuresReleaseTheirOwnReferenceAndLaterBatchStartsFresh,
        ::failedRegistrationReleasesResourcesAndCanRetry,
    )
    for (test in cases) {
        PhysicalNetworkRegistry.instances.clear()
        PhysicalNetworkRegistry.onStart = {}
        PlatformDnsQueries.instances.clear()
        Network.bindings.clear()
        test()
        println("PASS ${test.name}")
    }
    println("${cases.size} standalone probe platform tests passed (Android/JNI boundaries mocked)")
}
