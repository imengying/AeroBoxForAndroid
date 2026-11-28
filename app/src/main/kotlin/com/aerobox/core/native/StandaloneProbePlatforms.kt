package com.aerobox.core.`native`

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities

/** One platform per overlapping batch; each new probe publishes the current underlay. */
internal class StandaloneProbePlatforms(
    private val context: Context,
    private val connectivity: ConnectivityManager,
) {
    private val lock = Any()
    private var platform: PhysicalNetworkCallbacks? = null
    private var users = 0

    fun <T> use(block: (PhysicalNetworkCallbacks) -> T): T {
        val acquired = synchronized(lock) {
            val network = connectivity.activeNetwork?.takeIf {
                connectivity.getNetworkCapabilities(it)
                    ?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) == true
            }
            // Publish loss too, so overlapping probes cannot keep opening
            // sockets on the previous default while this request fails.
            platform?.setUnderlyingNetwork(network)
            checkNotNull(network) { "No physical network available for latency test" }
            val current = platform ?: PhysicalNetworkCallbacks(context, connectivity, network).also {
                try { it.startNetworkMonitoring() }
                catch (failure: Throwable) {
                    runCatching { it.close() }.exceptionOrNull()?.let(failure::addSuppressed)
                    throw failure
                }
                platform = it
            }
            users++
            current
        }
        try {
            return block(acquired)
        } finally {
            synchronized(lock) {
                check(platform === acquired && users > 0)
                if (--users == 0) {
                    platform = null
                    acquired.close()
                }
            }
        }
    }
}
