package com.aerobox.service

import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Handler
import android.os.HandlerThread
import android.util.Log
import com.aerobox.AeroBoxApplication
import com.aerobox.core.native.PhysicalNetwork
import com.aerobox.core.native.PhysicalNetworkState
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.android.asCoroutineDispatcher
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull

/** Publishes the best physical network on one ordered callback thread. */
object DefaultNetworkMonitor {

    private const val TAG = "DefaultNetworkMonitor"
    private const val INITIAL_NETWORK_TIMEOUT_MS = 10_000L

    @Volatile
    var defaultNetwork: PhysicalNetwork? = null
        private set

    // All state except the published network is confined to this process-lifetime thread.
    private val callbackHandler by lazy {
        Handler(HandlerThread("aerobox-network").apply { start() }.looper)
    }
    private val callbackDispatcher by lazy { callbackHandler.asCoroutineDispatcher() }
    private var networkChangedCallback: ((PhysicalNetwork?) -> Unit)? = null
    private var registeredCallback: NetworkCallback? = null

    private val networkRequest: NetworkRequest = NetworkRequest.Builder()
        .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
        .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED)
        .build()

    private class NetworkCallback : ConnectivityManager.NetworkCallback() {
        private val state = PhysicalNetworkState()
        private val waiters = mutableSetOf<CompletableDeferred<Unit>>()

        fun awaitReady(): CompletableDeferred<Unit> = CompletableDeferred<Unit>().also {
            if (state.current != null) it.complete(Unit) else waiters.add(it)
        }

        fun removeWaiter(waiter: CompletableDeferred<Unit>) { waiters.remove(waiter) }

        fun cancelled() {
            waiters.forEach { it.cancel(CancellationException("Physical network monitor stopped")) }
            waiters.clear()
        }

        private fun publish() {
            val next = state.current
            val previous = defaultNetwork
            val changed = if (next == null) previous != null else !next.hasSameConfiguration(previous)
            if (changed) defaultNetwork = next
            if (next != null) {
                waiters.forEach { it.complete(Unit) }
                waiters.clear()
            }
            if (changed) networkChangedCallback?.invoke(next)
        }

        override fun onAvailable(network: Network) {
            if (registeredCallback !== this) return
            // Best-matching callbacks need not send onLost for the old best.
            // Clear it now, then wait for this network's complete event data.
            state.onAvailable(network)
            publish()
        }

        override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
            if (registeredCallback !== this) return
            state.onCapabilitiesChanged(network, capabilities)
            publish()
        }

        override fun onLinkPropertiesChanged(network: Network, properties: LinkProperties) {
            if (registeredCallback !== this) return
            state.onLinkPropertiesChanged(network, properties)
            publish()
        }

        override fun onLost(network: Network) {
            if (registeredCallback !== this) return
            state.onLost(network)
            publish()
        }
    }

    suspend fun start(onNetworkChanged: (PhysicalNetwork?) -> Unit) = withContext(callbackDispatcher) {
        val callback = registeredCallback ?: NetworkCallback().also {
            registeredCallback = it
            try {
                AeroBoxApplication.connectivity.registerBestMatchingNetworkCallback(networkRequest, it, callbackHandler)
            } catch (failure: Throwable) {
                registeredCallback = null
                throw failure
            }
        }
        networkChangedCallback = onNetworkChanged
        // Never seed from synchronous CM queries: their view can lag the events.
        onNetworkChanged(defaultNetwork)
        val ready = withTimeoutOrNull(INITIAL_NETWORK_TIMEOUT_MS) {
            while (true) {
                check(registeredCallback === callback) { "Physical network monitor stopped" }
                if (defaultNetwork != null) break
                val waiter = callback.awaitReady()
                try { waiter.await() }
                finally { callback.removeWaiter(waiter) }
            }
            true
        }
        check(ready == true) { "No physical network became ready within 10 seconds" }
    }

    suspend fun stop() = withContext(NonCancellable + callbackDispatcher) {
        val callback = registeredCallback
        // Invalidate queued callbacks before unregistering; a new start gets its own instance.
        registeredCallback = null
        defaultNetwork = null
        val listener = networkChangedCallback
        networkChangedCallback = null
        callback?.cancelled()
        try {
            listener?.invoke(null)
        } finally {
            if (callback != null) {
                runCatching {
                    AeroBoxApplication.connectivity.unregisterNetworkCallback(callback)
                }.onFailure {
                    Log.w(TAG, "Failed to unregister network callback", it)
                }
            }
        }
        Unit
    }

}
