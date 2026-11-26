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
import kotlinx.coroutines.android.asCoroutineDispatcher
import kotlinx.coroutines.withContext

/** Publishes the best physical network on one ordered callback thread. */
object DefaultNetworkMonitor {

    private const val TAG = "DefaultNetworkMonitor"

    @Volatile
    var defaultNetwork: Network? = null
        private set

    // All state except the published network is confined to this process-lifetime thread.
    private val callbackHandler by lazy {
        Handler(HandlerThread("aerobox-network").apply { start() }.looper)
    }
    private val callbackDispatcher by lazy { callbackHandler.asCoroutineDispatcher() }
    private var networkChangedCallback: ((Network?) -> Unit)? = null
    private var registeredCallback: ConnectivityManager.NetworkCallback? = null
    private var linkProperties: LinkProperties? = null

    private val networkRequest: NetworkRequest = NetworkRequest.Builder()
        .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
        .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED)
        .build()

    private class NetworkCallback : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            if (registeredCallback !== this) return
            defaultNetwork = network
            linkProperties = null
            networkChangedCallback?.invoke(network)
            // Android sends capabilities and link properties immediately after onAvailable.
        }

        override fun onLinkPropertiesChanged(network: Network, properties: LinkProperties) {
            if (registeredCallback === this && network == defaultNetwork) {
                linkProperties = properties
                networkChangedCallback?.invoke(network)
            }
        }

        override fun onLost(network: Network) {
            if (registeredCallback === this && network == defaultNetwork) {
                defaultNetwork = null
                linkProperties = null
                networkChangedCallback?.invoke(null)
            }
        }
    }

    suspend fun start(onNetworkChanged: (Network?) -> Unit) = withContext(callbackDispatcher) {
        if (registeredCallback == null) {
            val cm = AeroBoxApplication.connectivity
            val callback = NetworkCallback()
            cm.registerBestMatchingNetworkCallback(networkRequest, callback, callbackHandler)
            registeredCallback = callback
            defaultNetwork = cm.activeNetwork?.takeIf { network ->
                cm.getNetworkCapabilities(network)
                    ?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) == true
            }
            linkProperties = defaultNetwork?.let(cm::getLinkProperties)
        }
        networkChangedCallback = onNetworkChanged
        onNetworkChanged(defaultNetwork)
    }

    suspend fun stop() = withContext(callbackDispatcher) {
        val callback = registeredCallback
        // Invalidate queued callbacks before unregistering; a new start gets its own instance.
        registeredCallback = null
        defaultNetwork = null
        linkProperties = null
        networkChangedCallback = null
        if (callback != null) {
            runCatching {
                AeroBoxApplication.connectivity.unregisterNetworkCallback(callback)
            }.onFailure {
                Log.w(TAG, "Failed to unregister network callback", it)
            }
        }
        Unit
    }

}
