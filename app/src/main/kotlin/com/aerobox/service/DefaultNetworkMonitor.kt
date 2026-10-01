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
import io.nekohasekai.libbox.InterfaceUpdateListener
import kotlinx.coroutines.android.asCoroutineDispatcher
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import java.net.NetworkInterface

/**
 * Tracks the system default network and feeds interface updates to sing-box
 * via [InterfaceUpdateListener].
 *
 * Modeled after SFA's DefaultNetworkMonitor + DefaultNetworkListener.
 */
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
    private var listener: InterfaceUpdateListener? = null
    private var networkChangedCallback: ((Network?) -> Unit)? = null
    private var registeredCallback: ConnectivityManager.NetworkCallback? = null
    private var linkProperties: LinkProperties? = null

    private val networkRequest: NetworkRequest = NetworkRequest.Builder()
        .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
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

        override fun onCapabilitiesChanged(
            network: Network,
            capabilities: NetworkCapabilities
        ) {
            if (registeredCallback === this && network == defaultNetwork) {
                notifyInterfaceUpdate()
            }
        }

        override fun onLinkPropertiesChanged(network: Network, properties: LinkProperties) {
            if (registeredCallback === this && network == defaultNetwork) {
                linkProperties = properties
                notifyInterfaceUpdate()
            }
        }

        override fun onLost(network: Network) {
            if (registeredCallback === this && network == defaultNetwork) {
                defaultNetwork = null
                linkProperties = null
                networkChangedCallback?.invoke(null)
                notifyInterfaceUpdate()
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
        listener = null
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

    fun setListener(listener: InterfaceUpdateListener?) {
        if (listener == null) {
            // Core shutdown may hold locks needed by an in-flight network update.
            callbackHandler.post { this.listener = null }
            return
        }
        // Called by native startup on IO. Publish the initial interface before startup continues.
        runBlocking(callbackDispatcher.immediate) {
            if (registeredCallback == null) return@runBlocking
            this@DefaultNetworkMonitor.listener = listener
            notifyInterfaceUpdate()
        }
    }

    private fun notifyInterfaceUpdate() {
        val listener = listener ?: return
        val interfaceName = if (defaultNetwork != null) {
            linkProperties?.interfaceName ?: return
        } else {
            ""
        }

        val interfaceIndex = try {
            if (interfaceName.isEmpty()) -1 else NetworkInterface.getByName(interfaceName)?.index ?: -1
        } catch (_: Exception) {
            -1
        }

        // Always notify libbox — needed after service reload even if interface unchanged
        runCatching {
            listener.updateDefaultInterface(interfaceName, interfaceIndex, false, false)
        }.onFailure {
            Log.w(TAG, "updateDefaultInterface failed", it)
        }
    }
}
