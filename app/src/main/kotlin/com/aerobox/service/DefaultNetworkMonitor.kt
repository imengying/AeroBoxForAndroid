package com.aerobox.service

import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Handler
import android.os.Looper
import android.util.Log
import com.aerobox.AeroBoxApplication
import com.aerobox.core.logging.RuntimeLogBuffer
import io.nekohasekai.libbox.InterfaceUpdateListener
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

    private var listener: InterfaceUpdateListener? = null
    private var registered = false
    private val mainHandler = Handler(Looper.getMainLooper())

    // Dedup: only notify libbox when the interface actually changes
    private var lastInterfaceName: String? = null
    private var lastInterfaceIndex: Int = -1

    private val networkRequest: NetworkRequest = NetworkRequest.Builder()
        .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED)
        .build()

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            defaultNetwork = network
            RuntimeLogBuffer.append("debug", "Default network available: $network")
            notifyInterfaceUpdate(network)
        }

        override fun onCapabilitiesChanged(
            network: Network,
            capabilities: NetworkCapabilities
        ) {
            if (network == defaultNetwork) {
                notifyInterfaceUpdate(network)
            }
        }

        override fun onLost(network: Network) {
            if (network == defaultNetwork) {
                defaultNetwork = null
                lastInterfaceName = null
                lastInterfaceIndex = -1
                RuntimeLogBuffer.append("warn", "Default network lost: $network")
                listener?.runCatching {
                    updateDefaultInterface("", -1, false, false)
                }
            }
        }
    }

    fun start() {
        if (registered) return
        val cm = AeroBoxApplication.connectivity
        try {
            cm.registerBestMatchingNetworkCallback(
                networkRequest, networkCallback, mainHandler
            )
            registered = true
        } catch (e: Exception) {
            Log.w(TAG, "Failed to register network callback", e)
        }
        defaultNetwork = cm.activeNetwork
        defaultNetwork?.let { notifyInterfaceUpdate(it) }
    }

    fun stop() {
        if (!registered) return
        runCatching {
            AeroBoxApplication.connectivity.unregisterNetworkCallback(networkCallback)
        }
        registered = false
        defaultNetwork = null
        listener = null
        lastInterfaceName = null
        lastInterfaceIndex = -1
    }

    fun setListener(listener: InterfaceUpdateListener?) {
        this.listener = listener
        if (listener != null) {
            defaultNetwork?.let { notifyInterfaceUpdate(it) }
        }
    }

    private fun notifyInterfaceUpdate(network: Network) {
        val listener = listener ?: return
        val cm = AeroBoxApplication.connectivity
        val linkProperties = cm.getLinkProperties(network) ?: return
        val interfaceName = linkProperties.interfaceName ?: return

        val interfaceIndex = try {
            NetworkInterface.getByName(interfaceName)?.index ?: -1
        } catch (_: Exception) {
            -1
        }

        // Skip if interface hasn't changed — avoids flooding libbox with
        // duplicate updates on repeated onCapabilitiesChanged callbacks.
        if (interfaceName == lastInterfaceName && interfaceIndex == lastInterfaceIndex) return
        lastInterfaceName = interfaceName
        lastInterfaceIndex = interfaceIndex

        RuntimeLogBuffer.append("debug", "Default interface updated: name=$interfaceName, index=$interfaceIndex")
        runCatching {
            listener.updateDefaultInterface(interfaceName, interfaceIndex, false, false)
        }.onFailure {
            Log.w(TAG, "updateDefaultInterface failed", it)
            RuntimeLogBuffer.append("warn", "updateDefaultInterface failed: ${it.message ?: it}")
        }
    }
}
