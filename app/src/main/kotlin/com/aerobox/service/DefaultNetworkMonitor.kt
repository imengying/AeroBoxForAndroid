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
    private const val LOSS_LOG_DELAY_MS = 1500L

    @Volatile
    var defaultNetwork: Network? = null
        private set

    private var listener: InterfaceUpdateListener? = null
    private var networkChangedCallback: ((Network?) -> Unit)? = null
    private var registered = false
    private val mainHandler = Handler(Looper.getMainLooper())
    private var pendingLossLog: Runnable? = null

    private val networkRequest: NetworkRequest = NetworkRequest.Builder()
        .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED)
        .build()

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            cancelPendingLossLog()
            defaultNetwork = network
            networkChangedCallback?.invoke(network)
            notifyInterfaceUpdate(network)
        }

        override fun onCapabilitiesChanged(
            network: Network,
            capabilities: NetworkCapabilities
        ) {
            if (network == defaultNetwork) {
                cancelPendingLossLog()
                networkChangedCallback?.invoke(network)
                notifyInterfaceUpdate(network)
            }
        }

        override fun onLost(network: Network) {
            if (network == defaultNetwork) {
                defaultNetwork = null
                scheduleLossLog(network)
                networkChangedCallback?.invoke(null)
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
        networkChangedCallback?.invoke(defaultNetwork)
        defaultNetwork?.let { notifyInterfaceUpdate(it) }
    }

    fun stop() {
        if (!registered) return
        cancelPendingLossLog()
        runCatching {
            AeroBoxApplication.connectivity.unregisterNetworkCallback(networkCallback)
        }
        registered = false
        defaultNetwork = null
        listener = null
        networkChangedCallback = null
    }

    fun setListener(listener: InterfaceUpdateListener?) {
        this.listener = listener
        if (listener != null) {
            defaultNetwork?.let { notifyInterfaceUpdate(it) }
        }
    }

    fun setNetworkChangedCallback(callback: ((Network?) -> Unit)?) {
        networkChangedCallback = callback
        callback?.invoke(defaultNetwork)
    }

    private fun cancelPendingLossLog() {
        pendingLossLog?.let(mainHandler::removeCallbacks)
        pendingLossLog = null
    }

    private fun scheduleLossLog(network: Network) {
        cancelPendingLossLog()
        val logTask = Runnable {
            if (defaultNetwork == null) {
                RuntimeLogBuffer.append("info", "Default network lost: $network")
            }
            pendingLossLog = null
        }
        pendingLossLog = logTask
        mainHandler.postDelayed(logTask, LOSS_LOG_DELAY_MS)
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

        // Always notify libbox — needed after service reload even if interface unchanged
        runCatching {
            listener.updateDefaultInterface(interfaceName, interfaceIndex, false, false)
        }.onFailure {
            Log.w(TAG, "updateDefaultInterface failed", it)
            RuntimeLogBuffer.append("warn", "updateDefaultInterface failed: ${it.message ?: it}")
        }
    }
}
