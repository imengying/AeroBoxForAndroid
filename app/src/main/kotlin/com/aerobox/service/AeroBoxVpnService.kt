package com.aerobox.service

import android.app.Notification
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.Network
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import com.aerobox.AeroBoxApplication
import com.aerobox.MainActivity
import com.aerobox.NotificationSwitchActivity
import com.aerobox.R
import com.aerobox.core.logging.RuntimeLogBuffer
import com.aerobox.utils.NetworkUtils
import com.aerobox.utils.PreferenceManager
import io.nekohasekai.libbox.CommandServer
import io.nekohasekai.libbox.CommandServerHandler
import io.nekohasekai.libbox.OverrideOptions
import io.nekohasekai.libbox.SystemProxyStatus
import io.nekohasekai.libbox.TunOptions
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking

/**
 * AeroBox VPN Service — implements PlatformInterfaceWrapper so libbox
 * can call openTun / autoDetectInterfaceControl etc.
 *
 * The core lifecycle follows SFA:
 *   CommandServer(handler, platformInterface) → startOrReloadService(config, overrides)
 */
class AeroBoxVpnService : VpnService(), PlatformInterfaceWrapper, CommandServerHandler {

    companion object {
        const val ACTION_START = "com.aerobox.action.START"
        const val ACTION_STOP = "com.aerobox.action.STOP"
        const val ACTION_SWITCH = "com.aerobox.action.SWITCH"
        const val EXTRA_CONFIG = "extra_config"
        const val EXTRA_NODE_ID = "extra_node_id"
        const val NOTIFICATION_ID = 1001
        private const val TAG = "AeroBoxVpnService"

        val isServiceActive: StateFlow<Boolean> = VpnStateManager.serviceActive
    }

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var vpnInterface: ParcelFileDescriptor? = null
    private var speedTickerJob: Job? = null
    private var commandServer: CommandServer? = null
    private var receiverRegistered = false

    private var lastConfig: String? = null
    private var lastNodeId: Long = -1L
    private var userRequestedStop = false
    private var reconnectAttempts = 0
    private var pendingSwitchConfig: String? = null
    private var pendingSwitchNodeId: Long = -1L

    private val closeReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            when (intent.action) {
                ACTION_STOP -> {
                    userRequestedStop = true
                    stopService("Stopping service: notification action")
                    stopSelf()
                }
            }
        }
    }

    override fun onBind(intent: Intent?): IBinder? = super.onBind(intent)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> {
                val config = intent.getStringExtra(EXTRA_CONFIG).orEmpty()
                val nodeId = intent.getLongExtra(EXTRA_NODE_ID, -1L)
                userRequestedStop = false
                reconnectAttempts = 0
                pendingSwitchConfig = null
                pendingSwitchNodeId = -1L
                lastConfig = config
                if (nodeId > 0L) {
                    lastNodeId = nodeId
                }
                startVpn(config)
            }
            ACTION_SWITCH -> {
                val config = intent.getStringExtra(EXTRA_CONFIG).orEmpty()
                val nodeId = intent.getLongExtra(EXTRA_NODE_ID, -1L)
                if (config.isBlank()) {
                    RuntimeLogBuffer.append("warn", "Ignoring node switch: empty config")
                    return START_STICKY
                }
                userRequestedStop = false
                reconnectAttempts = 0
                pendingSwitchConfig = config
                pendingSwitchNodeId = nodeId
                if (commandServer != null && (VpnStateManager.serviceActive.value || vpnInterface != null)) {
                    RuntimeLogBuffer.append("info", "Switching node: restarting service")
                    runCatching { commandServer?.closeService() }
                        .onFailure {
                            RuntimeLogBuffer.append(
                                "warn",
                                "Switch restart failed, falling back to reload: ${it.message ?: it}"
                            )
                            pendingSwitchConfig = null
                            pendingSwitchNodeId = -1L
                            lastConfig = config
                            if (nodeId > 0L) {
                                lastNodeId = nodeId
                            }
                            startVpn(config)
                        }
                } else {
                    lastConfig = config
                    if (nodeId > 0L) {
                        lastNodeId = nodeId
                    }
                    pendingSwitchConfig = null
                    pendingSwitchNodeId = -1L
                    startVpn(config)
                }
            }
            ACTION_STOP -> {
                userRequestedStop = true
                pendingSwitchConfig = null
                pendingSwitchNodeId = -1L
                stopService("Stopping service: ACTION_STOP intent")
                stopSelf()
            }
        }
        return START_STICKY
    }

    // ─── VPN Lifecycle ───

    private fun startVpn(config: String) {
        VpnStateManager.updateServiceActive(true)
        serviceScope.launch {
            runCatching {
                RuntimeLogBuffer.append("info", "Starting sing-box service")
                startForeground(
                    NOTIFICATION_ID,
                    buildNotification(connected = false)
                )

                // Register close receiver
                if (!receiverRegistered) {
                    val filter = IntentFilter().apply {
                        addAction(ACTION_STOP)
                    }
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        registerReceiver(closeReceiver, filter, RECEIVER_NOT_EXPORTED)
                    } else {
                        registerReceiver(closeReceiver, filter)
                    }
                    receiverRegistered = true
                }

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
                    DefaultNetworkMonitor.setNetworkChangedCallback(::updateUnderlyingNetwork)
                }
                DefaultNetworkMonitor.start()

                val server = commandServer ?: CommandServer(this@AeroBoxVpnService, this@AeroBoxVpnService).also {
                    it.start()
                    commandServer = it
                    RuntimeLogBuffer.append("debug", "CommandServer started")
                }

                val overrides = buildOverrideOptions()
                server.startOrReloadService(config, overrides)
                RuntimeLogBuffer.append("info", "startOrReloadService invoked")

            }.onFailure { e ->
                Log.e(TAG, "startVpn failed", e)
                RuntimeLogBuffer.append("error", "startVpn failed: ${e.message ?: e}")
                VpnStateManager.updateLastError(e.message ?: e.toString())
                stopService("Stopping service after start failure")
            }
        }
    }

    private fun buildOverrideOptions(): OverrideOptions {
        return OverrideOptions().apply {
            // Per-app proxy
            val perAppEnabled = runBlocking {
                PreferenceManager.perAppProxyEnabledFlow(applicationContext).first()
            }
            if (perAppEnabled) {
                val mode = runBlocking {
                    PreferenceManager.perAppProxyModeFlow(applicationContext).first()
                }
                val packages = runBlocking {
                    PreferenceManager.perAppProxyPackagesFlow(applicationContext).first()
                }
                if (mode == "whitelist") {
                    includePackage = PlatformInterfaceWrapper.StringArray(
                        (packages + packageName).iterator()
                    )
                } else {
                    excludePackage = PlatformInterfaceWrapper.StringArray(
                        (packages - packageName).iterator()
                    )
                }
            }
        }
    }

    private suspend fun resolveCurrentNode(explicitNodeId: Long?): com.aerobox.data.model.ProxyNode? {
        val nodeId = when {
            explicitNodeId != null && explicitNodeId > 0L -> explicitNodeId
            lastNodeId > 0L -> lastNodeId
            else -> PreferenceManager.lastSelectedNodeIdFlow(applicationContext).first()
        }
        if (nodeId <= 0L) return null
        return AeroBoxApplication.database.proxyNodeDao().getNodeById(nodeId)
    }

    private fun stopService(reason: String = "Stopping service") {
        RuntimeLogBuffer.append("info", reason)
        speedTickerJob?.cancel()
        speedTickerJob = null

        DefaultNetworkMonitor.stop()

        runCatching { commandServer?.closeService() }
        runCatching {
            commandServer?.close()
            commandServer = null
        }

        // Close VPN tunnel
        runCatching {
            vpnInterface?.close()
            vpnInterface = null
        }

        // Unregister receiver
        if (receiverRegistered) {
            runCatching { unregisterReceiver(closeReceiver) }
            receiverRegistered = false
        }

        VpnStateManager.updateServiceActive(false)
        VpnStateManager.updateConnectionState(false, null)
        VpnStateManager.resetStats()

        stopForeground(STOP_FOREGROUND_REMOVE)
    }

    // ─── CommandServerHandler callbacks ───

    override fun serviceStop() {
        val switchConfig = pendingSwitchConfig
        val switchNodeId = pendingSwitchNodeId
        if (!switchConfig.isNullOrBlank()) {
            pendingSwitchConfig = null
            pendingSwitchNodeId = -1L
            vpnInterface?.close()
            vpnInterface = null
            VpnStateManager.updateConnectionState(false, null)
            RuntimeLogBuffer.append("info", "Service stopped for node switch")
            lastConfig = switchConfig
            if (switchNodeId > 0L) {
                lastNodeId = switchNodeId
            }
            serviceScope.launch {
                startVpn(switchConfig)
            }
            return
        }
        RuntimeLogBuffer.append(
            if (userRequestedStop) "info" else "warn",
            if (userRequestedStop) "Service stopped" else "Service stopped unexpectedly"
        )
        // Called by libbox when the service stops (may be unexpected)
        vpnInterface?.close()
        vpnInterface = null
        VpnStateManager.updateServiceActive(false)
        VpnStateManager.updateConnectionState(false, null)

        if (!userRequestedStop) {
            // Unexpected disconnect — try auto-reconnect
            attemptReconnect()
        } else {
            stopService("Stopping service after serviceStop callback")
        }
    }

    override fun serviceReload() {
        // Called by libbox for hot-reload — not used in our simple flow
        RuntimeLogBuffer.append("info", "Service reloaded")
    }

    override fun getSystemProxyStatus(): SystemProxyStatus {
        return SystemProxyStatus()
    }

    override fun setSystemProxyEnabled(enabled: Boolean) {
        // Not applicable to VPN mode
    }

    override fun writeDebugMessage(message: String) {
        Log.d(TAG, "libbox-debug: $message")
        RuntimeLogBuffer.append("debug", message)
    }

    override fun sendNotification(notification: io.nekohasekai.libbox.Notification) {
        Log.i(TAG, "libbox notification: ${notification.title} - ${notification.body}")
        val content = buildString {
            if (notification.title.isNotBlank()) append(notification.title)
            if (notification.body.isNotBlank()) {
                if (isNotEmpty()) append(" - ")
                append(notification.body)
            }
        }.ifBlank { "libbox notification" }
        RuntimeLogBuffer.append("info", content)
    }

    // ─── PlatformInterfaceWrapper overrides ───

    override fun autoDetectInterfaceControl(fd: Int) {
        if (!protect(fd)) {
            RuntimeLogBuffer.append("warn", "protect(fd) failed")
        }
    }

    override fun openTun(options: TunOptions): Int {
        if (prepare(this) != null) error("android: missing vpn permission")
        RuntimeLogBuffer.append("debug", "Opening VPN TUN interface")

        val builder = Builder()
            .setSession("AeroBox")
            .setMtu(options.mtu)

        builder.setMetered(false)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
            DefaultNetworkMonitor.defaultNetwork?.let { network ->
                runCatching {
                    builder.setUnderlyingNetworks(arrayOf(network))
                }.onSuccess {
                    RuntimeLogBuffer.append("debug", "Builder underlying network set: $network")
                }.onFailure {
                    RuntimeLogBuffer.append(
                        "warn",
                        "Builder setUnderlyingNetworks failed: ${it.message ?: it}"
                    )
                }
            }
        }

        val inet4Addresses = mutableListOf<Pair<String, Int>>()
        val inet4Address = options.inet4Address
        while (inet4Address.hasNext()) {
            val addr = inet4Address.next()
            inet4Addresses.add(addr.address() to addr.prefix())
        }
        inet4Addresses.forEach { (address, prefix) -> builder.addAddress(address, prefix) }

        val inet6Addresses = mutableListOf<Pair<String, Int>>()
        val inet6Address = options.inet6Address
        while (inet6Address.hasNext()) {
            val addr = inet6Address.next()
            inet6Addresses.add(addr.address() to addr.prefix())
        }
        inet6Addresses.forEach { (address, prefix) -> builder.addAddress(address, prefix) }

        if (options.autoRoute) {
            builder.addDnsServer(options.dnsServerAddress.value)
            builder.addRoute("0.0.0.0", 0)
            if (inet6Addresses.isNotEmpty()) {
                builder.addRoute("::", 0)
            }
            RuntimeLogBuffer.append(
                "debug",
                "Tun prepared: ipv4=${inet4Addresses.size}, ipv6=${inet6Addresses.size}, " +
                    "forcedDefaultRoutes=true"
            )
        }

        // Per-app proxy from OverrideOptions (handled by libbox include/exclude)
        val include = options.includePackage
        while (include.hasNext()) {
            runCatching { builder.addAllowedApplication(include.next()) }
        }
        val exclude = options.excludePackage
        while (exclude.hasNext()) {
            runCatching { builder.addDisallowedApplication(exclude.next()) }
        }

        val pfd = builder.establish()
            ?: error("android: failed to establish VPN interface")
        vpnInterface = pfd
        val connectedNode = runBlocking {
            resolveCurrentNode(null)
        }
        VpnStateManager.clearLastError()
        VpnStateManager.updateConnectionState(true, connectedNode)
        RuntimeLogBuffer.append(
            "info",
            "VPN interface established" + (
                connectedNode?.name?.takeIf { it.isNotBlank() }?.let { " for $it" } ?: ""
            )
        )
        val initialSpeedText = "↑ 0 B/s  ↓ 0 B/s"
        val notification = buildNotification(contentText = initialSpeedText, connected = true)
        val nm = getSystemService(NOTIFICATION_SERVICE) as android.app.NotificationManager
        nm.notify(NOTIFICATION_ID, notification)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
            updateUnderlyingNetwork(DefaultNetworkMonitor.defaultNetwork)
        }
        startSpeedTicker()
        return pfd.fd
    }

    private fun updateUnderlyingNetwork(network: Network?) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP_MR1) return
        runCatching {
            setUnderlyingNetworks(network?.let { arrayOf(it) })
        }.onSuccess {
            RuntimeLogBuffer.append(
                "debug",
                if (network != null) {
                    "Underlying network applied: $network"
                } else {
                    "Underlying network cleared"
                }
            )
        }.onFailure {
            RuntimeLogBuffer.append(
                "warn",
                "setUnderlyingNetworks failed: ${it.message ?: it}"
            )
        }
    }

    // ─── Notification ───

    private fun buildNotification(contentText: String = "", connected: Boolean = false): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val stopIntent = Intent(ACTION_STOP).setPackage(packageName)
        val stopPendingIntent = PendingIntent.getBroadcast(
            this,
            101,
            stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val switchIntent = Intent(this, NotificationSwitchActivity::class.java).apply {
            addFlags(
                Intent.FLAG_ACTIVITY_NEW_TASK or
                    Intent.FLAG_ACTIVITY_EXCLUDE_FROM_RECENTS or
                    Intent.FLAG_ACTIVITY_NO_HISTORY
            )
        }
        val switchPendingIntent = PendingIntent.getActivity(
            this,
            102,
            switchIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val title = if (connected) {
            VpnStateManager.vpnState.value.currentNode
                ?.name
                ?.takeIf { it.isNotBlank() }
                ?: getString(R.string.notification_title)
        } else {
            getString(R.string.notification_title)
        }
        val mergedContent = when {
            connected && contentText.isNotBlank() -> contentText
            connected -> "↑ 0 B/s  ↓ 0 B/s"
            contentText.isBlank() -> getString(R.string.notification_connecting)
            else -> contentText
        }

        val builder = NotificationCompat.Builder(this, AeroBoxApplication.NOTIFICATION_CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(mergedContent)
            .setSubText(null)
            .setSmallIcon(R.drawable.ic_stat_aerobox)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .setSilent(true)
            .setOnlyAlertOnce(true)

        if (connected) {
            builder
                .addAction(
                    android.R.drawable.ic_menu_rotate,
                    getString(R.string.notification_action_switch),
                    switchPendingIntent
                )
                .addAction(
                    android.R.drawable.ic_media_pause,
                    getString(R.string.notification_action_stop),
                    stopPendingIntent
                )
        } else {
            builder.addAction(
                android.R.drawable.ic_media_pause,
                getString(R.string.notification_action_stop),
                stopPendingIntent
            )
        }

        return builder.build()
    }

    private fun startSpeedTicker() {
        speedTickerJob?.cancel()
        val uid = applicationInfo.uid
        val initialTx = android.net.TrafficStats.getUidTxBytes(uid).takeIf { it >= 0L } ?: 0L
        val initialRx = android.net.TrafficStats.getUidRxBytes(uid).takeIf { it >= 0L } ?: 0L
        speedTickerJob = serviceScope.launch {
            var prevTx = initialTx
            var prevRx = initialRx

            while (isActive && VpnStateManager.serviceActive.value) {
                delay(1000)
                val curTx = android.net.TrafficStats.getUidTxBytes(uid).takeIf { it >= 0L } ?: prevTx
                val curRx = android.net.TrafficStats.getUidRxBytes(uid).takeIf { it >= 0L } ?: prevRx
                val uploadSpeed = (curTx - prevTx).coerceAtLeast(0L)
                val downloadSpeed = (curRx - prevRx).coerceAtLeast(0L)
                val totalUpload = (curTx - initialTx).coerceAtLeast(0L)
                val totalDownload = (curRx - initialRx).coerceAtLeast(0L)

                VpnStateManager.updateTrafficStats(
                    uploadSpeed = uploadSpeed,
                    downloadSpeed = downloadSpeed,
                    totalUpload = totalUpload,
                    totalDownload = totalDownload
                )

                prevTx = curTx
                prevRx = curRx

                val text = "↑ ${NetworkUtils.formatBytes(uploadSpeed)}/s  ↓ ${NetworkUtils.formatBytes(downloadSpeed)}/s"
                val notification = buildNotification(contentText = text, connected = true)
                val nm = getSystemService(NOTIFICATION_SERVICE) as android.app.NotificationManager
                nm.notify(NOTIFICATION_ID, notification)
            }
        }
    }

    override fun onDestroy() {
        userRequestedStop = true
        stopService("Stopping service: onDestroy")
        serviceScope.cancel()
        super.onDestroy()
    }

    // ─── Auto-Reconnect ───

    private fun attemptReconnect() {
        val config = lastConfig ?: return
        serviceScope.launch {
            val autoReconnect = runBlocking {
                PreferenceManager.autoReconnectFlow(applicationContext).first()
            }
            if (!autoReconnect) {
                stopService("Stopping service: auto reconnect disabled")
                return@launch
            }

            reconnectAttempts++
            val backoffMs = 1000L * (1L shl (reconnectAttempts - 1).coerceAtMost(5))
            Log.i(TAG, "Auto-reconnect attempt $reconnectAttempts in ${backoffMs}ms")
            RuntimeLogBuffer.append(
                "warn",
                "Auto-reconnect attempt $reconnectAttempts in ${backoffMs}ms"
            )
            delay(backoffMs)

            if (userRequestedStop) return@launch
            startVpn(config)
        }
    }
}
