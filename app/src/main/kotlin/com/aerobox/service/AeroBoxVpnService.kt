package com.aerobox.service

import android.app.Notification
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.IpPrefix
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
import com.aerobox.core.config.ConfigGenerator
import com.aerobox.core.logging.RuntimeLogBuffer
import com.aerobox.core.native.SingBoxNative
import com.aerobox.data.model.ProxyNode
import com.aerobox.data.repository.VpnConfigResolver
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
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.net.InetAddress

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
        const val ACTION_RELOAD = "com.aerobox.action.RELOAD"
        const val EXTRA_CONFIG = "extra_config"
        const val EXTRA_NODE_ID = "extra_node_id"
        const val NOTIFICATION_ID = 1001
        private const val TAG = "AeroBoxVpnService"
        private const val MAX_RECONNECT_ATTEMPTS = 10

        val isServiceActive: StateFlow<Boolean> = VpnStateManager.serviceActive
    }

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val startMutex = Mutex()
    private val configResolver by lazy {
        VpnConfigResolver(applicationContext)
    }
    private var vpnInterface: ParcelFileDescriptor? = null
    private var speedTickerJob: Job? = null
    private var commandServer: CommandServer? = null
    private var receiverRegistered = false

    private var lastNodeId: Long = -1L
    private var userRequestedStop = false
    private var reconnectAttempts = 0
    private var hasIpv6Tun = false
    private var cachedConnectedNode: ProxyNode? = null

    private data class StartRequest(
        val node: ProxyNode,
        val config: String
    )

    private fun nodeDisplayName(node: ProxyNode?): String {
        return node?.name?.takeIf { it.isNotBlank() } ?: "unnamed node"
    }

    private fun nodeSummary(node: ProxyNode?): String {
        val type = node?.type?.name ?: "UNKNOWN"
        return "${nodeDisplayName(node)} [$type]"
    }

    private fun logInfo(message: String) {
        Log.w(TAG, message)
        RuntimeLogBuffer.append("info", message)
    }

    private fun logWarn(message: String) {
        Log.w(TAG, message)
        RuntimeLogBuffer.append("warn", message)
    }

    private fun logError(message: String, throwable: Throwable? = null) {
        if (throwable != null) {
            Log.e(TAG, message, throwable)
        } else {
            Log.e(TAG, message)
        }
        RuntimeLogBuffer.append("error", message)
    }

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
            ACTION_START, ACTION_SWITCH, ACTION_RELOAD -> {
                val config = intent.getStringExtra(EXTRA_CONFIG)?.takeIf { it.isNotBlank() }
                val nodeId = intent.getLongExtra(EXTRA_NODE_ID, -1L).takeIf { it > 0L }
                userRequestedStop = false
                reconnectAttempts = 0
                if (nodeId != null) {
                    lastNodeId = nodeId
                }
                when (intent.action) {
                    ACTION_SWITCH -> RuntimeLogBuffer.append("info", "Switching node: reloading service")
                    ACTION_RELOAD -> RuntimeLogBuffer.append("info", "Reloading service with current settings")
                }
                startVpn(config, nodeId)
            }
            ACTION_STOP -> {
                userRequestedStop = true
                stopService("Stopping service: ACTION_STOP intent")
                stopSelf()
            }
        }
        return START_STICKY
    }

    // ─── VPN Lifecycle ───

    private fun startVpn(providedConfig: String? = null, requestedNodeId: Long? = null) {
        VpnStateManager.updateServiceActive(true)
        serviceScope.launch {
            startMutex.withLock {
                runCatching {
                    logInfo("Starting sing-box service")
                    startForeground(
                        NOTIFICATION_ID,
                        buildNotification(connected = false)
                    )

                    val startRequest = prepareStartRequest(
                        providedConfig = providedConfig,
                        requestedNodeId = requestedNodeId
                    ) ?: run {
                        stopService("Stopping service after config preparation failure")
                        return@launch
                    }

                    cachedConnectedNode = startRequest.node
                    lastNodeId = startRequest.node.id
                    logInfo("Prepared start request for ${nodeSummary(startRequest.node)}")
                    notificationManager.notify(
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
                        DefaultNetworkMonitor.start()
                    }

                    val server = commandServer ?: CommandServer(this@AeroBoxVpnService, this@AeroBoxVpnService).also {
                        it.start()
                        commandServer = it
                    }

                    val overrides = buildOverrideOptions()
                    logInfo("Invoking startOrReloadService for ${nodeSummary(startRequest.node)}")
                    server.startOrReloadService(startRequest.config, overrides)
                    logInfo("startOrReloadService returned for ${nodeSummary(startRequest.node)}")
                    startSpeedTicker()

                }.onFailure { e ->
                    logError("startVpn failed: ${e.message ?: e}", e)
                    VpnStateManager.updateLastError(e.message ?: e.toString())
                    stopService("Stopping service after start failure")
                }
            } // startMutex.withLock
        }
    }

    private suspend fun prepareStartRequest(
        providedConfig: String?,
        requestedNodeId: Long?
    ): StartRequest? {
        val node = configResolver.resolveNodeById(
            nodeId = requestedNodeId ?: lastNodeId.takeIf { it > 0L },
            fallbackToSelected = true
        )
        if (node == null) {
            val error = "No node available"
            logWarn(error)
            VpnStateManager.updateLastError(error)
            return null
        }

        val config = providedConfig ?: configResolver.buildConfig(node)
        val configError = configResolver.validateConfig(config)
        if (configError != null) {
            logWarn("Config validation failed for ${nodeSummary(node)}: $configError")
            VpnStateManager.updateLastError(configError)
            return null
        }

        return StartRequest(node = node, config = config)
    }

    private suspend fun buildOverrideOptions(): OverrideOptions {
        return OverrideOptions().apply {
            // Per-app proxy
            val perAppEnabled = PreferenceManager.perAppProxyEnabledFlow(applicationContext).first()
            if (perAppEnabled) {
                val mode = PreferenceManager.perAppProxyModeFlow(applicationContext).first()
                val packages = PreferenceManager.perAppProxyPackagesFlow(applicationContext).first()
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

    private suspend fun resolveCurrentNode(): ProxyNode? {
        return configResolver.resolveNodeById(
            nodeId = lastNodeId.takeIf { it > 0L },
            fallbackToSelected = true
        )
    }

    private fun stopService(reason: String = "Stopping service") {
        logInfo(reason)
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
        VpnStateManager.resetTrafficSession()
        cachedConnectedNode = null

        stopForeground(STOP_FOREGROUND_REMOVE)
    }

    // ─── CommandServerHandler callbacks ───

    override fun serviceStop() {
        val message = if (userRequestedStop) "Service stopped" else "Service stopped unexpectedly"
        if (userRequestedStop) logInfo(message) else logWarn(message)
        // Called by libbox when the service stops (may be unexpected)
        VpnStateManager.updateServiceActive(false)
        VpnStateManager.updateConnectionState(false, null)

        if (!userRequestedStop) {
            notificationManager.notify(
                NOTIFICATION_ID,
                buildNotification(
                    contentText = getString(R.string.notification_connecting),
                    connected = false
                )
            )
            // Unexpected disconnect — try auto-reconnect
            attemptReconnect()
        } else {
            stopService("Stopping service after serviceStop callback")
        }
    }

    override fun serviceReload() {
        logInfo("Service reloaded")
        serviceScope.launch {
            val currentNode = resolveCurrentNode()
            VpnStateManager.updateCurrentNode(currentNode)
            if (VpnStateManager.vpnState.value.isConnected) {
                val state = VpnStateManager.vpnState.value
                val upSpeed = NetworkUtils.formatBytes(state.uploadSpeed) + "/s"
                val downSpeed = NetworkUtils.formatBytes(state.downloadSpeed) + "/s"
                val notification = buildNotification(
                    contentText = "↑ $upSpeed  ↓ $downSpeed",
                    connected = true
                )
                val nm = notificationManager
                nm.notify(NOTIFICATION_ID, notification)
            }
        }
    }

    override fun getSystemProxyStatus(): SystemProxyStatus {
        return SystemProxyStatus()
    }

    override fun setSystemProxyEnabled(enabled: Boolean) {
        // Not applicable to VPN mode
    }

    override fun writeDebugMessage(message: String) {
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
        hasIpv6Tun = false

        val builder = Builder()
            .setSession("AeroBox")
            .setMtu(options.mtu)

        // Read addresses
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

        hasIpv6Tun = inet6Addresses.isNotEmpty()
        builder.setMetered(false)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
            DefaultNetworkMonitor.defaultNetwork?.let { network ->
                runCatching {
                    builder.setUnderlyingNetworks(arrayOf(network))
                }.onFailure {
                    RuntimeLogBuffer.append(
                        "debug",
                        "Builder setUnderlyingNetworks skipped: ${it.message ?: it}"
                    )
                }
            }
        }

        if (options.autoRoute) {
            val inet4Routes = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                readTunAddressList(options, "inet4RouteAddress")
            } else {
                readTunAddressList(options, "inet4RouteRange")
            }
            val inet6Routes = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                readTunAddressList(options, "inet6RouteAddress")
            } else {
                readTunAddressList(options, "inet6RouteRange")
            }
            val inet4ExcludedRoutes = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                readTunAddressList(options, "inet4RouteExcludeAddress")
            } else {
                emptyList()
            }
            val inet6ExcludedRoutes = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                readTunAddressList(options, "inet6RouteExcludeAddress")
            } else {
                emptyList()
            }
            val vpnDns = options.dnsServerAddress.value.trim().takeIf { it.isNotEmpty() }

            vpnDns?.let { builder.addDnsServer(it) }
            // Add an IPv6 DNS server so Android advertises IPv6 capability
            // on the VPN network. sing-box hijacks all DNS traffic, so the
            // actual address doesn't matter – it just needs to be routable
            // through the TUN.
            if (hasIpv6Tun) {
                inet6Addresses.firstOrNull()?.let { (address, _) ->
                    runCatching { builder.addDnsServer(address) }
                }
            }

            if (inet4Routes.isNotEmpty()) {
                inet4Routes.forEach { (address, prefix) ->
                    builder.addRouteCompat(address, prefix)
                }
            } else if (inet4Addresses.isNotEmpty()) {
                builder.addRoute("0.0.0.0", 0)
            }
            if (inet6Routes.isNotEmpty()) {
                inet6Routes.forEach { (address, prefix) ->
                    builder.addRouteCompat(address, prefix)
                }
            } else if (inet6Addresses.isNotEmpty()) {
                builder.addRoute("::", 0)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                inet4ExcludedRoutes.forEach { (address, prefix) ->
                    toIpPrefixOrNull(address, prefix)?.let { builder.excludeRoute(it) }
                }
                inet6ExcludedRoutes.forEach { (address, prefix) ->
                    toIpPrefixOrNull(address, prefix)?.let { builder.excludeRoute(it) }
                }
            }
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
        val connectedNode = cachedConnectedNode
        VpnStateManager.clearLastError()
        VpnStateManager.updateConnectionState(true, connectedNode)
        logInfo("VPN interface established for ${nodeSummary(connectedNode)}")
        val initialSpeedText = "↑ 0 B/s  ↓ 0 B/s"
        val notification = buildNotification(contentText = initialSpeedText, connected = true)
        notificationManager.notify(NOTIFICATION_ID, notification)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
            updateUnderlyingNetwork(DefaultNetworkMonitor.defaultNetwork)
        }
        return pfd.fd
    }

    private fun updateUnderlyingNetwork(network: Network?) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP_MR1) return
        runCatching {
            setUnderlyingNetworks(network?.let { arrayOf(it) })
        }.onFailure {
            RuntimeLogBuffer.append(
                "debug",
                "setUnderlyingNetworks skipped: ${it.message ?: it}"
            )
        }
    }

    private fun Builder.addRouteCompat(address: String, prefix: Int) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            toIpPrefixOrNull(address, prefix)?.let(::addRoute) ?: addRoute(address, prefix)
        } else {
            addRoute(address, prefix)
        }
    }

    private fun toIpPrefixOrNull(address: String, prefix: Int): IpPrefix? {
        val normalized = address
            .trim()
            .removePrefix("[")
            .removeSuffix("]")
            .substringBefore('%')
            .trim()
        if (normalized.isEmpty()) return null
        return runCatching {
            IpPrefix(InetAddress.getByName(normalized), prefix)
        }.getOrNull()
    }

    private fun readTunAddressList(options: TunOptions, memberName: String): List<Pair<String, Int>> {
        val iterator = resolveNoArgMember(options, memberName) ?: return emptyList()
        val pairs = mutableListOf<Pair<String, Int>>()
        while (iteratorHasNext(iterator)) {
            val item = iteratorNext(iterator) ?: break
            val address = readStringMember(item, "address") ?: continue
            val prefix = readIntMember(item, "prefix") ?: continue
            pairs += address to prefix
        }
        return pairs
    }

    private fun resolveNoArgMember(target: Any, memberName: String): Any? {
        val getterName = "get" + memberName.replaceFirstChar { it.uppercaseChar() }
        return runCatching {
            target.javaClass.methods.firstOrNull { method ->
                method.parameterCount == 0 && (method.name == memberName || method.name == getterName)
            }?.invoke(target)
        }.getOrNull()
    }

    private fun iteratorHasNext(iterator: Any): Boolean {
        return runCatching {
            iterator.javaClass.methods.firstOrNull { method ->
                method.parameterCount == 0 && method.name == "hasNext"
            }?.invoke(iterator) as? Boolean
        }.getOrNull() == true
    }

    private fun iteratorNext(iterator: Any): Any? {
        return runCatching {
            iterator.javaClass.methods.firstOrNull { method ->
                method.parameterCount == 0 && method.name == "next"
            }?.invoke(iterator)
        }.getOrNull()
    }

    private fun readStringMember(target: Any, memberName: String): String? {
        return resolveNoArgMember(target, memberName)?.toString()?.takeIf { it.isNotBlank() }
    }

    private fun readIntMember(target: Any, memberName: String): Int? {
        val value = resolveNoArgMember(target, memberName) ?: return null
        return when (value) {
            is Int -> value
            is Number -> value.toInt()
            else -> value.toString().toIntOrNull()
        }
    }

    // ─── Notification ───

    private val notificationManager by lazy {
        getSystemService(NOTIFICATION_SERVICE) as android.app.NotificationManager
    }
    private val contentPendingIntent by lazy {
        PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
    }
    private val stopPendingIntent by lazy {
        val stopIntent = Intent(ACTION_STOP).setPackage(packageName)
        PendingIntent.getBroadcast(
            this, 101, stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
    }
    private val switchPendingIntent by lazy {
        val switchIntent = Intent(this, NotificationSwitchActivity::class.java).apply {
            addFlags(
                Intent.FLAG_ACTIVITY_NEW_TASK or
                    Intent.FLAG_ACTIVITY_EXCLUDE_FROM_RECENTS or
                    Intent.FLAG_ACTIVITY_NO_HISTORY
            )
        }
        PendingIntent.getActivity(
            this, 102, switchIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
    }

    private fun buildNotification(contentText: String = "", connected: Boolean = false): Notification {
        val displayNode = if (connected) {
            VpnStateManager.vpnState.value.currentNode ?: cachedConnectedNode
        } else {
            cachedConnectedNode ?: VpnStateManager.vpnState.value.currentNode
        }
        val title = displayNode
            ?.name
            ?.takeIf { it.isNotBlank() }
            ?: getString(R.string.notification_title)
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
            .setContentIntent(contentPendingIntent)
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
        speedTickerJob = serviceScope.launch {
            val trackedOutbounds = listOf("proxy", "direct")
            val initialStats = waitForOutboundStats(trackedOutbounds)
                ?: SingBoxNative.OutboundTrafficStats(0L, 0L)
            var prevUpload = initialStats.uploadBytes
            var prevDownload = initialStats.downloadBytes

            while (isActive && VpnStateManager.serviceActive.value) {
                delay(1000)
                val currentStats = SingBoxNative.queryV2RayOutboundStats(
                    apiAddress = ConfigGenerator.V2RAY_API_LISTEN,
                    outboundTags = trackedOutbounds
                )
                val currentUpload = currentStats?.uploadBytes ?: prevUpload
                val currentDownload = currentStats?.downloadBytes ?: prevDownload
                val uploadSpeed = (currentUpload - prevUpload).coerceAtLeast(0L)
                val downloadSpeed = (currentDownload - prevDownload).coerceAtLeast(0L)

                VpnStateManager.updateTrafficStats(
                    uploadSpeed = uploadSpeed,
                    downloadSpeed = downloadSpeed,
                    uploadDelta = uploadSpeed,
                    downloadDelta = downloadSpeed
                )

                prevUpload = currentUpload
                prevDownload = currentDownload

                val text = "↑ ${NetworkUtils.formatBytes(uploadSpeed)}/s  ↓ ${NetworkUtils.formatBytes(downloadSpeed)}/s"
                val notification = buildNotification(contentText = text, connected = true)
                notificationManager.notify(NOTIFICATION_ID, notification)
            }
        }
    }

    private suspend fun waitForOutboundStats(
        trackedOutbounds: List<String>
    ): SingBoxNative.OutboundTrafficStats? {
        repeat(6) { attempt ->
            val stats = SingBoxNative.queryV2RayOutboundStats(
                apiAddress = ConfigGenerator.V2RAY_API_LISTEN,
                outboundTags = trackedOutbounds,
                logErrors = attempt == 5
            )
            if (stats != null) return stats
            delay(250)
        }
        return null
    }

    override fun onDestroy() {
        userRequestedStop = true
        stopService("Stopping service: onDestroy")
        serviceScope.cancel()
        super.onDestroy()
    }

    // ─── Auto-Reconnect ───

    private fun attemptReconnect() {
        val reconnectNodeId = lastNodeId.takeIf { it > 0L }
        serviceScope.launch {
            val autoReconnect = PreferenceManager.autoReconnectFlow(applicationContext).first()
            if (!autoReconnect) {
                stopService("Stopping service: auto reconnect disabled")
                return@launch
            }

            reconnectAttempts++
            if (reconnectAttempts > MAX_RECONNECT_ATTEMPTS) {
                logWarn("Max reconnect attempts ($MAX_RECONNECT_ATTEMPTS) reached, giving up")
                stopService("Stopping service: max reconnect attempts reached")
                return@launch
            }
            val backoffMs = 1000L * (1L shl (reconnectAttempts - 1).coerceAtMost(5))
            Log.i(TAG, "Auto-reconnect attempt $reconnectAttempts in ${backoffMs}ms")
            RuntimeLogBuffer.append("warn", "Auto-reconnect attempt $reconnectAttempts in ${backoffMs}ms")
            delay(backoffMs)

            if (userRequestedStop) return@launch
            startVpn(requestedNodeId = reconnectNodeId)
        }
    }
}
