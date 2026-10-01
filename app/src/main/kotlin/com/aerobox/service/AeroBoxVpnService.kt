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
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import com.aerobox.AeroBoxApplication
import com.aerobox.MainActivity
import com.aerobox.NotificationSwitchActivity
import com.aerobox.R
import com.aerobox.core.config.ConfigGenerator
import com.aerobox.core.logging.RuntimeLogBuffer
import com.aerobox.core.native.SingBoxNative
import com.aerobox.data.model.ProxyNode
import com.aerobox.data.repository.VpnConfigResolver
import com.aerobox.utils.AppLocaleManager
import com.aerobox.utils.NetworkUtils
import com.aerobox.utils.PreferenceManager
import io.nekohasekai.libbox.CommandServer
import io.nekohasekai.libbox.CommandServerHandler
import io.nekohasekai.libbox.OverrideOptions
import io.nekohasekai.libbox.RoutePrefixIterator
import io.nekohasekai.libbox.SystemProxyStatus
import io.nekohasekai.libbox.TunOptions
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.net.InetAddress
import java.lang.ref.WeakReference

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
        const val EXTRA_OPERATION_ID = "extra_operation_id"
        const val NOTIFICATION_ID = 1001
        private const val TAG = "AeroBoxVpnService"
        private const val MAX_RECONNECT_ATTEMPTS = 10
        private val TRAFFIC_OUTBOUND_TAGS = listOf("proxy", "direct")

        @Volatile
        private var activeServiceReference: WeakReference<AeroBoxVpnService>? = null
        private var pendingCleanup: Job? = null

        internal fun activePlatformInterface(): PlatformInterfaceWrapper? {
            return activeServiceReference?.get()
        }
    }

    private val serviceJob = SupervisorJob()
    private val serviceScope = CoroutineScope(serviceJob + Dispatchers.IO)
    private val lifecycleMutex = Mutex()
    private var startJobs = SupervisorJob(serviceJob)
    private var previousCleanup: Job? = null
    private var latestStartId = 0
    @Volatile
    private var destroyed = false
    @Volatile
    private var requestRevision = 0L
    private var runtimeRevision = 0L
    private val configResolver by lazy {
        VpnConfigResolver(applicationContext)
    }
    private var vpnInterface: ParcelFileDescriptor? = null
    private var speedTickerJob: Job? = null
    @Volatile
    private var reconnectJob: Job? = null
    private var notificationLanguageJob: Job? = null
    @Volatile
    private var commandServer: CommandServer? = null
    private var receiverRegistered = false
    @Volatile
    private var notificationLanguageTag = AppLocaleManager.SYSTEM_LANGUAGE_TAG

    // Guards mutable tunnel state that is accessed from both the serviceScope
    // coroutines and the libbox JNI callback thread (openTun).
    private val tunnelLock = Any()
    private var lastNodeId: Long = -1L
    @Volatile
    private var userRequestedStop = false
    private var reconnectAttempts = 0
    private var hasIpv6Tun = false
    private var cachedConnectedNode: ProxyNode? = null

    private data class StartRequest(
        val node: ProxyNode,
        val config: String
    )

    private class NonRetryableStartException(message: String) : IllegalStateException(message)

    override fun onCreate() {
        super.onCreate()
        previousCleanup = pendingCleanup
        activeServiceReference = WeakReference(this)
    }

    private fun nodeDisplayName(node: ProxyNode?): String {
        return node?.name?.takeIf { it.isNotBlank() } ?: "unnamed node"
    }

    private fun nodeSummary(node: ProxyNode?): String {
        val type = node?.type?.name ?: "UNKNOWN"
        return "${nodeDisplayName(node)} [$type]"
    }

    private fun logInfo(message: String) {
        Log.i(TAG, message)
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
        // Include the root cause when it adds information beyond the top-level message
        val rootCause = throwable?.rootCauseMessage()
        val fullMessage = if (rootCause != null && message != rootCause && !message.contains(rootCause)) {
            "$message\n  caused by: $rootCause"
        } else {
            message
        }
        RuntimeLogBuffer.append("error", fullMessage)
    }

    private fun Throwable.rootCauseMessage(): String? {
        var current: Throwable = this
        while (true) {
            val cause = current.cause?.takeIf { it !== current } ?: break
            current = cause
        }
        return current.message?.takeIf { it.isNotBlank() }
    }

    private val closeReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            when (intent.action) {
                ACTION_STOP -> {
                    requestStop("Stopping service: notification action")
                }
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        latestStartId = startId
        when (intent?.action) {
            ACTION_START, ACTION_SWITCH, ACTION_RELOAD -> {
                startNotificationLanguageObserver()
                val config = intent.getStringExtra(EXTRA_CONFIG)?.takeIf { it.isNotBlank() }
                val nodeId = intent.getLongExtra(EXTRA_NODE_ID, -1L).takeIf { it > 0L }
                val operationId = intent.getLongExtra(EXTRA_OPERATION_ID, 0L)
                when (intent.action) {
                    ACTION_SWITCH -> RuntimeLogBuffer.append("info", "Switching node: reloading service")
                    ACTION_RELOAD -> RuntimeLogBuffer.append("info", "Reloading service with current settings")
                }
                startVpn(config, nodeId, operationId, resetReconnectAttempts = true)
            }
            ACTION_STOP -> {
                requestStop("Stopping service: ACTION_STOP intent")
            }
            else -> {
                Log.w(TAG, "Ignoring VPN service start without a supported action")
                stopSelf(startId)
            }
        }
        return START_NOT_STICKY
    }

    // ─── VPN Lifecycle ───

    // Queue lifecycle operations on Main in command order; run native work on IO.
    private fun launchLifecycleOperation(
        parent: Job = serviceJob,
        block: suspend () -> Unit
    ): Job = serviceScope.launch(Dispatchers.Main.immediate + parent) {
        previousCleanup?.join()
        previousCleanup = null
        lifecycleMutex.withLock {
            withContext(Dispatchers.IO) { block() }
        }
    }

    private fun requestStop(reason: String) {
        val revision = ++requestRevision
        val startId = latestStartId
        userRequestedStop = true
        startJobs.cancel(CancellationException(reason))
        reconnectJob?.cancel()
        reconnectJob = null
        // Coroutine cancellation cannot interrupt JNI. closeService cancels the native startup context.
        val server = commandServer
        val interrupt = serviceScope.launch {
            runCatching { server?.closeService() }
        }
        launchLifecycleOperation {
            interrupt.join()
            stopService(reason)
            withContext(Dispatchers.Main.immediate) {
                if (!destroyed && requestRevision == revision) stopSelfResult(startId)
            }
        }
    }

    private fun startVpn(
        providedConfig: String? = null,
        requestedNodeId: Long? = null,
        operationId: Long = 0L,
        resetReconnectAttempts: Boolean = false
    ) {
        val revision = ++requestRevision
        reconnectJob?.cancel()
        reconnectJob = null
        if (!startJobs.isActive) startJobs = SupervisorJob(serviceJob)
        try {
            startForeground(NOTIFICATION_ID, buildNotification(connected = false))
        } catch (error: Exception) {
            VpnStateManager.reportServiceOperation(operationId, success = false, error = error.message)
            requestStop("Unable to start foreground VPN service")
            return
        }
        VpnStateManager.updateServiceActive(true)
        launchLifecycleOperation(startJobs) {
            userRequestedStop = false
            runtimeRevision = revision
            if (resetReconnectAttempts) reconnectAttempts = 0
            VpnStateManager.updateServiceActive(true)
            try {
                refreshNotificationLanguage()
                // Re-establish foreground state after an earlier queued stop or instance cleanup.
                startForeground(NOTIFICATION_ID, buildNotification(connected = false))
                logInfo("Starting sing-box service")

                val startRequest = prepareStartRequest(
                    providedConfig = providedConfig,
                    requestedNodeId = requestedNodeId
                )

                synchronized(tunnelLock) {
                    cachedConnectedNode = startRequest.node
                    lastNodeId = startRequest.node.id
                }
                logInfo("Prepared start request for ${nodeSummary(startRequest.node)}")
                notificationManager.notify(NOTIFICATION_ID, buildNotification(connected = false))

                if (!receiverRegistered) {
                    val filter = IntentFilter(ACTION_STOP)
                    ContextCompat.registerReceiver(
                        this@AeroBoxVpnService,
                        closeReceiver,
                        filter,
                        ContextCompat.RECEIVER_NOT_EXPORTED
                    )
                    receiverRegistered = true
                }

                DefaultNetworkMonitor.setNetworkChangedCallback(::updateUnderlyingNetwork)
                DefaultNetworkMonitor.start()

                val server = commandServer ?: CommandServer(this@AeroBoxVpnService, this@AeroBoxVpnService).also {
                    commandServer = it
                    it.start()
                }

                val overrides = buildOverrideOptions()
                stopSpeedTicker()
                currentCoroutineContext().ensureActive()
                logInfo("Invoking startOrReloadService for ${nodeSummary(startRequest.node)}")
                server.startOrReloadService(startRequest.config, overrides)
                currentCoroutineContext().ensureActive()
                logInfo("startOrReloadService returned for ${nodeSummary(startRequest.node)}")
                reconnectAttempts = 0
                VpnStateManager.updateConnectionState(true, startRequest.node)
                notificationManager.notify(NOTIFICATION_ID, buildNotification(connected = true))
                startSpeedTicker()
                VpnStateManager.reportServiceOperation(operationId, success = true, node = startRequest.node)
            } catch (error: CancellationException) {
                throw error
            } catch (e: Throwable) {
                currentCoroutineContext().ensureActive()
                logError("startVpn failed: ${e.message ?: e}", e)
                handleStartFailure(
                    error = e,
                    allowReconnect = e !is NonRetryableStartException,
                    revision = revision,
                    operationId = operationId
                )
            }
        }.invokeOnCompletion { error ->
            if (error != null) {
                VpnStateManager.reportServiceOperation(
                    id = operationId,
                    success = false,
                    cancelled = error is CancellationException,
                    error = error.message
                )
            }
        }
    }

    private suspend fun prepareStartRequest(
        providedConfig: String?,
        requestedNodeId: Long?
    ): StartRequest {
        val node = configResolver.resolveNodeById(
            nodeId = requestedNodeId ?: lastNodeId.takeIf { it > 0L },
            fallbackToSelected = true
        )
        if (node == null) {
            val error = "No node available"
            logWarn(error)
            throw NonRetryableStartException(error)
        }

        val config = providedConfig ?: configResolver.buildConfig(node)
        // Configs supplied by VpnRepository have already passed the native check.
        val configError = if (providedConfig == null) configResolver.validateConfig(config) else null
        if (configError != null) {
            logWarn("Config validation failed for ${nodeSummary(node)}: $configError")
            throw NonRetryableStartException(configError)
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

    private suspend fun stopService(reason: String) {
        logInfo(reason)
        reconnectJob?.cancel()
        reconnectJob = null
        releaseRuntimeResources(stopping = true)

        VpnStateManager.updateServiceActive(false)
        VpnStateManager.updateConnectionState(false, null)
        VpnStateManager.resetTrafficSession()
    }

    private suspend fun releaseRuntimeResources(stopping: Boolean) {
        stopSpeedTicker()
        DefaultNetworkMonitor.stop()

        val server = commandServer
        commandServer = null
        runCatching { server?.closeService() }
        runCatching { server?.close() }

        synchronized(tunnelLock) {
            runCatching {
                vpnInterface?.close()
                vpnInterface = null
            }

            if (stopping) {
                cachedConnectedNode = null
            }
        }

        if (stopping && receiverRegistered) {
            runCatching { unregisterReceiver(closeReceiver) }
            receiverRegistered = false
        }

        if (stopping) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        }
    }

    // ─── CommandServerHandler callbacks ───

    override fun serviceStop() {
        val message = if (userRequestedStop) "Service stopped" else "Service stopped unexpectedly"
        if (userRequestedStop) logInfo(message) else logWarn(message)
        if (!userRequestedStop) {
            val revision = requestRevision
            launchLifecycleOperation {
                if (!userRequestedStop && !destroyed && revision == requestRevision) {
                    handleStartFailure(
                        error = IllegalStateException(message),
                        allowReconnect = true,
                        revision = revision
                    )
                }
            }
        }
    }

    override fun serviceReload() {
        logInfo("Service reloaded")
        launchLifecycleOperation {
            if (userRequestedStop || destroyed) return@launchLifecycleOperation
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
        RuntimeLogBuffer.appendCore(message)
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
        check(!userRequestedStop && !destroyed) { "VPN start was cancelled" }
        if (prepare(this) != null) error("android: missing vpn permission")
        hasIpv6Tun = false

        val builder = Builder()
            .setSession("AeroBox")
            .setMtu(options.mtu)

        // Read addresses
        val inet4Addresses = drainRouteAddresses(options.inet4Address)
        inet4Addresses.forEach { (address, prefix) -> builder.addAddress(address, prefix) }

        val inet6Addresses = drainRouteAddresses(options.inet6Address)
        inet6Addresses.forEach { (address, prefix) -> builder.addAddress(address, prefix) }

        hasIpv6Tun = inet6Addresses.isNotEmpty()
        builder.setMetered(false)
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

        if (options.autoRoute) {
            val inet4Routes = drainRouteAddresses(options.inet4RouteAddress)
            val inet6Routes = drainRouteAddresses(options.inet6RouteAddress)
            val inet4ExcludedRoutes = drainRouteAddresses(options.inet4RouteExcludeAddress)
            val inet6ExcludedRoutes = drainRouteAddresses(options.inet6RouteExcludeAddress)
            val dnsServers = options.dnsServerAddress
            while (dnsServers.hasNext()) {
                builder.addDnsServer(dnsServers.next())
            }
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
        synchronized(tunnelLock) {
            if (userRequestedStop || destroyed) {
                pfd.close()
                error("VPN start was cancelled")
            }
            // Close any previous fd to prevent leaks during rapid switch
            runCatching { vpnInterface?.close() }
            vpnInterface = pfd
        }
        logInfo("VPN interface established for ${nodeSummary(cachedConnectedNode)}")
        updateUnderlyingNetwork(DefaultNetworkMonitor.defaultNetwork)
        return pfd.fd
    }

    private fun updateUnderlyingNetwork(network: Network?) {
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

    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
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

    private fun drainRouteAddresses(
        iterator: RoutePrefixIterator
    ): List<Pair<String, Int>> {
        val result = mutableListOf<Pair<String, Int>>()
        while (iterator.hasNext()) {
            val prefix = iterator.next()
            result += prefix.address() to prefix.prefix()
        }
        return result
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

    private fun startNotificationLanguageObserver() {
        if (notificationLanguageJob?.isActive == true) return
        notificationLanguageJob = serviceScope.launch {
            PreferenceManager.languageTagFlow(applicationContext).collect { languageTag ->
                notificationLanguageTag = AppLocaleManager.normalize(languageTag)
            }
        }
    }

    private suspend fun refreshNotificationLanguage() {
        notificationLanguageTag = AppLocaleManager.normalize(
            PreferenceManager.languageTagFlow(applicationContext).first()
        )
    }

    private fun notificationString(resId: Int, vararg formatArgs: Any) =
        AppLocaleManager.string(this, notificationLanguageTag, resId, *formatArgs)

    private fun buildNotification(contentText: String = "", connected: Boolean = false): Notification {
        val displayNode = if (connected) {
            VpnStateManager.vpnState.value.currentNode ?: cachedConnectedNode
        } else {
            cachedConnectedNode ?: VpnStateManager.vpnState.value.currentNode
        }
        val title = displayNode
            ?.name
            ?.takeIf { it.isNotBlank() }
            ?: notificationString(R.string.notification_title)
        val mergedContent = when {
            connected && contentText.isNotBlank() -> contentText
            connected -> "↑ 0 B/s  ↓ 0 B/s"
            contentText.isBlank() -> notificationString(R.string.notification_connecting)
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
                    notificationString(R.string.notification_action_switch),
                    switchPendingIntent
                )
                .addAction(
                    android.R.drawable.ic_media_pause,
                    notificationString(R.string.notification_action_stop),
                    stopPendingIntent
                )
        } else {
            builder.addAction(
                android.R.drawable.ic_media_pause,
                notificationString(R.string.notification_action_stop),
                stopPendingIntent
            )
        }

        return builder.build()
    }

    private suspend fun stopSpeedTicker() {
        val ticker = speedTickerJob
        speedTickerJob = null
        ticker?.cancel()
        SingBoxNative.closeV2RayOutboundStats()
        ticker?.join()
    }

    private fun startSpeedTicker() {
        val revision = runtimeRevision
        speedTickerJob = serviceScope.launch speedTicker@{
            val initialStats = waitForOutboundStats()
                ?: SingBoxNative.OutboundTrafficStats(0L, 0L)
            var prevUpload = initialStats.uploadBytes
            var prevDownload = initialStats.downloadBytes
            var previousSampleTime = SystemClock.elapsedRealtime()
            var consecutiveStatsFailures = 0

            while (isActive && VpnStateManager.serviceActive.value) {
                delay(1000)
                val currentStats = SingBoxNative.queryV2RayOutboundStats(
                    apiAddress = ConfigGenerator.V2RAY_API_LISTEN,
                    outboundTags = TRAFFIC_OUTBOUND_TAGS
                )
                currentCoroutineContext().ensureActive()
                if (currentStats == null) {
                    consecutiveStatsFailures++
                    if (consecutiveStatsFailures >= 5) {
                        val error = "Core health check failed: traffic API unavailable"
                        logWarn(error)
                        launchLifecycleOperation {
                            if (!userRequestedStop && !destroyed && runtimeRevision == revision &&
                                requestRevision == revision && VpnStateManager.serviceActive.value
                            ) {
                                handleStartFailure(
                                    error = IllegalStateException(error),
                                    allowReconnect = true,
                                    revision = revision
                                )
                            }
                        }
                        return@speedTicker
                    }
                } else {
                    consecutiveStatsFailures = 0
                }
                val sampleTime = SystemClock.elapsedRealtime()
                val currentUpload = currentStats?.uploadBytes ?: prevUpload
                val currentDownload = currentStats?.downloadBytes ?: prevDownload
                val uploadDelta = (currentUpload - prevUpload).coerceAtLeast(0L)
                val downloadDelta = (currentDownload - prevDownload).coerceAtLeast(0L)
                val elapsedMs = (sampleTime - previousSampleTime).coerceAtLeast(1L)
                val uploadSpeed = if (currentStats != null) uploadDelta * 1000L / elapsedMs else 0L
                val downloadSpeed = if (currentStats != null) downloadDelta * 1000L / elapsedMs else 0L

                VpnStateManager.updateTrafficStats(
                    uploadSpeed = uploadSpeed,
                    downloadSpeed = downloadSpeed,
                    uploadDelta = uploadDelta,
                    downloadDelta = downloadDelta
                )

                if (currentStats != null) {
                    prevUpload = currentUpload
                    prevDownload = currentDownload
                    previousSampleTime = sampleTime
                }

                val text = "↑ ${NetworkUtils.formatBytes(uploadSpeed)}/s  ↓ ${NetworkUtils.formatBytes(downloadSpeed)}/s"
                val notification = buildNotification(contentText = text, connected = true)
                notificationManager.notify(NOTIFICATION_ID, notification)
            }
        }
    }

    private suspend fun waitForOutboundStats(): SingBoxNative.OutboundTrafficStats? {
        repeat(6) { attempt ->
            val stats = SingBoxNative.queryV2RayOutboundStats(
                apiAddress = ConfigGenerator.V2RAY_API_LISTEN,
                outboundTags = TRAFFIC_OUTBOUND_TAGS,
                logErrors = attempt == 5
            )
            if (stats != null) return stats
            delay(250)
        }
        return null
    }

    override fun onDestroy() {
        destroyed = true
        requestRevision++
        userRequestedStop = true
        if (activeServiceReference?.get() === this) {
            activeServiceReference = null
        }
        serviceScope.cancel()
        // A replacement service must wait for this instance to release shared native resources.
        val cleanup = serviceScope.launch(NonCancellable + Dispatchers.Main.immediate) {
            previousCleanup?.join()
            withContext(Dispatchers.IO) { runCatching { commandServer?.closeService() } }
            lifecycleMutex.withLock {
                withContext(Dispatchers.IO) { stopService("Stopping service: onDestroy") }
            }
        }
        pendingCleanup = cleanup
        cleanup.invokeOnCompletion {
            if (pendingCleanup === cleanup) pendingCleanup = null
        }
        super.onDestroy()
    }

    // ─── Auto-Reconnect ───

    private suspend fun handleStartFailure(
        error: Throwable,
        allowReconnect: Boolean,
        revision: Long,
        operationId: Long = 0L
    ) {
        val errorMessage = error.message?.takeIf { it.isNotBlank() } ?: error.toString()
        releaseRuntimeResources(stopping = false)
        VpnStateManager.updateConnectionState(false, null)
        VpnStateManager.resetTrafficSession()
        VpnStateManager.reportServiceOperation(operationId, success = false, error = errorMessage)
        if (userRequestedStop || destroyed || requestRevision != revision) return

        val autoReconnect = allowReconnect && !userRequestedStop &&
            PreferenceManager.autoReconnectFlow(applicationContext).first()
        if (!autoReconnect || reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
            VpnStateManager.updateLastError(errorMessage)
            val reason = if (reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
                "Stopping service: max reconnect attempts reached"
            } else {
                "Stopping service after non-retryable start failure"
            }
            stopService(reason)
            withContext(Dispatchers.Main.immediate) {
                if (!destroyed && requestRevision == revision) stopSelfResult(latestStartId)
            }
            return
        }

        VpnStateManager.clearLastError()
        notificationManager.notify(
            NOTIFICATION_ID,
            buildNotification(
                contentText = notificationString(R.string.notification_connecting),
                connected = false
            )
        )
        scheduleReconnect(errorMessage, revision)
    }

    private fun scheduleReconnect(lastError: String, revision: Long) {
        val reconnectNodeId = lastNodeId.takeIf { it > 0L }
        reconnectJob?.cancel()
        reconnectAttempts++
        reconnectJob = serviceScope.launch {
            val backoffMs = 1000L * (1L shl (reconnectAttempts - 1).coerceAtMost(5))
            val message = "Auto-reconnect attempt $reconnectAttempts in ${backoffMs}ms after: $lastError"
            Log.i(TAG, message)
            RuntimeLogBuffer.append("warn", message)
            delay(backoffMs)

            withContext(Dispatchers.Main.immediate) {
                if (!userRequestedStop && !destroyed && requestRevision == revision) {
                    reconnectJob = null
                    startVpn(requestedNodeId = reconnectNodeId)
                }
            }
        }
    }
}
