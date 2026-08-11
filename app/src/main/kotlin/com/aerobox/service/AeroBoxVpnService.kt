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
import io.nekohasekai.libbox.SystemProxyStatus
import io.nekohasekai.libbox.TunOptions
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
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
        const val NOTIFICATION_ID = 1001
        private const val TAG = "AeroBoxVpnService"
        private const val MAX_RECONNECT_ATTEMPTS = 10
        private val TRAFFIC_OUTBOUND_TAGS = listOf("proxy", "direct")
        // Matches "INFO[0000] ", "ERROR[0001] ", etc.
        private val coreLogBracketRegex = Regex("""(?i)(FATAL|PANIC|ERROR|WARN(?:ING)?|INFO|DEBUG|TRACE)\[\d{4}\]\s?""")
        // Matches "error: ", "warn: ", etc.
        private val coreLogColonRegex = Regex("""(?i)(fatal|panic|error|warn(?:ing)?|info|debug|trace):\s?""")

        val isServiceActive: StateFlow<Boolean> = VpnStateManager.serviceActive

        @Volatile
        private var activeServiceReference: WeakReference<AeroBoxVpnService>? = null

        internal fun activePlatformInterface(): PlatformInterfaceWrapper? {
            return activeServiceReference?.get()
        }
    }

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val startMutex = Mutex()
    private val configResolver by lazy {
        VpnConfigResolver(applicationContext)
    }
    private var vpnInterface: ParcelFileDescriptor? = null
    private var speedTickerJob: Job? = null
    private var reconnectJob: Job? = null
    private var notificationLanguageJob: Job? = null
    private var commandServer: CommandServer? = null
    private var receiverRegistered = false
    @Volatile
    private var notificationLanguageTag = AppLocaleManager.SYSTEM_LANGUAGE_TAG

    // Guards mutable tunnel state that is accessed from both the serviceScope
    // coroutines and the libbox JNI callback thread (openTun).
    private val tunnelLock = Any()
    private var lastNodeId: Long = -1L
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
        activeServiceReference = WeakReference(this)
    }

    private fun nodeDisplayName(node: ProxyNode?): String {
        return node?.name?.takeIf { it.isNotBlank() } ?: "unnamed node"
    }

    private fun nodeSummary(node: ProxyNode?): String {
        val type = node?.type?.name ?: "UNKNOWN"
        return "${nodeDisplayName(node)} [$type]"
    }

    /**
     * Parse sing-box core log level from message prefix.
     * Formats: "INFO[0000] ...", "ERROR ...", "info: ...", plain text, etc.
     */
    private fun parseCoreLogLevel(message: String): Pair<String, String> {
        val trimmed = message.trimStart()
        // "FATAL[0000] msg", "ERROR[0001] msg", "WARN[0002] msg", "INFO[0003] msg", "DEBUG[0004] msg"
        val bracketMatch = coreLogBracketRegex.matchAt(trimmed, 0)
        if (bracketMatch != null) {
            val tag = bracketMatch.groupValues[1].uppercase()
            val body = trimmed.substring(bracketMatch.range.last + 1).trimStart()
            return mapCoreLevel(tag) to body
        }
        // "error: msg", "warn: msg", etc.
        val colonMatch = coreLogColonRegex.matchAt(trimmed, 0)
        if (colonMatch != null) {
            val tag = colonMatch.groupValues[1].uppercase()
            val body = trimmed.substring(colonMatch.range.last + 1).trimStart()
            return mapCoreLevel(tag) to body
        }
        return "debug" to trimmed
    }

    private fun mapCoreLevel(tag: String): String = when (tag) {
        "FATAL", "PANIC" -> "error"
        "ERROR" -> "error"
        "WARN", "WARNING" -> "warn"
        "INFO" -> "info"
        "DEBUG", "TRACE" -> "debug"
        else -> "debug"
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
                reconnectJob?.cancel()
                reconnectJob = null
                startNotificationLanguageObserver()
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
            else -> {
                Log.w(TAG, "Ignoring VPN service start without a supported action")
                stopSelf(startId)
            }
        }
        return START_NOT_STICKY
    }

    // ─── VPN Lifecycle ───

    private fun startVpn(providedConfig: String? = null, requestedNodeId: Long? = null) {
        VpnStateManager.updateServiceActive(true)
        serviceScope.launch {
            startMutex.withLock {
                try {
                    refreshNotificationLanguage()
                    logInfo("Starting sing-box service")
                    startForeground(
                        NOTIFICATION_ID,
                        buildNotification(connected = false)
                    )

                    val startRequest = prepareStartRequest(
                        providedConfig = providedConfig,
                        requestedNodeId = requestedNodeId
                    )

                    synchronized(tunnelLock) {
                        cachedConnectedNode = startRequest.node
                        lastNodeId = startRequest.node.id
                    }
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
                        it.start()
                        commandServer = it
                    }

                    val overrides = buildOverrideOptions()
                    logInfo("Invoking startOrReloadService for ${nodeSummary(startRequest.node)}")
                    server.startOrReloadService(startRequest.config, overrides)
                    logInfo("startOrReloadService returned for ${nodeSummary(startRequest.node)}")
                    startSpeedTicker()
                    VpnStateManager.reportServiceOperation(success = true)
                } catch (e: Throwable) {
                    logError("startVpn failed: ${e.message ?: e}", e)
                    VpnStateManager.reportServiceOperation(
                        success = false,
                        error = e.message ?: e.toString()
                    )
                    handleStartFailure(
                        error = e,
                        allowReconnect = e !is NonRetryableStartException
                    )
                }
            } // startMutex.withLock
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
        val configError = configResolver.validateConfig(config)
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

    private fun stopService(reason: String) {
        logInfo(reason)
        reconnectJob?.cancel()
        reconnectJob = null
        releaseRuntimeResources(
            closeRunningService = true,
            stopNetworkMonitor = true,
            unregisterReceiver = true,
            stopForegroundNotification = true,
            clearCachedNode = true
        )

        VpnStateManager.updateServiceActive(false)
        VpnStateManager.updateConnectionState(false, null)
        VpnStateManager.resetTrafficSession()
    }

    private fun releaseRuntimeResources(
        closeRunningService: Boolean,
        stopNetworkMonitor: Boolean,
        unregisterReceiver: Boolean,
        stopForegroundNotification: Boolean,
        clearCachedNode: Boolean
    ) {
        speedTickerJob?.cancel()
        speedTickerJob = null
        SingBoxNative.closeV2RayOutboundStats()

        if (stopNetworkMonitor) {
            DefaultNetworkMonitor.stop()
        }

        if (closeRunningService) {
            runCatching { commandServer?.closeService() }
        }
        runCatching {
            commandServer?.close()
            commandServer = null
        }

        synchronized(tunnelLock) {
            runCatching {
                vpnInterface?.close()
                vpnInterface = null
            }

            if (clearCachedNode) {
                cachedConnectedNode = null
            }
        }

        if (unregisterReceiver && receiverRegistered) {
            runCatching { unregisterReceiver(closeReceiver) }
            receiverRegistered = false
        }

        if (stopForegroundNotification) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        }
    }

    // ─── CommandServerHandler callbacks ───

    override fun serviceStop() {
        val message = if (userRequestedStop) "Service stopped" else "Service stopped unexpectedly"
        if (userRequestedStop) logInfo(message) else logWarn(message)
        if (!userRequestedStop) {
            serviceScope.launch {
                startMutex.withLock {
                    handleStartFailure(
                        error = IllegalStateException(message),
                        allowReconnect = true
                    )
                }
            }
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
        val (level, body) = parseCoreLogLevel(message)
        RuntimeLogBuffer.append(level, body)
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
            val vpnDns = readStringIteratorValue(options.dnsServerAddress)

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
        val connectedNode: ProxyNode?
        synchronized(tunnelLock) {
            // Close any previous fd to prevent leaks during rapid switch
            runCatching { vpnInterface?.close() }
            vpnInterface = pfd
            reconnectAttempts = 0
            connectedNode = cachedConnectedNode
        }
        VpnStateManager.clearLastError()
        VpnStateManager.updateConnectionState(true, connectedNode)
        logInfo("VPN interface established for ${nodeSummary(connectedNode)}")
        val initialSpeedText = "↑ 0 B/s  ↓ 0 B/s"
        val notification = buildNotification(contentText = initialSpeedText, connected = true)
        notificationManager.notify(NOTIFICATION_ID, notification)
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
        iterator: Any
    ): List<Pair<String, Int>> {
        val result = mutableListOf<Pair<String, Int>>()
        while (iteratorHasNext(iterator)) {
            val addr = iteratorNext(iterator) ?: break
            val address = readStringMember(addr, "address") ?: continue
            val prefix = readIntMember(addr, "prefix") ?: continue
            result += address to prefix
        }
        return result
    }

    // ─── Cached Reflection Helpers ───

    // Cache resolved Method objects keyed by (Class, methodName) to avoid
    // scanning the methods array on every invocation.
    private data class CachedMethod(val method: java.lang.reflect.Method?)

    private val methodCache = java.util.concurrent.ConcurrentHashMap<Pair<Class<*>, String>, CachedMethod>()

    private fun cachedMethod(clazz: Class<*>, name: String): java.lang.reflect.Method? {
        return methodCache.getOrPut(clazz to name) {
            CachedMethod(clazz.methods.firstOrNull { it.parameterCount == 0 && it.name == name })
        }.method
    }

    private fun resolveNoArgMember(target: Any, memberName: String): Any? {
        val getterName = "get" + memberName.replaceFirstChar { it.uppercaseChar() }
        return runCatching {
            val method = cachedMethod(target.javaClass, memberName)
                ?: cachedMethod(target.javaClass, getterName)
            method?.invoke(target)
        }.getOrNull()
    }

    private fun iteratorHasNext(iterator: Any): Boolean {
        return runCatching {
            cachedMethod(iterator.javaClass, "hasNext")?.invoke(iterator) as? Boolean
        }.getOrNull() == true
    }

    private fun iteratorNext(iterator: Any): Any? {
        return runCatching {
            cachedMethod(iterator.javaClass, "next")?.invoke(iterator)
        }.getOrNull()
    }

    private fun readStringMember(target: Any, memberName: String): String? {
        return resolveNoArgMember(target, memberName)?.toString()?.takeIf { it.isNotBlank() }
    }

    private fun readStringIteratorValue(target: Any?): String? {
        if (target == null) return null
        if (target is String) return target.trim().takeIf { it.isNotEmpty() }

        readStringMember(target, "value")?.let { return it.trim().takeIf { value -> value.isNotEmpty() } }

        val values = mutableListOf<String>()
        while (iteratorHasNext(target)) {
            val value = iteratorNext(target)?.toString()?.trim()?.takeIf { it.isNotEmpty() } ?: continue
            values += value
        }
        return values.firstOrNull()
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

    private fun startSpeedTicker() {
        speedTickerJob?.cancel()
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
                if (currentStats == null) {
                    consecutiveStatsFailures++
                    if (consecutiveStatsFailures >= 5) {
                        val error = "Core health check failed: traffic API unavailable"
                        logWarn(error)
                        serviceScope.launch {
                            startMutex.withLock {
                                if (!userRequestedStop && VpnStateManager.serviceActive.value) {
                                    handleStartFailure(
                                        error = IllegalStateException(error),
                                        allowReconnect = true
                                    )
                                }
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
        userRequestedStop = true
        stopService("Stopping service: onDestroy")
        if (activeServiceReference?.get() === this) {
            activeServiceReference = null
        }
        serviceScope.cancel()
        super.onDestroy()
    }

    // ─── Auto-Reconnect ───

    private suspend fun handleStartFailure(error: Throwable, allowReconnect: Boolean) {
        val errorMessage = error.message?.takeIf { it.isNotBlank() } ?: error.toString()
        releaseRuntimeResources(
            closeRunningService = true,
            stopNetworkMonitor = true,
            unregisterReceiver = false,
            stopForegroundNotification = false,
            clearCachedNode = false
        )
        VpnStateManager.updateConnectionState(false, null)
        VpnStateManager.resetTrafficSession()

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
            stopSelf()
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
        scheduleReconnect(errorMessage)
    }

    private fun scheduleReconnect(lastError: String) {
        val reconnectNodeId = lastNodeId.takeIf { it > 0L }
        reconnectJob?.cancel()
        reconnectJob = serviceScope.launch {
            reconnectAttempts++
            val backoffMs = 1000L * (1L shl (reconnectAttempts - 1).coerceAtMost(5))
            val message = "Auto-reconnect attempt $reconnectAttempts in ${backoffMs}ms after: $lastError"
            Log.i(TAG, message)
            RuntimeLogBuffer.append("warn", message)
            delay(backoffMs)

            if (userRequestedStop) return@launch
            startVpn(requestedNodeId = reconnectNodeId)
        }
    }
}
