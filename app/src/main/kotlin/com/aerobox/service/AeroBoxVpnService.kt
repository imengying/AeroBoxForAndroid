package com.aerobox.service

import android.app.Notification
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import android.os.SystemClock
import android.util.Log
import androidx.core.content.ContextCompat
import com.aerobox.appContainer
import com.aerobox.AeroBoxApplication
import com.aerobox.core.native.RustCoreNative
import com.aerobox.core.native.RustTunController
import com.aerobox.core.native.RustVpnSession
import com.aerobox.core.native.PhysicalNetwork
import com.aerobox.R
import com.aerobox.core.logging.RuntimeLogBuffer
import com.aerobox.core.native.RustCore
import com.aerobox.data.model.ProxyNode
import com.aerobox.utils.NetworkUtils
import com.aerobox.utils.PreferenceManager
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
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.lang.ref.WeakReference
import java.util.concurrent.atomic.AtomicLong

/** Android lifecycle and foreground state around the pure Rust VPN session. */
class AeroBoxVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.aerobox.action.START"
        const val ACTION_STOP = "com.aerobox.action.STOP"
        const val ACTION_SWITCH = "com.aerobox.action.SWITCH"
        const val ACTION_RELOAD = "com.aerobox.action.RELOAD"
        private const val ACTION_UPDATE_RESTART_POLICY = "com.aerobox.action.UPDATE_RESTART_POLICY"
        const val EXTRA_CONFIG = "extra_config"
        const val EXTRA_NODE_ID = "extra_node_id"
        const val EXTRA_OPERATION_ID = "extra_operation_id"
        const val EXTRA_STOP_REVISION = "extra_stop_revision"
        const val NOTIFICATION_ID = 1001
        private const val TAG = "AeroBoxVpnService"
        private const val MAX_RECONNECT_ATTEMPTS = 10

        @Volatile
        private var activeServiceReference: WeakReference<AeroBoxVpnService>? = null
        private var pendingCleanup: Job? = null

        internal fun activePlatformInterface(): RustCoreNative.PlatformCallbacks? {
            return activeServiceReference?.get()?.coreSession?.platform
        }

        suspend fun connectionSnapshot(): String = withContext(Dispatchers.IO) {
            val service = activeServiceReference?.get() ?: return@withContext "[]"
            service.lifecycleMutex.withLock { service.coreSession?.connectionSnapshot() ?: "[]" }
        }

        suspend fun closeTrackedConnection(id: String) = withContext(Dispatchers.IO) {
            val service = activeServiceReference?.get() ?: return@withContext
            service.lifecycleMutex.withLock { service.coreSession?.closeTrackedConnection(id) }
        }

        suspend fun cancelStartOperation(id: Long) = withContext(Dispatchers.Main.immediate) {
            val service = activeServiceReference?.get() ?: return@withContext
            if (service.activeOperationId.compareAndSet(id, 0L)) {
                service.requestStop("VPN reload timed out", userInitiated = false)
            }
        }
    }

    private val serviceJob = SupervisorJob()
    private val serviceScope = CoroutineScope(serviceJob + Dispatchers.IO)
    private val lifecycleMutex = Mutex()
    private var startJobs = SupervisorJob(serviceJob)
    private var previousCleanup: Job? = null
    private var latestStartId = 0
    @Volatile
    private var stickyRestartEnabled = false
    @Volatile
    private var destroyed = false
    @Volatile
    private var requestRevision = 0L
    private var runtimeRevision = 0L
    @Volatile
    private var stateGeneration = VpnStateManager.vpnState.value.generation
    private val activeOperationId = AtomicLong()
    private val configResolver by lazy {
        appContainer.vpnConfigResolver
    }
    private val trafficMonitor by lazy {
        VpnTrafficMonitor(
            query = ::queryTraffic,
            clock = SystemClock::elapsedRealtime,
            isInteractive = { getSystemService(android.os.PowerManager::class.java).isInteractive }
        )
    }
    @Volatile
    private var reconnectJob: Job? = null
    @Volatile
    private var coreSession: RustVpnSession? = null
    private var coreLogJob: Job? = null
    private var receiverRegistered = false

    @Volatile
    private var lastNodeId: Long = -1L
    @Volatile
    private var userRequestedStop = false
    private var reconnectAttempts = 0
    @Volatile
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

    private fun queryTraffic(logErrors: Boolean): TrafficCounters? = try {
        val session = checkNotNull(coreSession) { "Rust VPN session is unavailable" }
        check(session.isRunning()) { "Rust core is not running" }
        session.trafficCounters().let { TrafficCounters(it.uploadBytes, it.downloadBytes) }
    } catch (error: Exception) {
        if (logErrors) logError("Rust traffic query failed: ${error.message}", error)
        null
    }

    private fun nodeSummary(node: ProxyNode?): String {
        val type = node?.type?.name ?: "UNKNOWN"
        return "${nodeDisplayName(node)} [$type]"
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
        RuntimeLogBuffer.appendError(fullMessage)
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
                Intent.ACTION_SCREEN_ON, Intent.ACTION_SCREEN_OFF -> trafficMonitor.screenChanged()
                ACTION_STOP -> {
                    requestStop("Stopping service: notification action")
                }
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        latestStartId = startId
        // Every startForegroundService delivery must acknowledge its deadline, including
        // STOP and stale START requests. Native cleanup may outlive that deadline, and
        // an existing service can have been demoted by an earlier queued stop.
        val operationId = intent?.getLongExtra(EXTRA_OPERATION_ID, 0L) ?: 0L
        if (!promoteToForeground(operationId, VpnStateManager.vpnState.value.isConnected)) {
            return START_NOT_STICKY
        }
        when (intent?.action) {
            ACTION_START, ACTION_SWITCH, ACTION_RELOAD, SERVICE_INTERFACE, null -> {
                notifications.observeLanguage(serviceScope)
                if ((intent?.action == SERVICE_INTERFACE || intent == null) && VpnStateManager.vpnState.value.serviceActive) {
                    return restartResult()
                }
                val config = intent?.getStringExtra(EXTRA_CONFIG)?.takeIf { it.isNotBlank() }
                val nodeId = intent?.getLongExtra(EXTRA_NODE_ID, -1L)?.takeIf { it > 0L }
                if (intent?.hasExtra(EXTRA_STOP_REVISION) == true &&
                    intent.getLongExtra(EXTRA_STOP_REVISION, -1L) != VpnStateManager.stopRevision.get()) {
                    VpnStateManager.reportServiceOperation(operationId, success = false, cancelled = true)
                    if (!VpnStateManager.vpnState.value.serviceActive) stopSelf(startId)
                    return restartResult()
                }
                startVpn(config, nodeId, operationId, resetReconnectAttempts = true)
            }
            ACTION_STOP -> {
                requestStop("Stopping service: ACTION_STOP intent", userInitiated = !intent.hasExtra(EXTRA_STOP_REVISION))
            }
            ACTION_UPDATE_RESTART_POLICY -> Unit
            else -> {
                Log.w(TAG, "Ignoring VPN service start without a supported action")
                stopSelf(startId)
            }
        }
        return restartResult()
    }

    private fun restartResult(): Int {
        stickyRestartEnabled = !userRequestedStop && VpnStateManager.vpnState.value.serviceActive && isAlwaysOn
        return if (stickyRestartEnabled) START_STICKY else START_NOT_STICKY
    }

    private fun refreshRestartPolicy() {
        if (destroyed || userRequestedStop || !VpnStateManager.vpnState.value.isConnected) return
        // Android only exposes isAlwaysOn after the tunnel is established. It also
        // skips restarting an already connected service when always-on is enabled.
        // Refresh the service result after connection and when that setting changes.
        val alwaysOn = isAlwaysOn
        if (alwaysOn == stickyRestartEnabled) return
        stickyRestartEnabled = alwaysOn
        runCatching {
            startService(Intent(this, AeroBoxVpnService::class.java).setAction(ACTION_UPDATE_RESTART_POLICY))
        }.onFailure {
            stickyRestartEnabled = !alwaysOn // Retry on the next traffic sample.
            logError("Unable to refresh VPN restart policy: ${it.javaClass.simpleName}", it)
        }
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

    private fun requestStop(reason: String, userInitiated: Boolean = true) {
        if (userInitiated) VpnStateManager.stopRevision.incrementAndGet()
        val generation = VpnStateManager.beginStop()
        stateGeneration = generation
        activeOperationId.set(0L)
        val revision = ++requestRevision
        userRequestedStop = true
        startJobs.cancel(CancellationException(reason))
        reconnectJob?.cancel()
        reconnectJob = null
        // Coroutine cancellation cannot interrupt JNI. closeService cancels the native startup context.
        val server = coreSession
        val interrupt = serviceScope.launch {
            runCatching { server?.closeService() }
        }
        launchLifecycleOperation {
            interrupt.join()
            stopService(reason, generation)
            withContext(Dispatchers.Main.immediate) {
                if (!destroyed && requestRevision == revision) stopSelfResult(latestStartId)
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
        val generation = VpnStateManager.beginStart()
        stateGeneration = generation
        activeOperationId.set(operationId)
        reconnectJob?.cancel()
        reconnectJob = null
        if (!startJobs.isActive) startJobs = SupervisorJob(serviceJob)
        if (!promoteToForeground(operationId)) return
        launchLifecycleOperation(startJobs) {
            userRequestedStop = false
            runtimeRevision = revision
            if (resetReconnectAttempts) reconnectAttempts = 0
            var stage = "native initialization"
            try {
                RustCore.awaitReady()
                notifications.refreshLanguage()
                // Re-establish foreground state after an earlier queued stop or instance cleanup.
                stage = "foreground service promotion"
                startForeground(NOTIFICATION_ID, buildNotification(connected = false))
                Log.i(TAG, "Starting Rust core service")

                stage = "configuration preparation"
                val startRequest = prepareStartRequest(
                    providedConfig = providedConfig,
                    requestedNodeId = requestedNodeId
                )

                cachedConnectedNode = startRequest.node
                lastNodeId = startRequest.node.id
                Log.i(TAG, "Prepared start request for ${nodeSummary(startRequest.node)}")
                notifications.show(buildNotification(connected = false))

                if (!receiverRegistered) {
                    val filter = IntentFilter(ACTION_STOP)
                    filter.addAction(Intent.ACTION_SCREEN_ON)
                    filter.addAction(Intent.ACTION_SCREEN_OFF)
                    ContextCompat.registerReceiver(
                        this@AeroBoxVpnService,
                        closeReceiver,
                        filter,
                        ContextCompat.RECEIVER_NOT_EXPORTED
                    )
                    receiverRegistered = true
                }

                stage = "network monitoring"
                DefaultNetworkMonitor.start { network ->
                    val current = coreSession
                    try { current?.networkChanged(network) }
                    catch (failure: Throwable) { coreNetworkFailure(current, failure) }
                }

                stage = "core service startup"
                val network = checkNotNull(DefaultNetworkMonitor.defaultNetwork) { "No physical network available" }
                val server = coreSession ?: createCoreSession(network).also { coreSession = it }
                // Publish the latest physical network even when the session was
                // reused for a node switch while the callback queue was idle.
                server.networkChanged(DefaultNetworkMonitor.defaultNetwork)
                startCoreLogs(server)

                val overrides = buildOverrideOptions()
                trafficMonitor.stop()
                currentCoroutineContext().ensureActive()
                Log.i(TAG, "Invoking startOrReloadService for ${nodeSummary(startRequest.node)}")
                server.startOrReloadService(startRequest.config, overrides)
                currentCoroutineContext().ensureActive()
                Log.i(TAG, "startOrReloadService returned for ${nodeSummary(startRequest.node)}")
                reconnectAttempts = 0
                if (!VpnStateManager.connected(generation, startRequest.node)) {
                    VpnStateManager.reportServiceOperation(operationId, success = false, cancelled = true)
                    return@launchLifecycleOperation
                }
                notifications.show(buildNotification(connected = true))
                refreshRestartPolicy()
                startTrafficMonitor()
                VpnStateManager.reportServiceOperation(operationId, success = true, node = startRequest.node)
            } catch (error: CancellationException) {
                throw error
            } catch (e: Throwable) {
                currentCoroutineContext().ensureActive()
                logError("VPN startup failed during $stage: ${e.javaClass.simpleName}: ${e.message.orEmpty()}", e)
                handleStartFailure(
                    error = e,
                    allowReconnect = e !is NonRetryableStartException,
                    revision = revision,
                    generation = generation,
                    operationId = operationId
                )
            }
        }.invokeOnCompletion { error ->
            activeOperationId.compareAndSet(operationId, 0L)
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

    private fun promoteToForeground(operationId: Long, connected: Boolean = false): Boolean = try {
        startForeground(NOTIFICATION_ID, buildNotification(connected = connected))
        true
    } catch (error: Exception) {
        val message = "Unable to start foreground VPN service: ${error.javaClass.simpleName}: ${error.message.orEmpty()}"
        logError(message, error)
        VpnStateManager.updateLastError(message)
        VpnStateManager.reportServiceOperation(operationId, success = false, error = message)
        requestStop("Unable to start foreground VPN service", userInitiated = false)
        false
    }

    private suspend fun prepareStartRequest(
        providedConfig: String?,
        requestedNodeId: Long?
    ): StartRequest {
        val node = configResolver.resolveNodeById(
            nodeId = requestedNodeId ?: lastNodeId.takeIf { it > 0L }
        )
        if (node == null) {
            val error = "No node available"
            Log.w(TAG, error)
            throw NonRetryableStartException(error)
        }

        val config = providedConfig ?: configResolver.buildConfig(node)
        // Configs supplied by VpnRepository have already passed the native check.
        val configError = if (providedConfig == null) configResolver.validateConfig(config) else null
        if (configError != null) {
            Log.w(TAG, "Config validation failed for ${nodeSummary(node)}: $configError")
            throw NonRetryableStartException(configError)
        }

        return StartRequest(node = node, config = config)
    }

    private suspend fun buildOverrideOptions(): RustTunController.Applications {
        if (!PreferenceManager.perAppProxyEnabledFlow(applicationContext).first()) {
            return RustTunController.Applications()
        }
        val mode = PreferenceManager.perAppProxyModeFlow(applicationContext).first()
        val packages = PreferenceManager.perAppProxyPackagesFlow(applicationContext).first()
        return if (mode == "whitelist") {
            RustTunController.Applications(include = (packages + packageName).toSet())
        } else {
            RustTunController.Applications(exclude = (packages - packageName).toSet())
        }
    }

    private suspend fun stopService(reason: String, generation: Long) {
        Log.i(TAG, reason)
        reconnectJob?.cancel()
        reconnectJob = null
        releaseRuntimeResources(stopping = true)

        VpnStateManager.stopped(generation)
    }

    private suspend fun releaseRuntimeResources(stopping: Boolean) {
        trafficMonitor.stop()
        DefaultNetworkMonitor.stop()

        val server = coreSession
        coreSession = null
        runCatching { server?.closeService() }
        runCatching { server?.close() }

        coreLogJob?.cancel()
        coreLogJob = null
        runCatching { server?.drainLogs(RuntimeLogBuffer::appendCore) }
        if (stopping) cachedConnectedNode = null

        if (stopping && receiverRegistered) {
            runCatching { unregisterReceiver(closeReceiver) }
            receiverRegistered = false
        }

        if (stopping) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        }
    }

    private fun createCoreSession(network: PhysicalNetwork): RustVpnSession {
        lateinit var session: RustVpnSession
        session = RustVpnSession(
            this, AeroBoxApplication.connectivity, network,
            onNetworkRefreshFailure = { error -> coreNetworkFailure(session, error) },
        )
        return session
    }

    private fun coreNetworkFailure(session: RustVpnSession?, error: Throwable) {
        val revision = requestRevision
        val generation = stateGeneration
        launchLifecycleOperation {
            if (session != null && coreSession === session && !userRequestedStop &&
                !destroyed && revision == requestRevision) {
                handleStartFailure(error, allowReconnect = true, revision = revision, generation = generation)
            }
        }
    }

    private fun startCoreLogs(session: RustVpnSession) {
        coreLogJob?.cancel()
        coreLogJob = serviceScope.launch {
            while (coreSession === session && !destroyed) {
                runCatching { session.drainLogs(RuntimeLogBuffer::appendCore) }
                    .onFailure { Log.w(TAG, "Core log drain failed", it) }
                delay(250)
            }
        }
    }

    // ─── Notification ───

    private val notifications by lazy { VpnNotifications(this, ACTION_STOP) }

    private fun buildNotification(contentText: String = "", connected: Boolean = false): Notification {
        val currentNode = VpnStateManager.vpnState.value.currentNode
        val displayNode = if (connected) currentNode ?: cachedConnectedNode else cachedConnectedNode ?: currentNode
        return notifications.build(displayNode?.name, contentText, connected)
    }

    private fun startTrafficMonitor() {
        val revision = runtimeRevision
        val generation = stateGeneration
        var lastNotificationText: String? = null
        trafficMonitor.start(
            scope = serviceScope,
            serviceActive = { VpnStateManager.vpnState.value.serviceActive },
            onSample = { sample, interactive ->
                refreshRestartPolicy()
                VpnStateManager.updateTrafficStats(
                    uploadSpeed = sample.uploadSpeed,
                    downloadSpeed = sample.downloadSpeed,
                    uploadDelta = sample.uploadDelta,
                    downloadDelta = sample.downloadDelta
                )
                if (interactive) {
                    val text = "↑ ${NetworkUtils.formatBytes(sample.uploadSpeed)}/s  ↓ ${NetworkUtils.formatBytes(sample.downloadSpeed)}/s"
                    val key = "${notifications.languageTag}:$text"
                    if (key != lastNotificationText) {
                        notifications.show(buildNotification(contentText = text, connected = true))
                        lastNotificationText = key
                    }
                }
            },
            onUnavailable = {
                val error = "Core health check failed: traffic API unavailable"
                Log.w(TAG, error)
                launchLifecycleOperation {
                    if (!userRequestedStop && !destroyed && runtimeRevision == revision &&
                        requestRevision == revision && VpnStateManager.vpnState.value.serviceActive
                    ) {
                        handleStartFailure(
                            error = IllegalStateException(error),
                            allowReconnect = true,
                            revision = revision,
                            generation = generation
                        )
                    }
                }
            }
        )
    }

    override fun onDestroy() {
        if (!userRequestedStop && VpnStateManager.vpnState.value.serviceActive) {
            logError("VPN service destroyed while active")
        }
        destroyed = true
        val generation = if (VpnStateManager.vpnState.value.generation == stateGeneration) {
            VpnStateManager.beginStop()
        } else stateGeneration
        requestRevision++
        userRequestedStop = true
        if (activeServiceReference?.get() === this) {
            activeServiceReference = null
        }
        serviceScope.cancel()
        // A replacement service must wait for this instance to release shared native resources.
        val cleanup = serviceScope.launch(NonCancellable + Dispatchers.Main.immediate) {
            previousCleanup?.join()
            withContext(Dispatchers.IO) { runCatching { coreSession?.closeService() } }
            lifecycleMutex.withLock {
                withContext(Dispatchers.IO) { stopService("Stopping service: onDestroy", generation) }
            }
        }
        pendingCleanup = cleanup
        cleanup.invokeOnCompletion {
            if (pendingCleanup === cleanup) pendingCleanup = null
        }
        super.onDestroy()
    }

    override fun onRevoke() {
        // VpnService can deliver revocation off the main thread. Use the same ordered cleanup
        // as a stop command so the tunnel and native service are released before stopSelf.
        serviceScope.launch(Dispatchers.Main.immediate) {
            val message = "VPN permission revoked by the system or another VPN"
            logError(message)
            VpnStateManager.updateLastError(message)
            requestStop(message)
        }
    }

    // ─── Auto-Reconnect ───

    private suspend fun handleStartFailure(
        error: Throwable,
        allowReconnect: Boolean,
        revision: Long,
        generation: Long,
        operationId: Long = 0L
    ) {
        val errorMessage = error.message?.takeIf { it.isNotBlank() } ?: error.toString()
        releaseRuntimeResources(stopping = false)
        VpnStateManager.reportServiceOperation(operationId, success = false, error = errorMessage)
        if (userRequestedStop || destroyed || requestRevision != revision) return

        val autoReconnect = allowReconnect && !userRequestedStop &&
            PreferenceManager.autoReconnectFlow(applicationContext).first()
        if (!autoReconnect || reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
            VpnStateManager.disconnected(generation, errorMessage)
            val reason = if (reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
                "Stopping service: max reconnect attempts reached"
            } else {
                "Stopping service after non-retryable start failure"
            }
            stopService(reason, generation)
            withContext(Dispatchers.Main.immediate) {
                if (!destroyed && requestRevision == revision) stopSelfResult(latestStartId)
            }
            return
        }

        VpnStateManager.disconnected(generation, errorMessage, retrying = true)
        notifications.show(
            buildNotification(
                contentText = notifications.string(R.string.notification_connecting),
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
