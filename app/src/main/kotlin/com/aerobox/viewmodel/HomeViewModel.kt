package com.aerobox.viewmodel

import android.app.Application
import android.content.Context
import android.os.Debug
import android.os.SystemClock
import android.content.Intent
import android.net.VpnService
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.aerobox.core.connection.ConnectionDiagnostics
import com.aerobox.core.connection.ConnectionFixAction
import com.aerobox.core.connection.ConnectionIssue
import com.aerobox.core.geo.GeoAssetManager
import com.aerobox.core.network.PublicIpDetector
import com.aerobox.core.network.IpFamily
import com.aerobox.core.network.IpDetectionResult
import com.aerobox.core.network.NetworkDetection
import com.aerobox.data.model.IPv6Mode
import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.NodeLatencyState
import com.aerobox.data.model.RoutingMode
import com.aerobox.data.model.Subscription
import com.aerobox.data.model.TrafficStats
import com.aerobox.data.model.VpnState
import com.aerobox.data.repository.VpnConnectionResult
import com.aerobox.service.VpnStateManager
import com.aerobox.utils.AppLocaleManager
import com.aerobox.utils.NetworkUtils
import com.aerobox.utils.PreferenceManager
import com.aerobox.utils.formatDuration
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.drop
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.shareIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.supervisorScope
import kotlinx.coroutines.withContext

@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class HomeViewModel(
    application: Application,
    private val nodeDao: com.aerobox.data.database.ProxyNodeDao,
    private val vpnRepository: com.aerobox.data.repository.VpnRepository,
    private val subscriptionRepository: com.aerobox.data.repository.SubscriptionRepository
) : AndroidViewModel(application) {
    private companion object {
        const val POST_CONNECT_IP_DETECT_DELAY_MS = 500L
        const val NODE_TEST_TIMEOUT_MS = 5000
        const val NODE_TEST_CONCURRENCY = 3
        const val LATENCY_PUBLISH_INTERVAL_MS = 250L
        const val CONNECT_TIMEOUT_MS = 12_000L
        const val AUTO_RECONNECT_TIMEOUT_MS = 5 * 60_000L
    }

    private data class UrlTestSettings(
        val directDns: String,
        val ipv6Mode: IPv6Mode
    )

    private val appContext = application.applicationContext
    private val ipDetector = PublicIpDetector()
    private var latencyTestJob: Job? = null
    private val languageTag = PreferenceManager.languageTagFlow(appContext)
        .stateIn(viewModelScope, SharingStarted.Eagerly, AppLocaleManager.SYSTEM_LANGUAGE_TAG)

    val vpnState: StateFlow<VpnState> = VpnStateManager.vpnState

    val routingMode: StateFlow<RoutingMode> = PreferenceManager.routingModeFlow(appContext)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), RoutingMode.GLOBAL_PROXY)

    fun setRoutingMode(mode: RoutingMode) {
        viewModelScope.launch {
            applyRoutingMode(mode)
        }
    }

    val trafficStats: StateFlow<TrafficStats> = vpnState
        .map { it.traffic }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), TrafficStats())

    private val allNodes = nodeDao.getAllNodes()
        .shareIn(viewModelScope, SharingStarted.Eagerly, replay = 1)

    private val _nodeLatencyOverrides = MutableStateFlow<Map<Long, Int>>(emptyMap())
    val displayNodes: StateFlow<List<ProxyNode>> = combine(allNodes, _nodeLatencyOverrides) { nodes, overrides ->
        if (overrides.isEmpty()) {
            nodes
        } else {
            nodes.map { node ->
                overrides[node.id]?.let { latency -> node.copy(latency = latency) } ?: node
            }
        }
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    private val _nodeSortOrder = MutableStateFlow<Map<Long, List<Long>>>(emptyMap())
    val nodeSortOrder: StateFlow<Map<Long, List<Long>>> = _nodeSortOrder.asStateFlow()

    val subscriptions: StateFlow<List<Subscription>> = subscriptionRepository
        .getAllSubscriptions()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    private val _selectedNode = MutableStateFlow<ProxyNode?>(null)
    val selectedNode: StateFlow<ProxyNode?> = _selectedNode.asStateFlow()

    val connectionDuration: StateFlow<String> = vpnState
        .map { state ->
            if (!state.isConnected) null else state.connectionTime
        }
        .distinctUntilChanged()
        .map { connectionTime ->
            if (connectionTime == null || connectionTime <= 0L) {
                flow { emit("00:00:00") }
            } else {
                flow {
                    while (true) {
                        emit(connectionTime.formatDuration())
                        delay(1_000)
                    }
                }
            }
        }
        .flatMapLatest { it }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), "00:00:00")

    private val _networkDetection = MutableStateFlow(NetworkDetection())
    val networkDetection: StateFlow<NetworkDetection> = _networkDetection.asStateFlow()

    private val _connectionIssue = MutableStateFlow<ConnectionIssue?>(null)
    val connectionIssue: StateFlow<ConnectionIssue?> = _connectionIssue.asStateFlow()

    // Polls memory info every 15s, but only while something is observing
    // (e.g., HomeScreen is visible).  Stops automatically when there are no
    // collectors, saving CPU/battery when the app is in the background.
    val memoryUsage: StateFlow<String> = flow {
        while (true) {
            emit(readMemoryUsage())
            delay(15_000)
        }
    }
        .flowOn(Dispatchers.Default)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), "--")

    private val _uiMessage = MutableSharedFlow<String>(extraBufferCapacity = 1)
    val uiMessage: SharedFlow<String> = _uiMessage.asSharedFlow()

    private var detectIpJob: Job? = null
    private var connectWatchdogJob: Job? = null

    override fun onCleared() {
        detectIpJob?.cancel()
        connectWatchdogJob?.cancel()
        ipDetector.shutdown()
    }

    init {
        observeSelectedNode()
        observeNetworkInfoTriggers()
        refreshNetworkInfo()
    }

    private fun observeSelectedNode() {
        viewModelScope.launch {
            combine(
                allNodes,
                PreferenceManager.lastSelectedNodeIdFlow(appContext)
            ) { nodes, selectedId ->
                (nodes.firstOrNull { it.id == selectedId } ?: nodes.firstOrNull()) to selectedId
            }.collect { (node, selectedId) ->
                vpnRepository.runtimeSettingsMutex.withLock {
                    if (PreferenceManager.lastSelectedNodeIdFlow(appContext).first() != selectedId) return@withLock
                    // A restored selection can arrive before Room publishes its committed rows.
                    val resolved = if (node?.id == selectedId) node else {
                        nodeDao.getNodeById(selectedId) ?: nodeDao.getFirstNode()
                    }
                    _selectedNode.value = resolved
                    if (resolved?.id != selectedId) {
                        PreferenceManager.replaceSelectedNode(appContext, selectedId, resolved?.id ?: 0L)
                    }
                }
            }
        }
    }



    private fun observeNetworkInfoTriggers() {
        viewModelScope.launch {
            vpnState
                .map { state -> Triple(state.isConnected, state.currentNode?.id, state.connectionTime) }
                .distinctUntilChanged()
                .drop(1)
                .collect { (isConnected, _) ->
                    if (isConnected) {
                        connectWatchdogJob?.cancel()
                        connectWatchdogJob = null
                        scheduleNetworkInfoRefresh(POST_CONNECT_IP_DETECT_DELAY_MS)
                    } else {
                        refreshNetworkInfo()
                    }
                }
        }
    }


    private fun readMemoryUsage(): String {
        return runCatching {
            val info = Debug.MemoryInfo()
            Debug.getMemoryInfo(info)
            NetworkUtils.formatBytes(info.totalPss.toLong() * 1024L)
        }.getOrDefault("--")
    }


    private suspend fun applyRoutingMode(mode: RoutingMode): Boolean {
        val result = vpnRepository.runtimeSettings.update(
            readCurrent = { PreferenceManager.routingModeFlow(appContext).first() },
            persist = { PreferenceManager.setRoutingMode(appContext, it) }
        ) { mode }
        if (result.reloaded) {
            _uiMessage.tryEmit(appString(com.aerobox.R.string.switched_to_mode, appString(mode.labelResId)))
        }
        result.failure?.let(::dispatchConnectionError)
        return result.applied
    }

    fun toggleConnection(context: Context): Intent? {
        if (!vpnState.value.serviceActive) {
            val permissionIntent = VpnService.prepare(context)
            if (permissionIntent != null) {
                return permissionIntent
            }
            startConnection()
            return null
        }

        stopConnection()
        return null
    }

    fun onVpnPermissionGranted() {
        startConnection()
    }

    private fun startConnection() {
        val node = selectedNode.value
        if (node == null) {
            _uiMessage.tryEmit(appString(com.aerobox.R.string.add_node_first))
            return
        }

        viewModelScope.launch {
            VpnStateManager.clearLastError()
            val result = vpnRepository.connectNode(node)
            if (result is VpnConnectionResult.Success) {
                _selectedNode.value = result.node
                PreferenceManager.setLastSelectedNodeId(appContext, result.node.id)
                if (result.node.id != node.id) {
                    _uiMessage.tryEmit(appString(com.aerobox.R.string.subscription_refreshed_new_node, result.node.name))
                }
                startConnectWatchdog()
            } else {
                connectWatchdogJob?.cancel()
                connectWatchdogJob = null
                dispatchConnectionError(result)
            }
        }
    }

    private fun stopConnection() {
        connectWatchdogJob?.cancel()
        connectWatchdogJob = null
        runCatching { vpnRepository.stopVpn() }
        VpnStateManager.clearLastError()
    }

    private fun startConnectWatchdog() {
        connectWatchdogJob?.cancel()
        connectWatchdogJob = viewModelScope.launch {
            val autoReconnectEnabled = PreferenceManager.autoReconnectFlow(appContext).first()
            val timeoutMs = if (autoReconnectEnabled) {
                AUTO_RECONNECT_TIMEOUT_MS
            } else {
                CONNECT_TIMEOUT_MS
            }
            val deadline = SystemClock.elapsedRealtime() + timeoutMs
            while (isActive) {
                if (vpnState.value.isConnected) {
                    return@launch
                }
                val rawError = VpnStateManager.vpnState.value.lastError?.takeIf { it.isNotBlank() }
                if (rawError != null) {
                    handleConnectionFailure(rawError)
                    return@launch
                }
                if (SystemClock.elapsedRealtime() >= deadline) {
                    val timeoutError = "service start timeout"
                    com.aerobox.core.logging.RuntimeLogBuffer.appendError("VPN service start timed out before a connection was established")
                    handleConnectionFailure(timeoutError)
                    return@launch
                }
                delay(500)
            }
        }
    }

    fun selectNode(node: ProxyNode) {
        if (!vpnState.value.isConnected) {
            _selectedNode.value = node
            refreshNetworkInfo()
            viewModelScope.launch {
                PreferenceManager.setLastSelectedNodeId(appContext, node.id)
            }
            return
        }

        viewModelScope.launch {
            val result = vpnRepository.switchToNode(node)
            if (result is VpnConnectionResult.Success) {
                _selectedNode.value = result.node
                PreferenceManager.setLastSelectedNodeId(appContext, result.node.id)
            } else {
                dispatchConnectionError(result)
            }
        }
    }

    fun testSubscriptionNodesLatency(nodes: List<ProxyNode>) {
        val previousTest = latencyTestJob
        latencyTestJob = viewModelScope.launch {
            previousTest?.cancelAndJoin()
            val subscriptionId = nodes.firstOrNull()?.subscriptionId ?: return@launch
            val testSettings = loadUrlTestSettings()
            val semaphore = Semaphore(NODE_TEST_CONCURRENCY)
            val latencyResults = mutableMapOf<Long, Int>()
            _nodeLatencyOverrides.update { current ->
                current + nodes.associate { it.id to NodeLatencyState.TESTING }
            }

            try {
                supervisorScope {
                    val publisher = launch {
                        var publishedCount = 0
                        while (isActive) {
                            delay(LATENCY_PUBLISH_INTERVAL_MS)
                            if (latencyResults.size != publishedCount) {
                                val snapshot = latencyResults.toMap()
                                publishLatencyResults(nodes, subscriptionId, snapshot)
                                publishedCount = snapshot.size
                            }
                        }
                    }
                    try {
                        val jobs = nodes.map { node ->
                            launch {
                                val latency = semaphore.withPermit {
                                    testNodeLatency(node, testSettings)
                                }
                                latencyResults[node.id] = latency.takeIf { it > 0 } ?: NodeLatencyState.FAILED
                            }
                        }
                        jobs.forEach { it.join() }
                    } finally {
                        publisher.cancelAndJoin()
                    }
                }
                publishLatencyResults(nodes, subscriptionId, latencyResults.toMap())
                subscriptionRepository.updateNodeLatencies(nodes, latencyResults)
            } finally {
                val testedIds = nodes.map { it.id }.toSet()
                _nodeLatencyOverrides.update { current ->
                    current - testedIds
                }
            }
        }
    }

    private suspend fun publishLatencyResults(
        nodes: List<ProxyNode>,
        subscriptionId: Long,
        results: Map<Long, Int>
    ) {
        val sortedIds = withContext(Dispatchers.Default) { computeSortedIds(nodes, results) }
        _nodeLatencyOverrides.update { it + results }
        _nodeSortOrder.update { it + (subscriptionId to sortedIds) }
    }

    private fun computeSortedIds(
        nodes: List<ProxyNode>,
        latencyResults: Map<Long, Int>
    ): List<Long> {
        return nodes.sortedWith(
            compareBy<ProxyNode> {
                val lat = latencyResults[it.id] ?: it.latency
                when {
                    lat > 0 -> 0    // valid latency first
                    lat == NodeLatencyState.FAILED -> 1
                    lat == NodeLatencyState.TESTING -> 2
                    else -> 3       // UNTESTED last
                }
            }.thenBy {
                val lat = latencyResults[it.id] ?: it.latency
                if (lat > 0) lat else Int.MAX_VALUE
            }
        ).map { it.id }
    }

    fun testSingleNodeLatency(node: ProxyNode) {
        val previousTest = latencyTestJob
        latencyTestJob = viewModelScope.launch {
            previousTest?.cancelAndJoin()
            val testSettings = loadUrlTestSettings()
            _nodeLatencyOverrides.update { it + (node.id to NodeLatencyState.TESTING) }
            try {
                val latency = testNodeLatency(node, testSettings)
                val finalLatency = latency.takeIf { it > 0 } ?: NodeLatencyState.FAILED
                _nodeLatencyOverrides.update { it + (node.id to finalLatency) }
                subscriptionRepository.updateNodeLatency(node, finalLatency)
            } finally {
                _nodeLatencyOverrides.update { it - node.id }
            }
        }
    }

    private suspend fun testNodeLatency(node: ProxyNode, settings: UrlTestSettings): Int {
        return try {
            vpnRepository.urlTestNode(
                node = node,
                directDns = settings.directDns,
                ipv6Mode = settings.ipv6Mode,
                timeoutMs = NODE_TEST_TIMEOUT_MS
            )
        } catch (error: CancellationException) {
            throw error
        } catch (_: Exception) {
            -1
        }
    }

    fun refreshNetworkInfo() {
        scheduleNetworkInfoRefresh()
    }

    private fun scheduleNetworkInfoRefresh(delayMs: Long = 0L) {
        detectIpJob?.cancel()
        detectIpJob = viewModelScope.launch {
            _networkDetection.value = NetworkDetection()
            if (delayMs > 0L) {
                delay(delayMs)
                if (!vpnState.value.isConnected) {
                    return@launch
                }
            }

            val connected = vpnState.value.isConnected
            val testIpv6 = !connected || PreferenceManager.ipv6ModeFlow(appContext).first().enablesIpv6Tun()
            _networkDetection.value = NetworkDetection(
                ipv4 = IpDetectionResult.Checking,
                ipv6 = if (testIpv6) IpDetectionResult.Checking else IpDetectionResult.Disabled
            )
            supervisorScope {
                for (family in IpFamily.entries) {
                    if (family == IpFamily.IPV6 && !testIpv6) continue
                    launch {
                        val result = ipDetector.detect(family, connected)?.let { IpDetectionResult.Reachable(it) }
                            ?: IpDetectionResult.Failed
                        _networkDetection.update {
                            if (family == IpFamily.IPV4) it.copy(ipv4 = result) else it.copy(ipv6 = result)
                        }
                    }
                }
            }
        }
    }

    fun dismissConnectionIssue() {
        _connectionIssue.value = null
    }

    fun applyConnectionFix(fixAction: ConnectionFixAction) {
        viewModelScope.launch {
            val fixSuccess = when (fixAction) {
                ConnectionFixAction.UPDATE_GEO -> GeoAssetManager.updateAll(appContext).allOk
                ConnectionFixAction.SWITCH_GLOBAL_MODE -> applyRoutingMode(RoutingMode.GLOBAL_PROXY)

                ConnectionFixAction.REFRESH_SUBSCRIPTIONS -> {
                    val subscriptions = subscriptionRepository.getAllSubscriptions().first()
                    if (subscriptions.isEmpty()) {
                        false
                    } else {
                        val results = subscriptionRepository.refreshAllSubscriptions(subscriptions)
                        results.isNotEmpty() && results.all { it.isSuccess }
                    }
                }
            }

            if (fixSuccess) {
                _uiMessage.tryEmit(appString(com.aerobox.R.string.connection_fix_success))
                _connectionIssue.value = null
            } else {
                _uiMessage.tryEmit(appString(com.aerobox.R.string.connection_fix_failed))
            }
        }
    }

    private suspend fun loadUrlTestSettings(): UrlTestSettings {
        val preferences = PreferenceManager.readVpnConfigPreferences(appContext)
        return UrlTestSettings(
            directDns = preferences.directDns,
            ipv6Mode = preferences.ipv6Mode
        )
    }

    private fun handleConnectionFailure(rawError: String) {
        connectWatchdogJob?.cancel()
        connectWatchdogJob = null
        val issue = ConnectionDiagnostics.classify(rawError)
        _connectionIssue.value = issue
        _uiMessage.tryEmit(
            "${appString(com.aerobox.R.string.operation_failed)}: " +
                appString(issue.titleResId)
        )
    }

    /**
     * Central handler for non-success [VpnConnectionResult]s.
     * Extracts the raw error string and delegates to [handleConnectionFailure].
     */
    private fun dispatchConnectionError(result: VpnConnectionResult) {
        when (result) {
            is VpnConnectionResult.InvalidConfig,
            is VpnConnectionResult.Failure -> handleConnectionFailure(
                ConnectionDiagnostics.failureMessage(result, "")
            )
            VpnConnectionResult.NoNodeAvailable -> {
                _uiMessage.tryEmit(appString(com.aerobox.R.string.add_node_first))
            }
            is VpnConnectionResult.Success -> Unit // should not reach here
        }
    }

    private fun appString(resId: Int, vararg formatArgs: Any) =
        AppLocaleManager.string(appContext, languageTag.value, resId, *formatArgs)
}
