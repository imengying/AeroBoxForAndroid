package com.aerobox.viewmodel

import android.app.Application
import android.content.Context
import android.os.Debug
import android.content.Intent
import android.net.VpnService
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.aerobox.AeroBoxApplication
import com.aerobox.core.connection.ConnectionDiagnostics
import com.aerobox.core.connection.ConnectionFixAction
import com.aerobox.core.connection.ConnectionIssue
import com.aerobox.core.geo.GeoAssetManager
import com.aerobox.core.network.NodeAddressFamilyResolver
import com.aerobox.core.network.PublicIpDetector
import com.aerobox.data.model.IPv6Mode
import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.NodeLatencyState
import com.aerobox.data.model.RoutingMode
import com.aerobox.data.model.Subscription
import com.aerobox.data.model.TrafficStats
import com.aerobox.data.model.VpnState
import com.aerobox.data.repository.VpnConnectionResult
import com.aerobox.service.VpnStateManager
import com.aerobox.utils.NetworkUtils
import com.aerobox.utils.PreferenceManager
import com.aerobox.utils.formatDuration
import com.aerobox.utils.toTrafficStats
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
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
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.supervisorScope

@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class HomeViewModel(application: Application) : AndroidViewModel(application) {
    private companion object {
        const val POST_CONNECT_IP_DETECT_DELAY_MS = 500L
        const val NODE_TEST_TIMEOUT_MS = 5000
        const val NODE_TEST_CONCURRENCY = 10
    }

    private data class UrlTestSettings(
        val directDns: String,
        val ipv6Mode: IPv6Mode
    )

    private val appContext = application.applicationContext
    private val nodeDao = AeroBoxApplication.database.proxyNodeDao()
    private val vpnRepository = AeroBoxApplication.vpnRepository
    private val subscriptionRepository = AeroBoxApplication.subscriptionRepository
    private val ipDetector = PublicIpDetector()

    val vpnState: StateFlow<VpnState> = VpnStateManager.vpnState
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), VpnState())

    val isServiceActive: StateFlow<Boolean> = VpnStateManager.serviceActive
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), false)

    val isConnecting: StateFlow<Boolean> = combine(isServiceActive, vpnState) { serviceActive, state ->
        serviceActive && !state.isConnected
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), false)

    val routingMode: StateFlow<RoutingMode> = PreferenceManager.routingModeFlow(appContext)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), RoutingMode.GLOBAL_PROXY)

    fun setRoutingMode(mode: RoutingMode) {
        if (routingMode.value == mode) return
        viewModelScope.launch {
            applyRoutingMode(mode)
        }
    }

    val trafficStats: StateFlow<TrafficStats> = vpnState
        .map { it.toTrafficStats() }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), TrafficStats())

    val allNodes: StateFlow<List<ProxyNode>> = nodeDao.getAllNodes()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

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

    private val _detectedIp = MutableStateFlow(appContext.getString(com.aerobox.R.string.tap_detect_exit_ip))
    val detectedIp: StateFlow<String> = _detectedIp.asStateFlow()

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
        super.onCleared()
    }

    init {
        observeSelectedNode()
        observeNetworkInfoTriggers()
        refreshNetworkInfo()
    }

    private fun observeSelectedNode() {
        viewModelScope.launch {
            combine(
                nodeDao.getAllNodes(),
                PreferenceManager.lastSelectedNodeIdFlow(appContext)
            ) { nodes, selectedId ->
                nodes.firstOrNull { it.id == selectedId }
                    ?: if (selectedId > 0L) null else nodes.firstOrNull()
            }.collect { node ->
                _selectedNode.value = node
            }
        }
    }



    private fun observeNetworkInfoTriggers() {
        viewModelScope.launch {
            vpnState
                .map { state -> state.isConnected to state.currentNode?.id }
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
        val previousMode = routingMode.value
        PreferenceManager.setRoutingMode(appContext, mode)

        val currentNode = vpnState.value.currentNode ?: selectedNode.value
        if (!vpnState.value.isConnected || currentNode == null) {
            return true
        }

        val result = vpnRepository.switchToNode(currentNode)
        if (result is VpnConnectionResult.Success) {
            _uiMessage.tryEmit(
                appContext.getString(
                    com.aerobox.R.string.switched_to_mode,
                    appContext.getString(mode.labelResId)
                )
            )
            return true
        }
        PreferenceManager.setRoutingMode(appContext, previousMode)
        dispatchConnectionError(result)
        return false
    }

    fun toggleConnection(context: Context): Intent? {
        if (!isServiceActive.value) {
            val permissionIntent = VpnService.prepare(context)
            if (permissionIntent != null) {
                return permissionIntent
            }
            startConnection(context)
            return null
        }

        stopConnection()
        return null
    }

    fun onVpnPermissionGranted(context: Context) {
        startConnection(context)
    }

    private fun startConnection(context: Context) {
        val node = selectedNode.value
        if (node == null) {
            _uiMessage.tryEmit(context.getString(com.aerobox.R.string.add_node_first))
            return
        }

        viewModelScope.launch {
            VpnStateManager.clearLastError()
            val result = vpnRepository.connectNode(node)
            if (result is VpnConnectionResult.Success) {
                _selectedNode.value = result.node
                PreferenceManager.setLastSelectedNodeId(appContext, result.node.id)
                if (result.node.id != node.id) {
                    _uiMessage.tryEmit(appContext.getString(com.aerobox.R.string.subscription_refreshed_new_node, result.node.name))
                }
                startConnectWatchdog(context)
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

    private fun startConnectWatchdog(context: Context) {
        connectWatchdogJob?.cancel()
        connectWatchdogJob = viewModelScope.launch {
            val autoReconnectEnabled = PreferenceManager.autoReconnectFlow(appContext).first()
            if (autoReconnectEnabled) {
                while (isActive) {
                    if (vpnState.value.isConnected) {
                        return@launch
                    }
                    val rawError = VpnStateManager.lastError.value?.takeIf { it.isNotBlank() }
                    if (rawError != null) {
                        handleConnectionFailure(context, rawError)
                        return@launch
                    }
                    delay(500)
                }
            } else {
                delay(12_000)
                if (!vpnState.value.isConnected) {
                    val rawError = VpnStateManager.lastError.value ?: "service start timeout"
                    handleConnectionFailure(context, rawError)
                }
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
        viewModelScope.launch {
            val subscriptionId = nodes.firstOrNull()?.subscriptionId ?: return@launch
            val testSettings = loadUrlTestSettings()
            val semaphore = Semaphore(NODE_TEST_CONCURRENCY)
            val latencyResults = java.util.concurrent.ConcurrentHashMap<Long, Int>()
            _nodeLatencyOverrides.update { current ->
                current + nodes.associate { it.id to NodeLatencyState.TESTING }
            }

            try {
                supervisorScope {
                    val jobs = nodes.map { node ->
                        launch {
                            val latency = semaphore.withPermit {
                                testNodeLatency(node, testSettings)
                            }
                            val finalLatency = latency.takeIf { it > 0 } ?: NodeLatencyState.FAILED
                            latencyResults[node.id] = finalLatency
                            _nodeLatencyOverrides.update { it + (node.id to finalLatency) }

                            // Recompute sort after each result using in-memory states.
                            val sortedIds = computeSortedIds(nodes, latencyResults)
                            _nodeSortOrder.update { it + (subscriptionId to sortedIds) }
                        }
                    }
                    jobs.forEach { it.join() }
                }
                subscriptionRepository.updateNodeLatencies(latencyResults)
            } finally {
                val testedIds = nodes.map { it.id }.toSet()
                _nodeLatencyOverrides.update { current ->
                    current - testedIds
                }
            }
        }
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
        viewModelScope.launch {
            val testSettings = loadUrlTestSettings()
            _nodeLatencyOverrides.update { it + (node.id to NodeLatencyState.TESTING) }
            try {
                val latency = testNodeLatency(node, testSettings)
                val finalLatency = latency.takeIf { it > 0 } ?: NodeLatencyState.FAILED
                _nodeLatencyOverrides.update { it + (node.id to finalLatency) }
                subscriptionRepository.updateNodeLatency(node.id, finalLatency)
            } finally {
                _nodeLatencyOverrides.update { it - node.id }
            }
        }
    }

    private suspend fun testNodeLatency(node: ProxyNode, settings: UrlTestSettings): Int {
        return runCatching {
            vpnRepository.urlTestNode(
                node = node,
                directDns = settings.directDns,
                ipv6Mode = settings.ipv6Mode,
                timeoutMs = NODE_TEST_TIMEOUT_MS
            )
        }.getOrDefault(-1)
    }

    fun refreshNetworkInfo() {
        scheduleNetworkInfoRefresh()
    }

    private fun scheduleNetworkInfoRefresh(delayMs: Long = 0L) {
        detectIpJob?.cancel()
        detectIpJob = viewModelScope.launch {
            if (delayMs > 0L) {
                _detectedIp.value = appContext.getString(com.aerobox.R.string.detecting_ip_later)
                delay(delayMs)
                if (!vpnState.value.isConnected) {
                    return@launch
                }
            }

            _detectedIp.value = appContext.getString(com.aerobox.R.string.detecting_ip)
            _detectedIp.value = fetchPublicIp(vpnState.value.currentNode ?: selectedNode.value)
        }
    }

    fun dismissConnectionIssue() {
        _connectionIssue.value = null
    }

    fun applyConnectionFix(context: Context, fixAction: ConnectionFixAction) {
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
                _uiMessage.tryEmit(context.getString(com.aerobox.R.string.connection_fix_success))
                _connectionIssue.value = null
            } else {
                _uiMessage.tryEmit(context.getString(com.aerobox.R.string.connection_fix_failed))
            }
        }
    }

    private suspend fun fetchPublicIp(node: ProxyNode?): String {
        val preferIpv6Only = node?.let { NodeAddressFamilyResolver.isIpv6Only(it) } == true
        val useProxyFriendlyEndpoints = vpnState.value.isConnected
        return ipDetector.detect(preferIpv6Only, useProxyFriendlyEndpoints)
            ?: appContext.getString(com.aerobox.R.string.detect_failed_tap_retry)
    }

    private suspend fun loadUrlTestSettings(): UrlTestSettings {
        val preferences = PreferenceManager.readVpnConfigPreferences(appContext)
        val safeDirectDns = if (preferences.directDns.contains("[")) {
            PreferenceManager.DEFAULT_DIRECT_DNS
        } else {
            preferences.directDns
        }
        return UrlTestSettings(
            directDns = safeDirectDns,
            ipv6Mode = preferences.ipv6Mode
        )
    }

    private fun handleConnectionFailure(context: Context, rawError: String) {
        connectWatchdogJob?.cancel()
        connectWatchdogJob = null
        val issue = ConnectionDiagnostics.classify(rawError)
        _connectionIssue.value = issue
        _uiMessage.tryEmit(
            "${context.getString(com.aerobox.R.string.operation_failed)}: " +
                context.getString(issue.titleResId)
        )
    }

    /**
     * Central handler for non-success [VpnConnectionResult]s.
     * Extracts the raw error string and delegates to [handleConnectionFailure].
     */
    private fun dispatchConnectionError(result: VpnConnectionResult) {
        when (result) {
            is VpnConnectionResult.InvalidConfig -> handleConnectionFailure(appContext, result.error)
            is VpnConnectionResult.Failure -> {
                val details = result.throwable.message?.takeIf { it.isNotBlank() }
                    ?: result.throwable.toString()
                handleConnectionFailure(appContext, details)
            }
            VpnConnectionResult.NoNodeAvailable -> {
                _uiMessage.tryEmit(appContext.getString(com.aerobox.R.string.add_node_first))
            }
            is VpnConnectionResult.Success -> Unit // should not reach here
        }
    }
}
