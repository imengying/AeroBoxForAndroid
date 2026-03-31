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
import com.aerobox.data.model.IPv6Mode
import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.NodeLatencyState
import com.aerobox.data.model.RoutingMode
import com.aerobox.data.model.Subscription
import com.aerobox.data.model.TrafficStats
import com.aerobox.data.model.VpnState
import com.aerobox.data.repository.SubscriptionRepository
import com.aerobox.data.repository.VpnConnectionResult
import com.aerobox.data.repository.VpnRepository
import com.aerobox.service.VpnStateManager
import com.aerobox.utils.NetworkUtils
import com.aerobox.utils.PreferenceManager
import com.aerobox.utils.formatDuration
import com.aerobox.utils.toTrafficStats
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
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
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.supervisorScope
import kotlinx.coroutines.withContext
import okhttp3.Call
import okhttp3.Callback
import okhttp3.ConnectionPool
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import java.io.IOException
import java.util.concurrent.TimeUnit
import kotlin.coroutines.resume

class HomeViewModel(application: Application) : AndroidViewModel(application) {
    private companion object {
        const val POST_CONNECT_IP_DETECT_DELAY_MS = 500L
        const val NODE_TEST_TIMEOUT_MS = 5000
        const val NODE_TEST_CONCURRENCY = 10
        val IPV4_REGEX = Regex("""^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$""")
        val IPV6_REGEX = Regex("""^[0-9A-Fa-f:]+(%[0-9A-Za-z._~-]+)?$""")
        val ipCheckClient: OkHttpClient by lazy {
            OkHttpClient.Builder()
                .callTimeout(5, TimeUnit.SECONDS)
                .connectTimeout(3, TimeUnit.SECONDS)
                .readTimeout(3, TimeUnit.SECONDS)
                // Zero idle connections to ensure fresh sockets per detection,
                // avoiding stale connections from before VPN routing changed.
                .connectionPool(ConnectionPool(0, 1, TimeUnit.MILLISECONDS))
                .retryOnConnectionFailure(false)
                .build()
        }
    }

    private data class UrlTestSettings(
        val localDns: String,
        val ipv6Mode: IPv6Mode
    )

    private val appContext = application.applicationContext
    private val nodeDao = AeroBoxApplication.database.proxyNodeDao()
    private val vpnRepository = VpnRepository(appContext)
    private val subscriptionRepository = SubscriptionRepository(appContext)

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

    private val _connectionDuration = MutableStateFlow("00:00:00")
    val connectionDuration: StateFlow<String> = _connectionDuration.asStateFlow()

    private val _detectedIp = MutableStateFlow("点击检测出口 IP")
    val detectedIp: StateFlow<String> = _detectedIp.asStateFlow()

    private val _connectionIssue = MutableStateFlow<ConnectionIssue?>(null)
    val connectionIssue: StateFlow<ConnectionIssue?> = _connectionIssue.asStateFlow()

    private val _memoryUsage = MutableStateFlow("--")
    val memoryUsage: StateFlow<String> = _memoryUsage.asStateFlow()

    private val _uiMessage = MutableSharedFlow<String>(extraBufferCapacity = 1)
    val uiMessage: SharedFlow<String> = _uiMessage.asSharedFlow()

    private var detectIpJob: Job? = null
    private var connectWatchdogJob: Job? = null

    override fun onCleared() {
        detectIpJob?.cancel()
        connectWatchdogJob?.cancel()
        super.onCleared()
    }

    init {
        observeSelectedNode()
        observeConnectionDuration()
        observeNetworkInfoTriggers()
        observeMemoryUsage()
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

    private fun observeConnectionDuration() {
        viewModelScope.launch {
            vpnState.collect { state ->
                if (!state.isConnected) {
                    _connectionDuration.value = "00:00:00"
                    return@collect
                }

                while (isActive && VpnStateManager.vpnState.value.isConnected) {
                    _connectionDuration.value = VpnStateManager.vpnState.value.connectionTime.formatDuration()
                    delay(1_000)
                }
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


    private fun observeMemoryUsage() {
        viewModelScope.launch(Dispatchers.Default) {
            while (isActive) {
                _memoryUsage.value = readMemoryUsage()
                delay(15_000)
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

        return when (val result = vpnRepository.switchToNode(currentNode)) {
            is VpnConnectionResult.Success -> {
                _uiMessage.tryEmit("已切换为${mode.displayName}")
                true
            }

            is VpnConnectionResult.InvalidConfig -> {
                PreferenceManager.setRoutingMode(appContext, previousMode)
                handleConnectionFailure(appContext, result.error)
                false
            }

            is VpnConnectionResult.Failure -> {
                PreferenceManager.setRoutingMode(appContext, previousMode)
                val details = result.throwable.message?.takeIf { it.isNotBlank() }
                if (details != null) {
                    handleConnectionFailure(appContext, details)
                } else {
                    _uiMessage.tryEmit(appContext.getString(com.aerobox.R.string.operation_failed))
                }
                false
            }

            VpnConnectionResult.NoNodeAvailable -> {
                PreferenceManager.setRoutingMode(appContext, previousMode)
                false
            }
        }
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
            when (val result = vpnRepository.connectNode(node)) {
                is VpnConnectionResult.Success -> {
                    _selectedNode.value = result.node
                    PreferenceManager.setLastSelectedNodeId(appContext, result.node.id)
                    if (result.node.id != node.id) {
                        _uiMessage.tryEmit("订阅更新后，已使用匹配的新节点：${result.node.name}")
                    }
                    startConnectWatchdog(context)
                }

                is VpnConnectionResult.InvalidConfig -> {
                    handleConnectionFailure(context, result.error)
                }

                is VpnConnectionResult.Failure -> {
                    connectWatchdogJob?.cancel()
                    connectWatchdogJob = null
                    val details = result.throwable.message?.takeIf { msg -> msg.isNotBlank() }
                    if (details != null) {
                        handleConnectionFailure(context, details)
                    } else {
                        _uiMessage.tryEmit(context.getString(com.aerobox.R.string.operation_failed))
                    }
                }

                VpnConnectionResult.NoNodeAvailable -> {
                    _uiMessage.tryEmit(context.getString(com.aerobox.R.string.add_node_first))
                }
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
            when (val result = vpnRepository.switchToNode(node)) {
                is VpnConnectionResult.Success -> {
                    _selectedNode.value = result.node
                    PreferenceManager.setLastSelectedNodeId(appContext, result.node.id)
                }
                is VpnConnectionResult.InvalidConfig -> handleConnectionFailure(appContext, result.error)
                is VpnConnectionResult.Failure -> {
                    val details = result.throwable.message?.takeIf { it.isNotBlank() }
                    if (details != null) {
                        handleConnectionFailure(appContext, details)
                    } else {
                        _uiMessage.tryEmit(appContext.getString(com.aerobox.R.string.operation_failed))
                    }
                }
                VpnConnectionResult.NoNodeAvailable -> Unit
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
        return vpnRepository.urlTestNode(
            node = node,
            localDns = settings.localDns,
            ipv6Mode = settings.ipv6Mode,
            timeoutMs = NODE_TEST_TIMEOUT_MS
        )
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
                ConnectionFixAction.UPDATE_GEO -> GeoAssetManager.updateAll(appContext)
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

    private suspend fun fetchPublicIp(node: ProxyNode?): String = withContext(Dispatchers.IO) {
        val client = ipCheckClient
        val directIpv4Endpoints = listOf(
            "https://4.ipw.cn",
            "https://api.ip.sb/ip"
        )
        val directIpv6Endpoints = listOf(
            "https://6.ipw.cn",
            "https://api6.ipify.org"
        )
        val proxiedIpv4Endpoints = listOf(
            "https://api4.ipify.org",
            "https://v4.ident.me"
        )
        val proxiedIpv6Endpoints = listOf(
            "https://api6.ipify.org",
            "https://v6.ident.me"
        )
        val preferIpv6Only = isIpv6Literal(node?.server.orEmpty())
        val useProxyFriendlyEndpoints = vpnState.value.isConnected
        val ipv4Endpoints = if (useProxyFriendlyEndpoints) {
            proxiedIpv4Endpoints
        } else {
            directIpv4Endpoints + proxiedIpv4Endpoints
        }
        val ipv6Endpoints = if (useProxyFriendlyEndpoints) {
            proxiedIpv6Endpoints
        } else {
            directIpv6Endpoints + proxiedIpv6Endpoints
        }
        val endpointGroups = if (preferIpv6Only) {
            listOf(ipv6Endpoints)
        } else {
            listOf(ipv4Endpoints, ipv6Endpoints)
        }

        try {
            for (group in endpointGroups) {
                val detected = supervisorScope {
                    val uniqueEndpoints = group.distinct()
                    val resultChannel = Channel<String?>(capacity = uniqueEndpoints.size)
                    val jobs = uniqueEndpoints.map { endpoint ->
                        launch {
                            resultChannel.trySend(fetchIpFromEndpoint(client, endpoint))
                        }
                    }

                    try {
                        repeat(jobs.size) {
                            val ip = resultChannel.receive()
                            if (!ip.isNullOrBlank()) {
                                return@supervisorScope ip
                            }
                        }
                        null
                    } finally {
                        jobs.forEach { it.cancel() }
                        resultChannel.close()
                    }
                }

                if (!detected.isNullOrBlank()) {
                    return@withContext detected
                }
            }
            "检测失败，点击重试"
        } finally {
            client.dispatcher.cancelAll()
            client.connectionPool.evictAll()
        }
    }

    private suspend fun fetchIpFromEndpoint(client: OkHttpClient, endpoint: String): String? =
        kotlinx.coroutines.suspendCancellableCoroutine { continuation ->
            val request = Request.Builder()
                .url(endpoint)
                .header("User-Agent", "AeroBox/IP-Check")
                .header("Connection", "close")
                .build()
            val call = client.newCall(request)
            continuation.invokeOnCancellation { call.cancel() }
            call.enqueue(object : Callback {
                override fun onFailure(call: Call, e: IOException) {
                    if (continuation.isActive) {
                        continuation.resume(null)
                    }
                }

                override fun onResponse(call: Call, response: Response) {
                    response.use {
                        val ip = if (it.isSuccessful) it.body.string().trim() else null
                        val normalized = ip?.takeIf(::isLikelyIpAddress)
                        if (continuation.isActive) {
                            continuation.resume(normalized)
                        }
                    }
                }
            })
        }

    private suspend fun loadUrlTestSettings(): UrlTestSettings {
        val userLocalDns = PreferenceManager.localDnsFlow(appContext).first()
        val ipv6Mode = PreferenceManager.ipv6ModeFlow(appContext).first()
        val safeLocalDns = if (userLocalDns.contains("[")) "223.5.5.5" else userLocalDns
        return UrlTestSettings(
            localDns = safeLocalDns,
            ipv6Mode = ipv6Mode
        )
    }

    private fun isLikelyIpAddress(value: String): Boolean {
        val text = value.trim()
        return IPV4_REGEX.matches(text) || (text.contains(':') && IPV6_REGEX.matches(text))
    }

    private fun isIpv6Literal(host: String): Boolean {
        val value = host
            .trim()
            .removePrefix("[")
            .removeSuffix("]")
            .substringBefore('%')
        if (!value.contains(':')) return false
        return value.all { it.isDigit() || it in "abcdefABCDEF:." }
    }

    private fun handleConnectionFailure(context: Context, rawError: String) {
        connectWatchdogJob?.cancel()
        connectWatchdogJob = null
        val issue = ConnectionDiagnostics.classify(rawError)
        _connectionIssue.value = issue
        _uiMessage.tryEmit("${context.getString(com.aerobox.R.string.operation_failed)}: ${issue.title}")
    }
}
