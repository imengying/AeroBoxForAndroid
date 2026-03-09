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
import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.NodeLatencyState
import com.aerobox.data.model.RoutingMode
import com.aerobox.data.model.TrafficStats
import com.aerobox.data.model.VpnState
import com.aerobox.data.repository.SubscriptionRepository
import com.aerobox.data.repository.VpnConnectionResult
import com.aerobox.data.repository.VpnRepository
import com.aerobox.service.VpnStateManager
import com.aerobox.utils.NetworkUtils
import com.aerobox.utils.PreferenceManager
import com.aerobox.utils.formatDuration
import com.aerobox.utils.showToast
import com.aerobox.utils.toTrafficStats
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.drop
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import java.util.concurrent.TimeUnit

class HomeViewModel(application: Application) : AndroidViewModel(application) {
    private companion object {
        const val POST_CONNECT_IP_DETECT_DELAY_MS = 500L
        const val NODE_TEST_TIMEOUT_MS = 5000
        const val NODE_TEST_CONCURRENCY = 4
    }

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

    val subscriptionNames: StateFlow<Map<Long, String>> = subscriptionRepository
        .getAllSubscriptions()
        .map { subs -> subs.associate { it.id to it.name } }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyMap())

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

    private var detectIpJob: Job? = null
    private var connectWatchdogJob: Job? = null
    private val ipDetectClient = OkHttpClient.Builder()
        .callTimeout(1, TimeUnit.SECONDS)
        .connectTimeout(1, TimeUnit.SECONDS)
        .readTimeout(1, TimeUnit.SECONDS)
        .build()

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
                nodes.firstOrNull { it.id == selectedId } ?: nodes.firstOrNull()
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
                delay(2_000)
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


    private suspend fun applyRoutingMode(mode: RoutingMode) {
        val previousMode = routingMode.value
        PreferenceManager.setRoutingMode(appContext, mode)

        val currentNode = vpnState.value.currentNode ?: selectedNode.value
        if (!vpnState.value.isConnected || currentNode == null) {
            return
        }

        when (val result = vpnRepository.switchToNode(currentNode)) {
            is VpnConnectionResult.Success -> {
                appContext.showToast("已切换为${mode.displayName}")
            }

            is VpnConnectionResult.InvalidConfig -> {
                PreferenceManager.setRoutingMode(appContext, previousMode)
                handleConnectionFailure(appContext, result.error)
            }

            is VpnConnectionResult.Failure -> {
                PreferenceManager.setRoutingMode(appContext, previousMode)
                val details = result.throwable.message?.takeIf { it.isNotBlank() }
                if (details != null) {
                    handleConnectionFailure(appContext, details)
                } else {
                    appContext.showToast(appContext.getString(com.aerobox.R.string.operation_failed))
                }
            }

            VpnConnectionResult.NoNodeAvailable -> {
                PreferenceManager.setRoutingMode(appContext, previousMode)
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
            context.showToast(context.getString(com.aerobox.R.string.add_node_first))
            return
        }

        viewModelScope.launch {
            VpnStateManager.clearLastError()
            when (val result = vpnRepository.connectNode(node, refreshDueSubscriptions = true)) {
                is VpnConnectionResult.Success -> {
                    context.showToast(context.getString(com.aerobox.R.string.notification_connecting))
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
                        context.showToast(context.getString(com.aerobox.R.string.operation_failed))
                    }
                }

                VpnConnectionResult.NoNodeAvailable -> {
                    context.showToast(context.getString(com.aerobox.R.string.add_node_first))
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
            delay(12_000)
            if (!vpnState.value.isConnected) {
                val rawError = VpnStateManager.lastError.value ?: "service start timeout"
                handleConnectionFailure(context, rawError)
            }
        }
    }

    fun selectNode(node: ProxyNode) {
        _selectedNode.value = node
        if (!vpnState.value.isConnected) {
            refreshNetworkInfo()
        }
        viewModelScope.launch {
            PreferenceManager.setLastSelectedNodeId(appContext, node.id)
            if (!vpnState.value.isConnected) {
                return@launch
            }
            when (val result = vpnRepository.switchToNode(node)) {
                is VpnConnectionResult.Success -> Unit
                is VpnConnectionResult.InvalidConfig -> handleConnectionFailure(appContext, result.error)
                is VpnConnectionResult.Failure -> {
                    val details = result.throwable.message?.takeIf { it.isNotBlank() }
                    if (details != null) {
                        handleConnectionFailure(appContext, details)
                    } else {
                        appContext.showToast(appContext.getString(com.aerobox.R.string.operation_failed))
                    }
                }
                VpnConnectionResult.NoNodeAvailable -> Unit
            }
        }
    }

    fun testSubscriptionNodesLatency(nodes: List<ProxyNode>) {
        viewModelScope.launch {
            val semaphore = Semaphore(NODE_TEST_CONCURRENCY)
            val jobs = nodes.map { node ->
                launch {
                    subscriptionRepository.updateNodeLatency(node.id, NodeLatencyState.TESTING)
                    val latency = semaphore.withPermit { testNodeLatency(node) }
                    subscriptionRepository.updateNodeLatency(
                        node.id,
                        latency.takeIf { it > 0 } ?: NodeLatencyState.FAILED
                    )
                }
            }
            jobs.forEach { it.join() }
        }
    }

    fun testSingleNodeLatency(node: ProxyNode) {
        viewModelScope.launch {
            subscriptionRepository.updateNodeLatency(node.id, NodeLatencyState.TESTING)
            val latency = testNodeLatency(node)
            subscriptionRepository.updateNodeLatency(
                node.id,
                latency.takeIf { it > 0 } ?: NodeLatencyState.FAILED
            )
        }
    }

    private suspend fun testNodeLatency(node: ProxyNode): Int {
        return vpnRepository.urlTestNode(
            node = node,
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

            val networkNode = vpnState.value.currentNode ?: selectedNode.value
            _detectedIp.value = appContext.getString(com.aerobox.R.string.detecting_ip)
            _detectedIp.value = fetchPublicIp(networkNode)
        }
    }

    fun dismissConnectionIssue() {
        _connectionIssue.value = null
    }

    fun applyConnectionFix(context: Context, fixAction: ConnectionFixAction) {
        viewModelScope.launch {
            val fixSuccess = when (fixAction) {
                ConnectionFixAction.UPDATE_GEO -> GeoAssetManager.updateAll(appContext)
                ConnectionFixAction.SWITCH_GLOBAL_MODE -> {
                    applyRoutingMode(RoutingMode.GLOBAL_PROXY)
                    true
                }

                ConnectionFixAction.REFRESH_SUBSCRIPTIONS -> {
                    val subscriptions = subscriptionRepository.getAllSubscriptions().first()
                    subscriptionRepository.refreshAllSubscriptions(subscriptions)
                    true
                }
            }

            if (fixSuccess) {
                context.showToast(context.getString(com.aerobox.R.string.connection_fix_success))
            } else {
                context.showToast(context.getString(com.aerobox.R.string.connection_fix_failed))
            }
            _connectionIssue.value = null
        }
    }

    private suspend fun fetchPublicIp(node: ProxyNode?): String = withContext(Dispatchers.IO) {
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
        val ipv4Endpoints = if (useProxyFriendlyEndpoints) proxiedIpv4Endpoints else directIpv4Endpoints + proxiedIpv4Endpoints
        val ipv6Endpoints = if (useProxyFriendlyEndpoints) proxiedIpv6Endpoints else directIpv6Endpoints + proxiedIpv6Endpoints
        val endpointGroups = if (preferIpv6Only) listOf(ipv6Endpoints) else listOf(ipv4Endpoints, ipv6Endpoints)

        for (group in endpointGroups) {
            for (endpoint in group) {
                val ip = runCatching {
                    val request = Request.Builder()
                        .url(endpoint)
                        .header("User-Agent", "AeroBox/IP-Check")
                        .build()
                    ipDetectClient.newCall(request).execute().use { response ->
                        if (!response.isSuccessful) return@use null
                        response.body?.string()?.trim()
                    }
                }.getOrNull()
                if (!ip.isNullOrBlank() && isLikelyIpAddress(ip)) {
                    return@withContext ip
                }
            }
        }
        "检测失败，点击重试"
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

    private fun isLikelyIpAddress(value: String): Boolean {
        val text = value.trim()
        val ipv4 = Regex("""^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$""")
        val ipv6 = Regex("""^[0-9A-Fa-f:]+(%[0-9A-Za-z._~-]+)?$""")
        return ipv4.matches(text) || (text.contains(':') && ipv6.matches(text))
    }

    private fun handleConnectionFailure(context: Context, rawError: String) {
        val issue = ConnectionDiagnostics.classify(rawError)
        _connectionIssue.value = issue
        context.showToast("${context.getString(com.aerobox.R.string.operation_failed)}: ${issue.title}")
    }
}
