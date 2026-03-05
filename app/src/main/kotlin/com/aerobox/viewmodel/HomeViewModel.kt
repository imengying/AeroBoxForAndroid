package com.aerobox.viewmodel

import android.app.Application
import android.content.Context
import android.content.Intent
import android.net.VpnService
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.aerobox.AeroBoxApplication
import com.aerobox.core.geo.GeoAssetManager
import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.RoutingMode
import com.aerobox.data.model.TrafficStats
import com.aerobox.data.model.VpnState
import com.aerobox.data.repository.SubscriptionRepository
import com.aerobox.data.repository.VpnRepository
import com.aerobox.service.VpnStateManager
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
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.URL

enum class ConnectionFixAction(val label: String) {
    UPDATE_GEO("更新 Geo 资源"),
    SWITCH_GLOBAL_MODE("切换为全局模式"),
    REFRESH_SUBSCRIPTIONS("重新拉取订阅")
}

data class ConnectionIssue(
    val title: String,
    val message: String,
    val rawError: String,
    val fixAction: ConnectionFixAction? = null
)

class HomeViewModel(application: Application) : AndroidViewModel(application) {
    private val appContext = application.applicationContext
    private val nodeDao = AeroBoxApplication.database.proxyNodeDao()
    private val vpnRepository = VpnRepository(appContext)
    private val subscriptionRepository = SubscriptionRepository(appContext)

    val vpnState: StateFlow<VpnState> = VpnStateManager.vpnState
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), VpnState())

    val routingMode: StateFlow<RoutingMode> = PreferenceManager.routingModeFlow(appContext)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), RoutingMode.RULE_BASED)

    fun setRoutingMode(mode: RoutingMode) {
        viewModelScope.launch {
            PreferenceManager.setRoutingMode(appContext, mode)
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

    private var statsJob: Job? = null
    private var detectIpJob: Job? = null
    private var connectWatchdogJob: Job? = null

    init {
        observeSelectedNode()
        observeConnectionDuration()
        observeTrafficStats()
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

    private fun observeTrafficStats() {
        statsJob?.cancel()
        statsJob = viewModelScope.launch {
            vpnRepository.isRunning.collect { running ->
                if (!running) {
                    VpnStateManager.resetStats()
                    if (vpnState.value.isConnected) {
                        VpnStateManager.updateConnectionState(false, null)
                    }
                    return@collect
                }

                val uid = android.os.Process.myUid()
                var prevTx = android.net.TrafficStats.getUidTxBytes(uid)
                var prevRx = android.net.TrafficStats.getUidRxBytes(uid)

                connectWatchdogJob?.cancel()
                connectWatchdogJob = null

                while (isActive && vpnRepository.isRunning.value) {
                    delay(1_000)
                    val curTx = android.net.TrafficStats.getUidTxBytes(uid)
                    val curRx = android.net.TrafficStats.getUidRxBytes(uid)
                    val uploadSpeed = (curTx - prevTx).coerceAtLeast(0L)
                    val downloadSpeed = (curRx - prevRx).coerceAtLeast(0L)

                    VpnStateManager.updateTrafficStats(
                        uploadSpeed = uploadSpeed,
                        downloadSpeed = downloadSpeed,
                        totalUpload = curTx,
                        totalDownload = curRx
                    )
                    prevTx = curTx
                    prevRx = curRx
                }
            }
        }
    }

    fun toggleConnection(context: Context): Intent? {
        if (!vpnState.value.isConnected) {
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
            runCatching {
                val autoUpdateSubscription = PreferenceManager
                    .autoUpdateSubscriptionFlow(appContext)
                    .first()
                if (autoUpdateSubscription) {
                    val subscriptions = subscriptionRepository.getAllSubscriptions().first()
                    subscriptionRepository.refreshDueSubscriptions(subscriptions)
                }

                val config = vpnRepository.buildConfig(node)
                val configError = vpnRepository.checkConfig(config)
                if (configError != null) {
                    handleConnectionFailure(context, configError)
                    return@launch
                }
                vpnRepository.startVpn(config, node.id)
                context.showToast(context.getString(com.aerobox.R.string.notification_connecting))
                startConnectWatchdog(context)
            }.onFailure {
                connectWatchdogJob?.cancel()
                connectWatchdogJob = null
                VpnStateManager.updateConnectionState(false, null)
                val details = it.message?.takeIf { msg -> msg.isNotBlank() }
                if (details != null) {
                    handleConnectionFailure(context, details)
                } else {
                    context.showToast(context.getString(com.aerobox.R.string.operation_failed))
                }
            }
        }
    }

    private fun stopConnection() {
        connectWatchdogJob?.cancel()
        connectWatchdogJob = null
        runCatching { vpnRepository.stopVpn() }
        VpnStateManager.updateConnectionState(false, null)
        VpnStateManager.resetStats()
    }

    private fun startConnectWatchdog(context: Context) {
        connectWatchdogJob?.cancel()
        connectWatchdogJob = viewModelScope.launch {
            delay(12_000)
            if (!vpnRepository.isRunning.value && !vpnState.value.isConnected) {
                _connectionIssue.value = ConnectionIssue(
                    title = "连接超时",
                    message = "启动服务超时，请检查节点配置或切换节点后重试。",
                    rawError = "service start timeout"
                )
                context.showToast("连接超时，请查看日志后重试")
            }
        }
    }

    fun selectNode(node: ProxyNode) {
        _selectedNode.value = node
        viewModelScope.launch {
            PreferenceManager.setLastSelectedNodeId(appContext, node.id)
        }
    }

    fun testSelectedNodeLatency(onResult: (Int) -> Unit = {}) {
        val node = selectedNode.value ?: return
        viewModelScope.launch {
            val latency = com.aerobox.utils.NetworkUtils.pingTcp(node.server, node.port)
            subscriptionRepository.updateNodeLatency(node.id, latency)
            onResult(latency)
        }
    }

    fun updateAllSubscriptions() {
        viewModelScope.launch {
            val subscriptions = subscriptionRepository.getAllSubscriptions().first()
            subscriptionRepository.refreshAllSubscriptions(subscriptions)
        }
    }

    fun testAllNodesLatency() {
        viewModelScope.launch {
            val jobs = allNodes.value.map { node ->
                launch {
                    val latency = com.aerobox.utils.NetworkUtils.pingTcp(node.server, node.port)
                    subscriptionRepository.updateNodeLatency(node.id, latency)
                }
            }
            jobs.forEach { it.join() }

            // Auto-select best (lowest latency) node after all tests complete
            val updatedNodes = nodeDao.getAllNodes().first()
            val bestNode = updatedNodes
                .filter { it.latency > 0 }
                .minByOrNull { it.latency }
            if (bestNode != null) {
                selectNode(bestNode)
            }
        }
    }

    fun testSingleNodeLatency(node: ProxyNode) {
        viewModelScope.launch {
            val latency = com.aerobox.utils.NetworkUtils.pingTcp(node.server, node.port)
            subscriptionRepository.updateNodeLatency(node.id, latency)
        }
    }

    fun refreshNetworkInfo() {
        detectIpJob?.cancel()
        detectIpJob = viewModelScope.launch {
            _detectedIp.value = "检测中..."
            _detectedIp.value = fetchPublicIp(selectedNode.value)
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
                    PreferenceManager.setRoutingMode(appContext, RoutingMode.GLOBAL_PROXY)
                    true
                }

                ConnectionFixAction.REFRESH_SUBSCRIPTIONS -> {
                    val subscriptions = subscriptionRepository.getAllSubscriptions().first()
                    subscriptionRepository.refreshAllSubscriptions(subscriptions)
                    true
                }
            }

            if (fixSuccess) {
                context.showToast("修复已完成，请重试连接")
            } else {
                context.showToast("修复失败，请检查网络后重试")
            }
            _connectionIssue.value = null
        }
    }

    private suspend fun fetchPublicIp(node: ProxyNode?): String = withContext(Dispatchers.IO) {
        val ipv4Endpoints = listOf(
            "https://api4.ipify.org",
            "https://ipv4.icanhazip.com",
            "https://v4.ident.me"
        )
        val ipv6Endpoints = listOf(
            "https://api6.ipify.org",
            "https://ipv6.icanhazip.com",
            "https://v6.ident.me"
        )

        val preferIpv6Only = isIpv6Literal(node?.server.orEmpty())
        val endpointGroups = if (preferIpv6Only) {
            listOf(ipv6Endpoints)
        } else {
            listOf(ipv4Endpoints, ipv6Endpoints)
        }

        for (group in endpointGroups) {
            for (endpoint in group) {
                val ip = runCatching {
                    URL(endpoint).openStream().bufferedReader().use { it.readText().trim() }
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
        val issue = classifyConnectionIssue(rawError)
        _connectionIssue.value = issue
        context.showToast("${context.getString(com.aerobox.R.string.operation_failed)}: ${issue.title}")
    }

    private fun classifyConnectionIssue(rawError: String): ConnectionIssue {
        val msg = rawError.lowercase()

        return when {
            msg.contains("geosite") ||
                    msg.contains("geoip") ||
                    (msg.contains("router") && msg.contains("database")) -> {
                ConnectionIssue(
                    title = "Geo 规则资源异常",
                    message = "检测到 GeoIP/GeoSite 数据库不可用或格式不兼容。",
                    rawError = rawError,
                    fixAction = ConnectionFixAction.UPDATE_GEO
                )
            }

            msg.contains("rule") ||
                    (msg.contains("router") && msg.contains("parse")) -> {
                ConnectionIssue(
                    title = "路由规则异常",
                    message = "当前规则模式可能与节点配置不兼容，建议先切换到全局模式。",
                    rawError = rawError,
                    fixAction = ConnectionFixAction.SWITCH_GLOBAL_MODE
                )
            }

            msg.contains("outbound") ||
                    msg.contains("node") ||
                    msg.contains("subscription") ||
                    msg.contains("proxy") -> {
                ConnectionIssue(
                    title = "节点或订阅可能失效",
                    message = "节点参数可能已过期，建议重新拉取订阅后再连接。",
                    rawError = rawError,
                    fixAction = ConnectionFixAction.REFRESH_SUBSCRIPTIONS
                )
            }

            else -> {
                ConnectionIssue(
                    title = "连接配置异常",
                    message = "请检查节点、DNS、分流设置，必要时更新订阅后重试。",
                    rawError = rawError
                )
            }
        }
    }
}
