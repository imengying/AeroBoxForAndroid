package com.aerobox.viewmodel

import android.app.Application
import android.content.Context
import android.content.Intent
import android.net.VpnService
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.aerobox.AeroBoxApplication
import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.TrafficStats
import com.aerobox.data.model.VpnState
import com.aerobox.data.repository.SubscriptionRepository
import com.aerobox.data.repository.VpnRepository
import com.aerobox.service.VpnStateManager
import com.aerobox.utils.PreferenceManager
import com.aerobox.utils.formatDuration
import com.aerobox.utils.showToast
import com.aerobox.utils.toTrafficStats
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

import com.aerobox.data.model.RoutingMode

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

    private var statsJob: Job? = null

    init {
        observeSelectedNode()
        observeConnectionDuration()
        observeTrafficStats()
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
                val config = vpnRepository.buildConfig(node)
                val configError = vpnRepository.checkConfig(config)
                if (configError != null) {
                    context.showToast("${context.getString(com.aerobox.R.string.operation_failed)}: $configError")
                    return@launch
                }
                VpnStateManager.updateConnectionState(true, node)
                vpnRepository.startVpn(config)
            }.onFailure {
                VpnStateManager.updateConnectionState(false, null)
                context.showToast(context.getString(com.aerobox.R.string.operation_failed))
            }
        }
    }

    private fun stopConnection() {
        runCatching { vpnRepository.stopVpn() }
        VpnStateManager.updateConnectionState(false, null)
        VpnStateManager.resetStats()
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
}
