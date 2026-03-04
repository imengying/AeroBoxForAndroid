package com.aerobox.viewmodel

import android.app.Application
import android.content.Context
import android.content.Intent
import android.net.VpnService
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.aerobox.AeroBoxApplication
import com.aerobox.core.config.ConfigGenerator
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

class HomeViewModel(application: Application) : AndroidViewModel(application) {
    private val appContext = application.applicationContext
    private val nodeDao = AeroBoxApplication.database.proxyNodeDao()
    private val vpnRepository = VpnRepository(appContext)
    private val subscriptionRepository = SubscriptionRepository(appContext)

    val vpnState: StateFlow<VpnState> = VpnStateManager.vpnState
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), VpnState())

    val trafficStats: StateFlow<TrafficStats> = vpnState
        .map { it.toTrafficStats() }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), TrafficStats())

    val allNodes: StateFlow<List<ProxyNode>> = nodeDao.getAllNodes()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

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

                var previous = vpnRepository.getTrafficStats()
                while (isActive && vpnRepository.isRunning.value) {
                    delay(1_000)
                    val current = vpnRepository.getTrafficStats()
                    val totalUpload = current.getOrElse(0) { 0L }
                    val totalDownload = current.getOrElse(1) { 0L }
                    val uploadSpeed = (totalUpload - previous.getOrElse(0) { 0L }).coerceAtLeast(0L)
                    val downloadSpeed = (totalDownload - previous.getOrElse(1) { 0L }).coerceAtLeast(0L)

                    VpnStateManager.updateTrafficStats(
                        uploadSpeed = uploadSpeed,
                        downloadSpeed = downloadSpeed,
                        totalUpload = totalUpload,
                        totalDownload = totalDownload
                    )
                    previous = current
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
                // Read routing/DNS settings
                val routingMode = PreferenceManager.routingModeFlow(appContext)
                    .stateIn(viewModelScope, SharingStarted.Eagerly, RoutingMode.RULE_BASED).value
                val remoteDns = PreferenceManager.remoteDnsFlow(appContext)
                    .stateIn(viewModelScope, SharingStarted.Eagerly, "tls://8.8.8.8").value
                val localDns = PreferenceManager.localDnsFlow(appContext)
                    .stateIn(viewModelScope, SharingStarted.Eagerly, "223.5.5.5").value
                val enableDoh = PreferenceManager.enableDohFlow(appContext)
                    .stateIn(viewModelScope, SharingStarted.Eagerly, true).value
                val enableSocksInbound = PreferenceManager.enableSocksInboundFlow(appContext)
                    .stateIn(viewModelScope, SharingStarted.Eagerly, false).value
                val enableHttpInbound = PreferenceManager.enableHttpInboundFlow(appContext)
                    .stateIn(viewModelScope, SharingStarted.Eagerly, false).value

                val config = ConfigGenerator.generateSingBoxConfig(
                    node = node,
                    routingMode = routingMode,
                    remoteDns = remoteDns,
                    localDns = localDns,
                    enableDoh = enableDoh,
                    enableSocksInbound = enableSocksInbound,
                    enableHttpInbound = enableHttpInbound
                )
                if (!vpnRepository.testConfig(config)) {
                    context.showToast(context.getString(com.aerobox.R.string.operation_failed))
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
            allNodes.value.forEach { node ->
                launch {
                    val latency = com.aerobox.utils.NetworkUtils.pingTcp(node.server, node.port)
                    subscriptionRepository.updateNodeLatency(node.id, latency)
                }
            }
        }
    }
}
