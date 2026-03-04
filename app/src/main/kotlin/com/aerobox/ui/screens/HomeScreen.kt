package com.aerobox.ui.screens

import android.app.Activity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.aerobox.AeroBoxApplication
import com.aerobox.R
import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.TrafficStats
import com.aerobox.data.model.VpnState
import com.aerobox.ui.components.ConnectionCard
import com.aerobox.ui.components.NodeListSheet
import com.aerobox.ui.components.QuickActionsCard
import com.aerobox.ui.components.TrafficStatsCard
import com.aerobox.ui.theme.SingBoxVPNTheme
import com.aerobox.utils.NetworkUtils
import com.aerobox.utils.showToast
import com.aerobox.viewmodel.HomeViewModel
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

@Composable
fun HomeScreen(viewModel: HomeViewModel = viewModel()) {
    val context = LocalContext.current
    val vpnState by viewModel.vpnState.collectAsStateWithLifecycle()
    val trafficStats by viewModel.trafficStats.collectAsStateWithLifecycle()
    val selectedNode by viewModel.selectedNode.collectAsStateWithLifecycle()
    val connectionDuration by viewModel.connectionDuration.collectAsStateWithLifecycle()
    val allNodes by viewModel.allNodes.collectAsStateWithLifecycle()
    var showNodeList by remember { mutableStateOf(false) }

    val permissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            viewModel.onVpnPermissionGranted(context)
        } else {
            context.showToast(context.getString(R.string.permission_required))
        }
    }

    HomeScreenContent(
        vpnState = vpnState,
        trafficStats = trafficStats,
        selectedNodeName = selectedNode?.name ?: stringResource(R.string.not_selected),
        selectedNodeAddress = selectedNode?.let { "${it.server}:${it.port}" } ?: "--",
        hasSelectedNode = selectedNode != null,
        connectionDuration = connectionDuration,
        onToggleConnection = {
            val permissionIntent = viewModel.toggleConnection(context)
            if (permissionIntent != null) {
                permissionLauncher.launch(permissionIntent)
            }
        },
        onNodeNameClick = { showNodeList = true },
        onLatencyTest = {
            viewModel.testSelectedNodeLatency { latency ->
                val text = if (latency >= 0) {
                    "${context.getString(R.string.test_result_prefix)} ${latency}ms"
                } else {
                    context.getString(R.string.operation_failed)
                }
                context.showToast(text)
            }
        },
        onUpdateSubscription = {
            viewModel.updateAllSubscriptions()
            context.showToast(context.getString(R.string.updating))
        }
    )

    // Node list bottom sheet
    if (showNodeList) {
        NodeListSheet(
            nodes = allNodes,
            selectedNodeId = selectedNode?.id ?: -1,
            onNodeSelected = { node ->
                viewModel.selectNode(node)
                showNodeList = false
            },
            onTestAll = {
                viewModel.testAllNodesLatency()
            },
            onDismiss = { showNodeList = false }
        )
    }
}

@Composable
private fun HomeScreenContent(
    vpnState: VpnState,
    trafficStats: TrafficStats,
    selectedNodeName: String,
    selectedNodeAddress: String,
    hasSelectedNode: Boolean,
    connectionDuration: String,
    onToggleConnection: () -> Unit,
    onNodeNameClick: () -> Unit,
    onLatencyTest: () -> Unit,
    onUpdateSubscription: () -> Unit
) {
    val listState = rememberLazyListState()
    LazyColumn(
        state = listState,
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item {
            ConnectionCard(
                isConnected = vpnState.isConnected,
                nodeName = selectedNodeName,
                nodeAddress = selectedNodeAddress,
                connectionDuration = connectionDuration,
                onToggleConnection = onToggleConnection,
                onNodeNameClick = onNodeNameClick
            )
        }

        item {
            TrafficStatsCard(stats = trafficStats)
        }

        item {
            QuickActionsCard(
                onLatencyTest = onLatencyTest,
                onUpdateSubscription = onUpdateSubscription
            )
        }

        if (!hasSelectedNode) {
            item {
                Text(
                    text = stringResource(R.string.hint_add_subscription),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Preview(showBackground = true)
@Composable
private fun HomeScreenPreview() {
    SingBoxVPNTheme {
        HomeScreenContent(
            vpnState = VpnState(isConnected = true, connectionTime = System.currentTimeMillis()),
            trafficStats = TrafficStats(
                uploadSpeed = 12_300,
                downloadSpeed = 88_000,
                totalUpload = 33_554_432,
                totalDownload = 134_217_728
            ),
            selectedNodeName = "Tokyo-01",
            selectedNodeAddress = "1.1.1.1:443",
            hasSelectedNode = true,
            connectionDuration = "00:20:13",
            onToggleConnection = {},
            onNodeNameClick = {},
            onLatencyTest = {},
            onUpdateSubscription = {}
        )
    }
}
