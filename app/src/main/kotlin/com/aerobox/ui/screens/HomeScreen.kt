package com.aerobox.ui.screens

import android.Manifest
import android.app.Activity
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.aerobox.R
import com.aerobox.data.model.RoutingMode
import com.aerobox.ui.components.ConnectionCard
import com.aerobox.ui.components.NodeListSheet
import com.aerobox.ui.components.TrafficStatsCard
import com.aerobox.core.AppEventBus
import com.aerobox.core.connection.ConnectionFixAction
import com.aerobox.ui.components.AppSnackbarHost
import com.aerobox.viewmodel.HomeViewModel
import androidx.compose.runtime.LaunchedEffect
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch

@Composable
fun HomeScreen(viewModel: HomeViewModel = viewModel()) {
    val context = LocalContext.current
    val vpnState by viewModel.vpnState.collectAsStateWithLifecycle()
    val trafficStats by viewModel.trafficStats.collectAsStateWithLifecycle()
    val isConnecting by viewModel.isConnecting.collectAsStateWithLifecycle()
    val selectedNode by viewModel.selectedNode.collectAsStateWithLifecycle()
    val connectionDuration by viewModel.connectionDuration.collectAsStateWithLifecycle()
    val allNodes by viewModel.allNodes.collectAsStateWithLifecycle()
    val routingMode by viewModel.routingMode.collectAsStateWithLifecycle()
    val detectedIp by viewModel.detectedIp.collectAsStateWithLifecycle()
    val memoryUsage by viewModel.memoryUsage.collectAsStateWithLifecycle()
    val connectionIssue by viewModel.connectionIssue.collectAsStateWithLifecycle()
    var showNodeList by remember { mutableStateOf(false) }
    val snackbarHostState = remember { SnackbarHostState() }
    val snackbarScope = rememberCoroutineScope()

    val notificationPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (!granted) {
            snackbarScope.launch {
                snackbarHostState.showSnackbar(context.getString(R.string.notification_permission_hint))
            }
        }
        viewModel.onVpnPermissionGranted(context)
    }
    val permissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            ensureNotificationPermissionThenStart(
                context = context,
                onContinue = { viewModel.onVpnPermissionGranted(context) },
                onRequest = { permission -> notificationPermissionLauncher.launch(permission) }
            )
        } else {
            snackbarScope.launch {
                snackbarHostState.showSnackbar(context.getString(R.string.permission_required))
            }
        }
    }

    val listState = rememberLazyListState()

    LaunchedEffect(Unit) {
        AppEventBus.showNodeSelector.collect {
            showNodeList = true
        }
    }
    LaunchedEffect(viewModel) {
        viewModel.uiMessage.collectLatest { message ->
            snackbarHostState.showSnackbar(message)
        }
    }
    Box(modifier = Modifier.fillMaxSize()) {
        LazyColumn(
            state = listState,
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(top = 80.dp, bottom = 24.dp, start = 16.dp, end = 16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            item {
                Column(verticalArrangement = Arrangement.spacedBy(5.dp)) {
                    ConnectionCard(
                        isConnected = vpnState.isConnected,
                        isConnecting = isConnecting,
                        connectionDuration = connectionDuration,
                        onToggleConnection = {
                            if (vpnState.isConnected || isConnecting) {
                                viewModel.toggleConnection(context)
                            } else {
                                val permissionIntent = VpnService.prepare(context)
                                if (permissionIntent != null) {
                                    permissionLauncher.launch(permissionIntent)
                                } else {
                                    ensureNotificationPermissionThenStart(
                                        context = context,
                                        onContinue = { viewModel.onVpnPermissionGranted(context) },
                                        onRequest = { permission -> notificationPermissionLauncher.launch(permission) }
                                    )
                                }
                            }
                        },
                    )
                }
            }

            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    NodeSelectorCard(
                        nodeName = selectedNode?.name ?: stringResource(R.string.not_selected),
                        nodeAddress = selectedNode?.type?.displayName() ?: "--",
                        onClick = { showNodeList = true },
                        modifier = Modifier.weight(0.5f).height(92.dp)
                    )
                    TrafficStatsCard(
                        stats = trafficStats,
                        modifier = Modifier.weight(0.5f).height(92.dp)
                    )
                }
            }

            item {
                RoutingModeRow(
                    selected = routingMode,
                    onSelect = { viewModel.setRoutingMode(it) }
                )
            }

            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    NetworkDetectCard(
                        ip = detectedIp,
                        onClick = { viewModel.refreshNetworkInfo() },
                        modifier = Modifier.weight(0.5f).height(92.dp)
                    )
                    MemoryUsageCard(
                        memoryUsage = memoryUsage,
                        modifier = Modifier.weight(0.5f).height(92.dp)
                    )
                }
            }

            if (selectedNode == null) {
                item {
                    Text(
                        text = stringResource(R.string.hint_add_subscription),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
        AppSnackbarHost(
            hostState = snackbarHostState,
            modifier = Modifier.align(Alignment.BottomCenter)
        )
    }

    // Node list bottom sheet
    if (showNodeList) {
        val subscriptions by viewModel.subscriptions.collectAsStateWithLifecycle()
        NodeListSheet(
            nodes = allNodes,
            subscriptions = subscriptions,
            selectedNodeId = selectedNode?.id ?: -1,
            onNodeSelected = { node ->
                viewModel.selectNode(node)
                showNodeList = false
            },
            onTestSubscription = { viewModel.testSubscriptionNodesLatency(it) },
            onTestNode = { node -> viewModel.testSingleNodeLatency(node) },
            onDismiss = { showNodeList = false }
        )
    }

    connectionIssue?.let { issue ->
        AlertDialog(
            onDismissRequest = { viewModel.dismissConnectionIssue() },
            title = { Text(issue.title) },
            text = {
                Text(
                    buildString {
                        append(issue.message)
                        if (issue.rawError.isNotBlank()) {
                            append("\n\n原始错误：")
                            append(issue.rawError.take(220))
                        }
                    }
                )
            },
            confirmButton = {
                val action = issue.fixAction
                if (action != null) {
                    TextButton(
                        onClick = { viewModel.applyConnectionFix(context, action) }
                    ) {
                        Text(action.label)
                    }
                } else {
                    TextButton(onClick = { viewModel.dismissConnectionIssue() }) {
                        Text("知道了")
                    }
                }
            },
            dismissButton = {
                TextButton(onClick = { viewModel.dismissConnectionIssue() }) {
                    Text(
                        if (issue.fixAction == ConnectionFixAction.REFRESH_SUBSCRIPTIONS) {
                            "稍后手动处理"
                        } else {
                            "取消"
                        }
                    )
                }
            }
        )
    }
}

private fun ensureNotificationPermissionThenStart(
    context: android.content.Context,
    onContinue: () -> Unit,
    onRequest: (String) -> Unit
) {
    val needsPermission = Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
        ContextCompat.checkSelfPermission(
            context,
            Manifest.permission.POST_NOTIFICATIONS
        ) != PackageManager.PERMISSION_GRANTED

    if (needsPermission) {
        onRequest(Manifest.permission.POST_NOTIFICATIONS)
    } else {
        onContinue()
    }
}

@Composable
private fun MemoryUsageCard(
    memoryUsage: String,
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainerHigh
        )
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 14.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp, Alignment.CenterVertically),
            horizontalAlignment = Alignment.Start
        ) {
            Text(
                text = "内存占用",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                text = memoryUsage,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSurface,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}

@Composable
private fun NetworkDetectCard(
    ip: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainerHigh
        )
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 14.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp, Alignment.CenterVertically),
            horizontalAlignment = Alignment.Start
        ) {
            Text(
                text = "网络检测",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                text = ip,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSurface,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}

@Composable
private fun NodeSelectorCard(
    nodeName: String,
    nodeAddress: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainerHigh
        )
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 14.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(3.dp, Alignment.CenterVertically),
            horizontalAlignment = Alignment.Start
        ) {
            Text(
                text = nodeName,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSurface,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            Text(
                text = nodeAddress,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                textAlign = TextAlign.Start,
                modifier = Modifier.fillMaxWidth()
            )
        }
    }
}

/**
 * Horizontal mode selector (规则 / 全局 / 直连).
 */
@Composable
private fun RoutingModeRow(
    selected: RoutingMode,
    onSelect: (RoutingMode) -> Unit,
    modifier: Modifier = Modifier
) {
    val modes = listOf(
        RoutingMode.RULE_BASED to "规则",
        RoutingMode.GLOBAL_PROXY to "全局",
        RoutingMode.DIRECT to "直连"
    )

    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainerHigh
        )
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(8.dp),
            contentAlignment = Alignment.Center
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                modes.forEach { (mode, label) ->
                    val isSelected = selected == mode
                    val bgColor by animateColorAsState(
                        targetValue = if (isSelected) MaterialTheme.colorScheme.secondaryContainer
                        else MaterialTheme.colorScheme.surfaceContainerHighest,
                        label = "modeBg"
                    )
                    val textColor by animateColorAsState(
                        targetValue = if (isSelected) MaterialTheme.colorScheme.onSecondaryContainer
                        else MaterialTheme.colorScheme.onSurfaceVariant,
                        label = "modeText"
                    )

                    Box(
                        modifier = Modifier
                            .weight(1f)
                            .clip(RoundedCornerShape(12.dp))
                            .background(bgColor)
                            .clickable { onSelect(mode) }
                            .padding(horizontal = 2.dp, vertical = 12.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = label,
                            style = MaterialTheme.typography.labelLarge,
                            fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal,
                            color = textColor,
                            textAlign = TextAlign.Center,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                }
            }
        }
    }
}
