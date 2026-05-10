package com.aerobox

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.core.view.WindowCompat
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.FilterChip
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.lifecycleScope
import com.aerobox.core.connection.ConnectionDiagnostics
import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.Subscription
import com.aerobox.data.repository.VpnConnectionResult
import com.aerobox.ui.components.AppSnackbarHost
import com.aerobox.ui.components.ProvideAppLocale
import com.aerobox.ui.theme.SingBoxVPNTheme
import com.aerobox.utils.PreferenceManager
import kotlinx.coroutines.launch
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.collectLatest

class NotificationSwitchActivity : ComponentActivity() {
    private val uiMessage = MutableSharedFlow<String>(extraBufferCapacity = 1)
    private val pendingNodeId = MutableStateFlow<Long?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowCompat.setDecorFitsSystemWindows(window, false)

        setContent {
            val darkMode by PreferenceManager.darkModeFlow(this)
                .collectAsStateWithLifecycle(initialValue = "system")
            val dynamicColor by PreferenceManager.dynamicColorFlow(this)
                .collectAsStateWithLifecycle(initialValue = true)

            SingBoxVPNTheme(
                darkTheme = when (darkMode) {
                    "on" -> true
                    "off" -> false
                    else -> androidx.compose.foundation.isSystemInDarkTheme()
                },
                dynamicColor = dynamicColor
            ) {
                val snackbarHostState = remember { SnackbarHostState() }
                val pendingNodeIdState by pendingNodeId.collectAsStateWithLifecycle()
                LaunchedEffect(Unit) {
                    uiMessage.collectLatest { message ->
                        snackbarHostState.showSnackbar(message)
                    }
                }
                ProvideAppLocale {
                    Box(modifier = Modifier.fillMaxSize()) {
                        NotificationSwitchDialog(
                            pendingNodeId = pendingNodeIdState,
                            onDismiss = { finish() },
                            onNodeSelected = { node ->
                                switchToNode(node)
                            }
                        )
                        AppSnackbarHost(
                            hostState = snackbarHostState,
                            modifier = Modifier.align(Alignment.BottomCenter)
                        )
                    }
                }
            }
        }
    }

    private fun switchToNode(node: ProxyNode) {
        if (pendingNodeId.value != null) return
        pendingNodeId.value = node.id
        lifecycleScope.launch {
            when (val result = AeroBoxApplication.vpnRepository.switchToNode(node)) {
                is VpnConnectionResult.Success -> {
                    PreferenceManager.setLastSelectedNodeId(applicationContext, result.node.id)
                    finish()
                }
                VpnConnectionResult.NoNodeAvailable,
                is VpnConnectionResult.InvalidConfig,
                is VpnConnectionResult.Failure -> {
                    uiMessage.tryEmit(
                        ConnectionDiagnostics.userFacingFailureMessage(
                            result = result,
                            operationFailedText = getString(R.string.operation_failed),
                            resolveTitle = ::getString
                        )
                    )
                    pendingNodeId.value = null
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun NotificationSwitchDialog(
    pendingNodeId: Long?,
    onDismiss: () -> Unit,
    onNodeSelected: (ProxyNode) -> Unit
) {
    val allNodes by AeroBoxApplication.database.proxyNodeDao().getAllNodes()
        .collectAsStateWithLifecycle(initialValue = emptyList())
    val subscriptions by AeroBoxApplication.database.subscriptionDao().getAllSubscriptions()
        .collectAsStateWithLifecycle(initialValue = emptyList())
    val selectedNodeId by PreferenceManager.lastSelectedNodeIdFlow(AeroBoxApplication.appInstance)
        .collectAsStateWithLifecycle(initialValue = -1L)
    val groupedNodes = remember(allNodes, subscriptions) {
        val nameMap = subscriptions.associate { it.id to it.name }
        val orderMap = subscriptions.withIndex().associate { it.value.id to it.index }
        allNodes
            .groupBy { it.subscriptionId }
            .filterValues { it.isNotEmpty() }
            .toList()
            .sortedWith(
                compareBy<Pair<Long, List<ProxyNode>>> { (subId, _) ->
                    orderMap[subId] ?: Int.MAX_VALUE
                }.thenBy { (subId, _) ->
                    if (subId == 0L || !nameMap.containsKey(subId)) 1 else 0
                }.thenBy { (subId, _) ->
                    nameMap[subId] ?: AeroBoxApplication.appInstance.getString(R.string.group_ungrouped)
                }
            )
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(Color.Transparent)
            .clickable(onClick = onDismiss),
        contentAlignment = Alignment.Center
    ) {
        Surface(
            shape = RoundedCornerShape(28.dp),
            color = MaterialTheme.colorScheme.surfaceContainerHigh,
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 36.dp)
                .clickable(
                    interactionSource = remember { MutableInteractionSource() },
                    indication = null,
                    onClick = {}
                )
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 14.dp, vertical = 12.dp)
            ) {
                Text(
                    text = stringResource(R.string.switch_node_title),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.padding(top = 2.dp, bottom = 10.dp)
                )

                var selectedGroupIndex by remember { mutableStateOf(0) }

                LazyRow(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    contentPadding = PaddingValues(bottom = 8.dp)
                ) {
                    items(count = groupedNodes.size) { index ->
                        val (subId, _) = groupedNodes[index]
                        val groupName = subscriptions.firstOrNull { it.id == subId }?.name
                            ?: stringResource(R.string.group_ungrouped)
                        FilterChip(
                            selected = selectedGroupIndex == index,
                            onClick = { selectedGroupIndex = index },
                            label = {
                                Text(
                                    text = groupName,
                                    style = MaterialTheme.typography.labelMedium,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                            }
                        )
                    }
                }

                LazyColumn(
                    modifier = Modifier.heightIn(max = 340.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                    contentPadding = PaddingValues(vertical = 4.dp)
                ) {
                    if (groupedNodes.isNotEmpty() && selectedGroupIndex < groupedNodes.size) {
                        val (_, nodes) = groupedNodes[selectedGroupIndex]
                        items(nodes, key = { it.id }) { node ->
                            val isSelected = node.id == selectedNodeId
                            Card(
                                onClick = {
                                    if (pendingNodeId == null) {
                                        onNodeSelected(node)
                                    }
                                },
                                enabled = pendingNodeId == null,
                                modifier = Modifier
                                    .fillMaxWidth(),
                                shape = RoundedCornerShape(16.dp)
                            ) {
                                Column(
                                    modifier = Modifier.padding(horizontal = 14.dp, vertical = 12.dp)
                                ) {
                                    Text(
                                        text = node.name,
                                        style = MaterialTheme.typography.titleSmall,
                                        fontWeight = if (isSelected) FontWeight.Bold else FontWeight.SemiBold,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis
                                    )
                                    Text(
                                        text = buildString {
                                            append(node.type.displayName())
                                            if (isSelected) append(stringResource(R.string.node_current_suffix))
                                        },
                                        style = MaterialTheme.typography.labelSmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis
                                    )
                                }
                            }
                        }
                    }
                }

                TextButton(
                    onClick = onDismiss,
                    modifier = Modifier.align(Alignment.End)
                ) {
                    Text(stringResource(R.string.cancel))
                }
            }
        }
    }
}
