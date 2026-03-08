package com.aerobox

import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.core.view.WindowCompat
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.FilterChip
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.lifecycleScope
import com.aerobox.core.connection.ConnectionDiagnostics
import com.aerobox.data.model.ProxyNode
import com.aerobox.data.repository.VpnConnectionResult
import com.aerobox.data.repository.VpnRepository
import com.aerobox.ui.theme.SingBoxVPNTheme
import com.aerobox.utils.PreferenceManager
import kotlinx.coroutines.launch

class NotificationSwitchActivity : ComponentActivity() {
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
                NotificationSwitchDialog(
                    onDismiss = { finish() },
                    onNodeSelected = { node ->
                        switchToNode(node)
                    }
                )
            }
        }
    }

    private fun switchToNode(node: ProxyNode) {
        lifecycleScope.launch {
            PreferenceManager.setLastSelectedNodeId(applicationContext, node.id)
            when (val result = VpnRepository(applicationContext).switchToNode(node)) {
                is VpnConnectionResult.Success -> Unit
                VpnConnectionResult.NoNodeAvailable,
                is VpnConnectionResult.InvalidConfig,
                is VpnConnectionResult.Failure -> {
                    Toast.makeText(
                        this@NotificationSwitchActivity,
                        ConnectionDiagnostics.userFacingFailureMessage(
                            result = result,
                            operationFailedText = getString(R.string.operation_failed)
                        ),
                        Toast.LENGTH_SHORT
                    ).show()
                }
            }
            finish()
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun NotificationSwitchDialog(
    onDismiss: () -> Unit,
    onNodeSelected: (ProxyNode) -> Unit
) {
    val allNodes by AeroBoxApplication.database.proxyNodeDao().getAllNodes()
        .collectAsStateWithLifecycle(initialValue = emptyList())
    val subscriptionNames by AeroBoxApplication.database.subscriptionDao().getAllSubscriptions()
        .collectAsStateWithLifecycle(initialValue = emptyList())
    val selectedNodeId by PreferenceManager.lastSelectedNodeIdFlow(AeroBoxApplication.appInstance)
        .collectAsStateWithLifecycle(initialValue = -1L)
    var pendingNodeId by remember { mutableStateOf<Long?>(null) }

    val groupedNodes = remember(allNodes, subscriptionNames) {
        val nameMap = subscriptionNames.associate { it.id to it.name }
        allNodes
            .groupBy { it.subscriptionId }
            .filterValues { it.isNotEmpty() }
            .toList()
            .sortedWith(
                compareBy<Pair<Long, List<ProxyNode>>> { (subId, _) ->
                    if (subId == 0L || !nameMap.containsKey(subId)) 1 else 0
                }.thenBy { (subId, _) -> nameMap[subId] ?: "未分组" }
            )
    }

    androidx.compose.ui.window.Dialog(onDismissRequest = onDismiss) {
        Surface(
            shape = RoundedCornerShape(28.dp),
            color = MaterialTheme.colorScheme.surfaceContainerHigh,
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp)
            ) {
                Text(
                text = "切换节点",
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.padding(top = 4.dp, bottom = 12.dp)
            )
            
            var selectedGroupIndex by remember { mutableStateOf(0) }
            
            LazyRow(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                contentPadding = PaddingValues(bottom = 8.dp)
            ) {
                items(groupedNodes.indices.toList()) { index ->
                    val (subId, _) = groupedNodes[index]
                    val groupName = subscriptionNames.firstOrNull { it.id == subId }?.name ?: "未分组"
                    FilterChip(
                        selected = selectedGroupIndex == index,
                        onClick = { selectedGroupIndex = index },
                        label = { Text(groupName) }
                    )
                }
            }

            LazyColumn(
                modifier = Modifier.heightIn(max = 380.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
                contentPadding = PaddingValues(vertical = 4.dp)
            ) {
                if (groupedNodes.isNotEmpty() && selectedGroupIndex < groupedNodes.size) {
                    val (_, nodes) = groupedNodes[selectedGroupIndex]
                    items(nodes, key = { it.id }) { node ->
                        val isSelected = node.id == selectedNodeId
                        Card(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable(enabled = pendingNodeId == null) {
                                    pendingNodeId = node.id
                                    onNodeSelected(node)
                                },
                            shape = RoundedCornerShape(16.dp)
                        ) {
                            Column(
                                modifier = Modifier.padding(horizontal = 16.dp, vertical = 14.dp)
                            ) {
                                Text(
                                    text = node.name,
                                    style = MaterialTheme.typography.titleMedium,
                                    fontWeight = if (isSelected) FontWeight.Bold else FontWeight.SemiBold,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                                Text(
                                    text = buildString {
                                        append(node.type.displayName())
                                        if (isSelected) append(" · 当前")
                                    },
                                    style = MaterialTheme.typography.bodySmall,
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
                Text("取消")
            }
        }
    }
}
}
