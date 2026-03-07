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
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
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

@Composable
private fun NotificationSwitchDialog(
    onDismiss: () -> Unit,
    onNodeSelected: (ProxyNode) -> Unit
) {
    val allNodes by AeroBoxApplication.database.proxyNodeDao().getAllNodes()
        .collectAsStateWithLifecycle(initialValue = emptyList())
    val selectedNodeId by PreferenceManager.lastSelectedNodeIdFlow(AeroBoxApplication.appInstance)
        .collectAsStateWithLifecycle(initialValue = -1L)
    var pendingNodeId by remember { mutableStateOf<Long?>(null) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                text = "切换节点",
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold
            )
        },
        text = {
            LazyColumn(
                modifier = Modifier.heightIn(max = 420.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
                contentPadding = PaddingValues(vertical = 4.dp)
            ) {
                items(allNodes, key = { it.id }) { node ->
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
        },
        confirmButton = {
            TextButton(onClick = onDismiss) {
                Text("取消")
            }
        }
    )
}
