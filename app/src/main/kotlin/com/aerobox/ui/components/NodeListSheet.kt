package com.aerobox.ui.components

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.aerobox.data.model.ProxyNode

private enum class SortMode { NAME, LATENCY }

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NodeListSheet(
    nodes: List<ProxyNode>,
    subscriptionNames: Map<Long, String> = emptyMap(),
    selectedNodeId: Long,
    onNodeSelected: (ProxyNode) -> Unit,
    onTestAll: () -> Unit,
    onTestNode: (ProxyNode) -> Unit,
    onDismiss: () -> Unit
) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    var searchQuery by remember { mutableStateOf("") }
    var sortMode by remember { mutableStateOf(SortMode.LATENCY) }

    val filteredNodes by remember(nodes, searchQuery, sortMode) {
        derivedStateOf {
            val filtered = if (searchQuery.isBlank()) nodes
            else nodes.filter {
                it.name.contains(searchQuery, ignoreCase = true) ||
                        it.server.contains(searchQuery, ignoreCase = true) ||
                        it.type.name.contains(searchQuery, ignoreCase = true)
            }
            when (sortMode) {
                SortMode.LATENCY -> filtered.sortedBy { if (it.latency < 0) Int.MAX_VALUE else it.latency }
                SortMode.NAME -> filtered.sortedBy { it.name.lowercase() }
            }
        }
    }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState
    ) {
        Column(modifier = Modifier.padding(horizontal = 16.dp)) {
            // Header
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "节点列表 (${filteredNodes.size}/${nodes.size})",
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold
                )
                TextButton(onClick = onTestAll) {
                    Icon(
                        Icons.Filled.Refresh,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(Modifier.width(4.dp))
                    Text("全部测速")
                }
            }

            // Search bar
            OutlinedTextField(
                value = searchQuery,
                onValueChange = { searchQuery = it },
                modifier = Modifier.fillMaxWidth(),
                placeholder = { Text("搜索节点名称、服务器、类型") },
                leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                trailingIcon = {
                    if (searchQuery.isNotEmpty()) {
                        IconButton(onClick = { searchQuery = "" }) {
                            Icon(Icons.Filled.Close, contentDescription = null)
                        }
                    }
                },
                singleLine = true,
                shape = RoundedCornerShape(12.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    unfocusedBorderColor = MaterialTheme.colorScheme.outlineVariant
                )
            )

            Spacer(Modifier.height(8.dp))

            // Sort chips
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(
                    selected = sortMode == SortMode.LATENCY,
                    onClick = { sortMode = SortMode.LATENCY },
                    label = { Text("按延迟") }
                )
                FilterChip(
                    selected = sortMode == SortMode.NAME,
                    onClick = { sortMode = SortMode.NAME },
                    label = { Text("按名称") }
                )
            }

            Spacer(Modifier.height(8.dp))

            if (filteredNodes.isEmpty()) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(200.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = if (nodes.isEmpty()) "暂无节点，请先添加订阅" else "未找到匹配的节点",
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            } else {
                val grouped = filteredNodes.groupBy { it.subscriptionId }
                LazyColumn(
                    modifier = Modifier.height(400.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    grouped.forEach { (subId, groupNodes) ->
                        if (grouped.size > 1) {
                            stickyHeader(key = "header_$subId") {
                                Surface(
                                    modifier = Modifier.fillMaxWidth(),
                                    color = MaterialTheme.colorScheme.surfaceContainerLow
                                ) {
                                    Text(
                                        text = subscriptionNames[subId] ?: "未分组",
                                        style = MaterialTheme.typography.labelLarge,
                                        fontWeight = FontWeight.SemiBold,
                                        color = MaterialTheme.colorScheme.primary,
                                        modifier = Modifier.padding(vertical = 6.dp, horizontal = 4.dp)
                                    )
                                }
                            }
                        }
                        items(groupNodes, key = { it.id }) { node ->
                            NodeItem(
                                node = node,
                                isSelected = node.id == selectedNodeId,
                                onClick = { onNodeSelected(node) },
                                onTestLatency = { onTestNode(node) }
                            )
                        }
                    }
                }
            }

            Spacer(Modifier.height(16.dp))
        }
    }
}

@Composable
private fun NodeItem(
    node: ProxyNode,
    isSelected: Boolean,
    onClick: () -> Unit,
    onTestLatency: () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
        colors = CardDefaults.cardColors(
            containerColor = if (isSelected) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surface
        ),
        border = androidx.compose.foundation.BorderStroke(
            1.dp,
            if (isSelected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f)
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Selection indicator
            if (isSelected) {
                Surface(
                    modifier = Modifier
                        .size(24.dp)
                        .clip(CircleShape),
                    color = MaterialTheme.colorScheme.primary
                ) {
                    Icon(
                        Icons.Filled.Check,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onPrimary,
                        modifier = Modifier.padding(4.dp)
                    )
                }
            } else {
                Surface(
                    modifier = Modifier
                        .size(24.dp)
                        .clip(CircleShape),
                    color = MaterialTheme.colorScheme.outline.copy(alpha = 0.3f)
                ) {}
            }

            Spacer(Modifier.width(12.dp))

            // Node info
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = node.name,
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.Medium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    text = "${node.type.name} · ${node.server}:${node.port}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }

            // Clickable latency badge — tap to test this node
            LatencyBadge(
                latency = node.latency,
                onClick = onTestLatency
            )
        }
    }
}

@Composable
private fun LatencyBadge(latency: Int, onClick: () -> Unit) {
    val (color, text) = when {
        latency < 0 -> MaterialTheme.colorScheme.outline to "测速"
        latency < 100 -> MaterialTheme.colorScheme.primary to "${latency}ms"
        latency < 300 -> MaterialTheme.colorScheme.tertiary to "${latency}ms"
        else -> MaterialTheme.colorScheme.error to "${latency}ms"
    }
    Surface(
        modifier = Modifier.clickable(onClick = onClick),
        color = color.copy(alpha = 0.15f),
        shape = MaterialTheme.shapes.small
    ) {
        Text(
            text = text,
            color = color,
            style = MaterialTheme.typography.labelSmall,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
        )
    }
}
