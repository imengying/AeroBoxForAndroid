package com.aerobox.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.aerobox.R
import com.aerobox.data.model.NodeLatencyState
import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.Subscription

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NodeListSheet(
    nodes: List<ProxyNode>,
    subscriptions: List<Subscription> = emptyList(),
    selectedNodeId: Long,
    nodeSortOrder: Map<Long, List<Long>> = emptyMap(),
    onNodeSelected: (ProxyNode) -> Unit,
    onTestSubscription: (List<ProxyNode>) -> Unit,
    onTestNode: (ProxyNode) -> Unit,
    onDismiss: () -> Unit
) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    val ungroupedLabel = stringResource(R.string.group_ungrouped)

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState
    ) {
        BoxWithConstraints {
            val listMaxHeight = maxHeight * 0.65f
            Column(modifier = Modifier.padding(horizontal = 16.dp)) {
            if (nodes.isEmpty()) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = stringResource(R.string.node_list_title),
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.Bold
                    )
                }
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(200.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = stringResource(R.string.node_list_empty_hint),
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            } else {
                val grouped = remember(nodes, subscriptions, ungroupedLabel) {
                    val subscriptionOrder = subscriptions.withIndex().associate { it.value.id to it.index }
                    val subscriptionNames = subscriptions.associate { it.id to it.name }
                    nodes
                        .groupBy { it.subscriptionId }
                        .filterValues { groupNodes -> groupNodes.isNotEmpty() }
                        .toList()
                        .sortedWith(
                            compareBy<Pair<Long, List<ProxyNode>>> { (subId, _) ->
                                subscriptionOrder[subId] ?: Int.MAX_VALUE
                            }.thenBy { (subId, _) ->
                                if (subId == 0L || !subscriptionNames.containsKey(subId)) 1 else 0
                            }.thenBy { (subId, _) ->
                                subscriptionNames[subId] ?: ungroupedLabel
                            }
                        )
                }
                val subscriptionNames = remember(subscriptions) {
                    subscriptions.associate { it.id to it.name }
                }
                val groupIds = remember(grouped) { grouped.map { it.first } }
                var selectedSubscriptionId by remember { mutableStateOf<Long?>(null) }
                LaunchedEffect(selectedNodeId, groupIds) {
                    val selectedGroupId = grouped.firstOrNull { (_, groupNodes) ->
                        groupNodes.any { it.id == selectedNodeId }
                    }?.first
                    val hasCurrent = groupIds.contains(selectedSubscriptionId)
                    selectedSubscriptionId = when {
                        selectedGroupId != null -> selectedGroupId
                        hasCurrent -> selectedSubscriptionId
                        else -> grouped.firstOrNull()?.first
                    }
                }
                val currentGroupNodes = remember(grouped, selectedSubscriptionId, nodeSortOrder) {
                    val groupNodes = grouped.firstOrNull { (subId, _) ->
                        subId == selectedSubscriptionId
                    }?.second.orEmpty()
                    val sortedIds = selectedSubscriptionId?.let { nodeSortOrder[it] }
                    if (sortedIds != null) {
                        val idToNode = groupNodes.associateBy { it.id }
                        val sorted = sortedIds.mapNotNull { idToNode[it] }
                        // Append any nodes not in the snapshot (e.g. newly added)
                        val sortedIdSet = sortedIds.toSet()
                        val remaining = groupNodes.filter { it.id !in sortedIdSet }
                        sorted + remaining
                    } else {
                        groupNodes
                    }
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = stringResource(R.string.node_list_title),
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.Bold
                    )
                    TextButton(onClick = { onTestSubscription(currentGroupNodes) }) {
                        Icon(
                            Icons.Filled.Refresh,
                            contentDescription = null,
                            modifier = Modifier.size(18.dp)
                        )
                        Spacer(Modifier.width(4.dp))
                        Text(stringResource(R.string.node_list_speed_test))
                    }
                }

                LazyRow(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    items(grouped, key = { it.first }) { (subId, groupNodes) ->
                        FilterChip(
                            selected = subId == selectedSubscriptionId,
                            onClick = { selectedSubscriptionId = subId },
                            label = {
                                Text(
                                    text = subscriptionNames[subId] ?: ungroupedLabel,
                                    style = MaterialTheme.typography.labelMedium,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                            },
                            shape = RoundedCornerShape(8.dp),
                            border = null
                        )
                    }
                }

                Spacer(Modifier.height(8.dp))

                LazyColumn(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 240.dp, max = listMaxHeight),
                    verticalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    items(currentGroupNodes, key = { it.id }) { node ->
                        NodeItem(
                            node = node,
                            isSelected = node.id == selectedNodeId,
                            onClick = { onNodeSelected(node) },
                            onTestLatency = { onTestNode(node) }
                        )
                    }
                }
            }

            Spacer(Modifier.height(16.dp))
            }
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
        onClick = onClick,
        modifier = Modifier
            .fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (isSelected) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceContainerLow
        ),
        border = androidx.compose.foundation.BorderStroke(
            1.dp,
            if (isSelected) MaterialTheme.colorScheme.primary else androidx.compose.ui.graphics.Color.Transparent
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
                    text = node.type.displayName(),
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
        latency == NodeLatencyState.TESTING -> MaterialTheme.colorScheme.primary to stringResource(R.string.latency_testing)
        latency == NodeLatencyState.FAILED -> MaterialTheme.colorScheme.error to stringResource(R.string.latency_failed)
        latency == NodeLatencyState.UNTESTED -> MaterialTheme.colorScheme.outline to stringResource(R.string.node_list_speed_test)
        latency < 100 -> MaterialTheme.colorScheme.primary to "${latency}ms"
        latency < 300 -> MaterialTheme.colorScheme.tertiary to "${latency}ms"
        else -> MaterialTheme.colorScheme.error to "${latency}ms"
    }
    Surface(
        onClick = onClick,
        modifier = Modifier,
        color = color.copy(alpha = 0.15f),
        shape = MaterialTheme.shapes.small
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            if (latency == NodeLatencyState.TESTING) {
                CircularProgressIndicator(
                    modifier = Modifier.size(12.dp),
                    color = color,
                    strokeWidth = 2.dp
                )
                Spacer(modifier = Modifier.width(4.dp))
            }
            Text(
                text = text,
                color = color,
                style = MaterialTheme.typography.labelSmall,
                fontWeight = FontWeight.Bold
            )
        }
    }
}
