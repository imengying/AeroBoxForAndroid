package com.aerobox.data.repository

import com.aerobox.data.model.NodeLatencyState
import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.ProxyNodeMatcher
import com.aerobox.data.model.connectionFingerprint

internal data class SubscriptionUpdatePlan(
    val nodes: List<ProxyNode>,
    val added: List<ProxyNode>,
    val changed: List<ProxyNode>,
    val removed: List<ProxyNode>,
    val summary: SubscriptionUpdateSummary
)

/** Pure calculation against the current transaction snapshot; performs no I/O. */
internal object SubscriptionUpdatePlanner {
    fun plan(existing: List<ProxyNode>, fresh: List<ProxyNode>, subscriptionId: Long, now: Long): SubscriptionUpdatePlan {
        val nodes = stabilize(existing, fresh, subscriptionId, now)
        val byId = existing.associateBy { it.id }
        val retained = nodes.mapTo(mutableSetOf()) { it.id }
        return SubscriptionUpdatePlan(
            nodes = nodes,
            added = nodes.filter { it.id == 0L },
            changed = nodes.filter { it.id > 0L && it != byId[it.id] },
            removed = existing.filter { it.id !in retained },
            summary = calculateUpdateSummary(existing, nodes)
        )
    }

    private fun stabilize(
        existingNodes: List<ProxyNode>,
        freshNodes: List<ProxyNode>,
        subscriptionId: Long,
        now: Long
    ): List<ProxyNode> {
        val matcher = ProxyNodeMatcher(existingNodes)
        var previousOrder = (existingNodes.firstOrNull()?.createdAt ?: now) - 1L
        return freshNodes.mapIndexed { index, freshNode ->
            val matchedNode = matcher.takeBestMatch(freshNode)
            val order = maxOf(
                existingNodes.getOrNull(index)?.createdAt ?: previousOrder + 1L,
                previousOrder + 1L
            )
            previousOrder = order
            val latency = if (matchedNode != null &&
                matchedNode.connectionFingerprint(includeName = false) == freshNode.connectionFingerprint(includeName = false)
            ) {
                matchedNode.latency
            } else {
                NodeLatencyState.UNTESTED
            }
            freshNode.copy(
                id = matchedNode?.id ?: 0L,
                subscriptionId = subscriptionId,
                latency = latency,
                createdAt = order
            )
        }
    }

    private fun calculateUpdateSummary(
        existingNodes: List<ProxyNode>,
        refreshedNodes: List<ProxyNode>
    ): SubscriptionUpdateSummary {
        val existingById = existingNodes.associateBy { it.id }
        val matchedIds = mutableSetOf<Long>()
        var addedCount = 0
        var updatedCount = 0

        refreshedNodes.forEach { node ->
            val existingNode = node.id.takeIf { it > 0L }?.let { existingById[it] }
            if (existingNode == null) {
                addedCount++
            } else {
                matchedIds += existingNode.id
                if (existingNode.connectionFingerprint() != node.connectionFingerprint()) {
                    updatedCount++
                }
            }
        }

        val deletedCount = existingNodes.count { it.id !in matchedIds }
        return SubscriptionUpdateSummary(
            addedCount = addedCount,
            updatedCount = updatedCount,
            deletedCount = deletedCount
        )
    }

}
