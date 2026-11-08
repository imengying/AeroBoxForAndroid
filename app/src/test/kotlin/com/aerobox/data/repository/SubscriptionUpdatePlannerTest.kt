package com.aerobox.data.repository

import com.aerobox.data.model.NodeLatencyState
import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.ProxyType
import org.junit.Assert.*
import org.junit.Test

class SubscriptionUpdatePlannerTest {
    private val first = ProxyNode(id = 1L, name = "A", type = ProxyType.SHADOWSOCKS,
        server = "192.0.2.1", port = 443, password = "old", method = "aes-128-gcm",
        subscriptionId = 8L, latency = 30, createdAt = 100L)

    @Test fun renamePreservesIdentityAndLatencyButCountsAsAnUpdate() {
        val plan = SubscriptionUpdatePlanner.plan(listOf(first), listOf(first.copy(id = 0, name = "renamed")), 8L, 999L)
        assertEquals(1L, plan.nodes.single().id)
        assertEquals(30, plan.nodes.single().latency)
        assertEquals(SubscriptionUpdateSummary(updatedCount = 1), plan.summary)
        assertTrue(plan.added.isEmpty())
    }

    @Test fun changedCredentialsInvalidateLatencyAndKeepStableId() {
        val plan = SubscriptionUpdatePlanner.plan(listOf(first), listOf(first.copy(id = 0, password = "new")), 8L, 999L)
        assertEquals(1L, plan.nodes.single().id)
        assertEquals(NodeLatencyState.UNTESTED, plan.nodes.single().latency)
        assertEquals(1, plan.changed.size)
    }

    @Test fun reorderAndDuplicateEndpointsDoNotReuseAnId() {
        val second = first.copy(id = 2, name = "B", createdAt = 101)
        val plan = SubscriptionUpdatePlanner.plan(listOf(first, second),
            listOf(second.copy(id = 0), first.copy(id = 0)), 8L, 999L)
        assertEquals(listOf(2L, 1L), plan.nodes.map { it.id })
        assertEquals(listOf(100L, 101L), plan.nodes.map { it.createdAt })
        assertEquals(0, plan.summary.changedCount)
        assertEquals(2, plan.changed.size) // Persist order changes, without presenting them as connection changes.
    }

    @Test fun additionsAndDeletionsAreComputedAgainstTheCommitSnapshot() {
        val fresh = first.copy(id = 0, name = "different", server = "192.0.2.2")
        val plan = SubscriptionUpdatePlanner.plan(listOf(first), listOf(fresh), 8L, 999L)
        assertEquals(listOf(first), plan.removed)
        assertEquals(0L, plan.added.single().id)
        assertEquals(8L, plan.added.single().subscriptionId)
        assertEquals(SubscriptionUpdateSummary(addedCount = 1, deletedCount = 1), plan.summary)
    }
}
