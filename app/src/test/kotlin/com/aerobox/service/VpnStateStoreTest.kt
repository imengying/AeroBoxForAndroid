package com.aerobox.service

import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.ProxyType
import com.aerobox.data.model.VpnPhase
import org.junit.Assert.*
import org.junit.Test

class VpnStateStoreTest {
    private val node = ProxyNode(name = "test", type = ProxyType.SOCKS, server = "192.0.2.1", port = 1080)

    @Test fun preparationIsImmediatelyActiveAndRejectsRepeatedStarts() {
        val store = VpnStateStore()
        val preparation = requireNotNull(store.tryBeginStart())
        assertEquals(VpnPhase.STARTING, store.state.value.phase)
        assertTrue(store.state.value.serviceActive)
        assertNull(store.tryBeginStart())
        store.stopped(preparation)
        assertFalse(store.state.value.serviceActive)
        assertNotNull(store.tryBeginStart())
    }

    @Test fun cancelledPreparationCannotClearAStopOrANewerConnection() {
        val store = VpnStateStore()
        val preparation = requireNotNull(store.tryBeginStart())
        val stop = store.beginStop()
        store.stopped(preparation)
        assertEquals(VpnPhase.STOPPING, store.state.value.phase)
        assertNull(store.tryBeginStart())
        store.stopped(stop)
        val next = requireNotNull(store.tryBeginStart())
        val service = store.beginStart()
        assertTrue(store.connected(service, node))
        store.stopped(preparation)
        store.stopped(next)
        assertTrue(store.state.value.isConnected)
    }

    @Test fun stopDuringStartupRejectsLateNativeSuccess() {
        val store = VpnStateStore()
        val starting = store.beginStart()
        val stopping = store.beginStop()
        assertFalse(store.connected(starting, node))
        assertEquals(VpnPhase.STOPPING, store.state.value.phase)
        store.stopped(stopping)
        assertEquals(VpnPhase.IDLE, store.state.value.phase)
        assertFalse(store.state.value.serviceActive)
    }

    @Test fun newerNodeSwitchWinsOverEarlierResultAndCleanup() {
        val store = VpnStateStore { 123L }
        val old = store.beginStart()
        val current = store.beginStart()
        assertFalse(store.connected(old, node))
        assertTrue(store.connected(current, node.copy(name = "new")))
        store.stopped(old)
        assertEquals("new", store.state.value.currentNode?.name)
        assertEquals(123L, store.state.value.connectionTime)
        assertTrue(store.state.value.serviceActive)
    }

    @Test fun timeoutOrRevocationCannotBeUndoneByLateSuccess() {
        val store = VpnStateStore()
        val request = store.beginStart()
        store.updateError("permission revoked")
        val stopped = store.beginStop()
        store.stopped(stopped)
        assertFalse(store.connected(request, node))
        assertEquals(VpnPhase.FAILED, store.state.value.phase)
        assertEquals("permission revoked", store.state.value.lastError)
        assertFalse(store.state.value.serviceActive)
    }

    @Test fun reconnectWaitStaysActiveAndStopInvalidatesItsResult() {
        val store = VpnStateStore()
        val request = store.beginStart()
        store.connected(request, node)
        store.disconnected(request, "network lost", retrying = true)
        assertTrue(store.state.value.serviceActive)
        assertFalse(store.state.value.isConnected)
        val stop = store.beginStop()
        store.disconnected(request, "late failure", retrying = true)
        assertEquals(VpnPhase.STOPPING, store.state.value.phase)
        store.stopped(stop)
        assertNull(store.state.value.lastError)
    }
}
