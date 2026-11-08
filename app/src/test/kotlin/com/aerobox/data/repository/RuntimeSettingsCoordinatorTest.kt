package com.aerobox.data.repository

import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.ProxyType
import com.aerobox.data.model.VpnPhase
import com.aerobox.data.model.VpnState
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test

class RuntimeSettingsCoordinatorTest {
    private val node = ProxyNode(name = "test", type = ProxyType.SOCKS, server = "192.0.2.1", port = 1080)
    private var state = VpnState(phase = VpnPhase.CONNECTED, serviceActive = true, currentNode = node)
    private var revision = 0L
    private var setting = "old"
    private val writes = mutableListOf<String>()
    private val restoreErrors = mutableListOf<VpnConnectionResult>()
    private fun coordinator(reload: suspend (ProxyNode, Long) -> VpnConnectionResult) =
        RuntimeSettingsCoordinator(Mutex(), { state }, { revision }, reload, restoreErrors::add)
    private suspend fun change(coordinator: RuntimeSettingsCoordinator) = coordinator.update(
        readCurrent = { setting },
        persist = { setting = it; writes.add(it) }
    ) { "new" }

    @Test fun successfulReloadKeepsTheNewSetting() = runTest {
        val result = change(coordinator { _, _ -> VpnConnectionResult.Success(node) })
        assertTrue(result.reloaded)
        assertEquals(listOf("new"), writes)
    }

    @Test fun failedReloadRestoresPreferencesAndThePreviousConnection() = runTest {
        var calls = 0
        val result = change(coordinator { _, _ ->
            if (++calls == 1) {
                state = VpnState()
                VpnConnectionResult.Failure(IllegalStateException("reload failed"))
            } else {
                assertEquals("old", setting)
                VpnConnectionResult.Success(node)
            }
        })
        assertFalse(result.applied)
        assertEquals(listOf("new", "old"), writes)
        assertEquals(2, calls)
    }

    @Test fun userStopDuringReloadKeepsPreferenceWithoutReconnecting() = runTest {
        var calls = 0
        val result = change(coordinator { _, _ ->
            calls++
            revision++
            state = VpnState()
            VpnConnectionResult.Failure(CancellationException("stopped"))
        })
        assertTrue(result.applied)
        assertEquals("new", setting)
        assertEquals(1, calls)
    }

    @Test fun stopDuringRollbackPreventsRestoringTheConnection() = runTest {
        var reloads = 0
        val coordinator = coordinator { _, _ ->
            reloads++
            state = VpnState()
            VpnConnectionResult.InvalidConfig("invalid")
        }
        val result = coordinator.update(
            readCurrent = { setting },
            persist = { setting = it; if (it == "old") revision++ }
        ) { "new" }
        assertFalse(result.applied)
        assertEquals(1, reloads)
    }

    @Test fun cancelledCallerStillCompensatesPersistedSettings() = runTest {
        val entered = CompletableDeferred<Unit>()
        val coordinator = coordinator { _, _ -> entered.complete(Unit); awaitCancellation() }
        val job = async { change(coordinator) }
        entered.await()
        job.cancel()
        job.join()
        assertEquals(listOf("new", "old"), writes)
    }

    @Test fun restorationFailureIsReportedWithoutHidingOriginalFailure() = runTest {
        val result = change(coordinator { _, _ ->
            state = VpnState()
            VpnConnectionResult.InvalidConfig("invalid")
        })
        assertFalse(result.applied)
        assertEquals(1, restoreErrors.size)
        assertEquals("old", setting)
    }
}
