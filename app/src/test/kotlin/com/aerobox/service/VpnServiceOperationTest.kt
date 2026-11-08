package com.aerobox.service

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class VpnServiceOperationTest {
    @Test fun timeoutAndLateReplyDoNotCompleteANewerOperation() = runTest {
        val first = VpnStateManager.registerServiceOperation()
        val waiting = async { first.awaitResult(100) }
        runCurrent()
        advanceTimeBy(100)
        runCurrent()
        assertNull(waiting.await())
        VpnStateManager.forgetServiceOperation(first.id)
        val second = VpnStateManager.registerServiceOperation()
        try {
            VpnStateManager.reportServiceOperation(first.id, success = true)
            assertFalse(second.result.isCompleted)
            VpnStateManager.reportServiceOperation(second.id, success = false, error = "current failure")
            assertEquals("current failure", second.awaitResult(100)?.error)
        } finally {
            VpnStateManager.forgetServiceOperation(second.id)
        }
    }

    @Test fun replyBeforeDeadlineWinsAndDuplicateRepliesAreIgnored() = runTest {
        val operation = VpnStateManager.registerServiceOperation()
        try {
            val waiting = async { operation.awaitResult(100) }
            runCurrent()
            advanceTimeBy(99)
            VpnStateManager.reportServiceOperation(operation.id, success = true)
            VpnStateManager.reportServiceOperation(operation.id, success = false, error = "late duplicate")
            assertTrue(requireNotNull(waiting.await()).success)
        } finally {
            VpnStateManager.forgetServiceOperation(operation.id)
        }
    }
}
