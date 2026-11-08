package com.aerobox.data.repository

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test

class BackupExporterTest {
    @Test fun slowDocumentWriteDoesNotHoldTheVpnSettingsLock() = runTest {
        val mutex = Mutex()
        val writing = CompletableDeferred<Unit>()
        val finishWrite = CompletableDeferred<Unit>()
        val bytes = byteArrayOf(1, 2, 3)
        val export = launch {
            BackupExporter(mutex).export(
                capture = {
                    assertTrue(mutex.isLocked)
                    bytes
                },
                write = {
                    assertArrayEquals(bytes, it)
                    writing.complete(Unit)
                    finishWrite.await()
                }
            )
        }
        writing.await()
        val acquired = mutex.tryLock()
        if (acquired) mutex.unlock()
        finishWrite.complete(Unit)
        export.join()
        assertTrue("VPN operations must proceed while a document provider is stalled", acquired)
    }

    @Test fun oversizedBackupDoesNotOpenTheDestinationAndReleasesTheLock() = runTest {
        val mutex = Mutex()
        var opened = false
        try {
            BackupExporter(mutex).export(
                capture = { throw BackupLimitExceededException() },
                write = { opened = true }
            )
            fail("Expected the size limit to reject the export")
        } catch (_: BackupLimitExceededException) {
            assertFalse(opened)
            assertFalse(mutex.isLocked)
        }
    }
}
