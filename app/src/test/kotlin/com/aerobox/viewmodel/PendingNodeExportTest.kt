package com.aerobox.viewmodel

import androidx.lifecycle.SavedStateHandle
import java.io.File
import java.util.Base64
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class PendingNodeExportTest {
    @get:Rule val temporaryFolder = TemporaryFolder()
    private val directory get() = File(temporaryFolder.root, "pending")

    @Test fun readsExistingVersionOneFilesAndRejectsEmptyExportRequests() = runTest {
        val token = "c38f502f-27be-4bba-8513-6af44d381e55"
        directory.mkdirs()
        val file = File(directory, token)
        // Existing format: version 1, count 2, IDs 7 and 42. Independent of the current writer.
        file.writeBytes(Base64.getDecoder().decode("AAAAAQAAAAIAAAAAAAAABwAAAAAAAAAq"))
        val request = PendingNodeExport(SavedStateHandle(mapOf("node_export_request" to token)), directory)
        assertEquals(listOf(7L, 42L), request.load(request.requestId))
        file.writeBytes(Base64.getDecoder().decode("AAAAAQAAAAA="))
        assertNull(request.load(request.requestId))
    }

    @Test fun recreationRestoresLargeSelectionWithOnlyARequestIdInSavedState() = runTest {
        val state = SavedStateHandle()
        val original = PendingNodeExport(state, directory)
        val ids = (1L..100_000L).toList()
        original.prepare(ids)
        val saved = state.keys().associateWith { state.get<Any>(it) }
        assertEquals(1, saved.size)
        assertTrue(saved.values.single() is String)
        assertEquals(36, (saved.values.single() as String).length)
        val recreated = PendingNodeExport(SavedStateHandle(saved), directory)
        assertEquals(ids, recreated.load(recreated.requestId))
    }

    @Test fun replacementAndCompletionRemoveRequestFilesAndState() = runTest {
        val state = SavedStateHandle()
        val request = PendingNodeExport(state, directory)
        request.prepare(listOf(1L, 2L))
        val previousId = request.requestId
        request.prepare(listOf(3L, 3L, 4L))
        assertNull(request.load(previousId))
        assertEquals(listOf(3L, 4L), request.load(request.requestId))
        // A stale result must not clear a more recent selection.
        request.clear(previousId)
        assertNotNull(request.requestId)
        request.clear(request.requestId)
        assertNull(request.requestId)
        assertTrue(state.keys().isEmpty())
        assertTrue(directory.listFiles().orEmpty().isEmpty())
    }

    @Test fun missingCorruptAndInvalidRequestsCannotExportAnotherSelection() = runTest {
        val request = PendingNodeExport(SavedStateHandle(), directory)
        assertNull(request.load(null))
        assertNull(request.load("../unrelated"))
        request.prepare(listOf(1L))
        File(directory, requireNotNull(request.requestId)).writeBytes(byteArrayOf(0))
        assertNull(request.load(request.requestId))
        File(directory, requireNotNull(request.requestId)).delete()
        assertNull(request.load(request.requestId))
    }
}
