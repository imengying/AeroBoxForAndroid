package com.aerobox.viewmodel

import androidx.lifecycle.SavedStateHandle
import java.io.File
import java.util.Base64
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.job
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class NodeSelectionStoreTest {
    @get:Rule val temporary = TemporaryFolder()

    private fun CoroutineScope.childScope() = CoroutineScope(coroutineContext + Job(coroutineContext[Job]))

    @Test fun readsExistingVersionOneFilesIncludingAnEmptySelection() = runTest {
        val token = "c38f502f-27be-4bba-8513-6af44d381e55"
        val file = File(temporary.root, token)
        for ((fixture, expected) in listOf(
            "AAAAAQAAAAIAAAAAAAAABwAAAAAAAAAq" to setOf(7L, 42L),
            "AAAAAQAAAAA=" to emptySet()
        )) {
            file.writeBytes(Base64.getDecoder().decode(fixture))
            val owner = backgroundScope.childScope()
            val store = NodeSelectionStore(SavedStateHandle(mapOf("node_selection_file" to token)),
                temporary.root, owner) { throw it }
            store.ready.first { it }
            assertEquals(expected, store.ids.value)
            owner.coroutineContext.job.cancelAndJoin()
        }
    }

    @Test fun largeSelectionSurvivesRecreationWithoutEnteringTheBundle() = runTest {
        val state = SavedStateHandle()
        val owner = backgroundScope.childScope()
        val store = NodeSelectionStore(state, temporary.root, owner) { throw it }
        store.ready.first { it }
        val selected = (1L..100_000L).toSet()
        store.replace(selected)
        store.flush()
        val saved = state.keys().associateWith { state.get<Any>(it) }
        assertEquals(1, saved.size)
        assertEquals(36, (saved.values.single() as String).length)
        owner.coroutineContext.job.cancelAndJoin()
        val restarted = NodeSelectionStore(SavedStateHandle(saved), temporary.root, backgroundScope) { throw it }
        restarted.ready.first { it }
        assertEquals(selected, restarted.ids.value)
    }

    @Test fun savedTokenStillReadsChangesWrittenAfterStateWasCaptured() = runTest {
        val state = SavedStateHandle()
        val owner = backgroundScope.childScope()
        val store = NodeSelectionStore(state, temporary.root, owner) { throw it }
        store.ready.first { it }
        val saved = state.keys().associateWith { state.get<Any>(it) }
        repeat(100) { store.replace(listOf(it.toLong() + 1)) }
        store.flush()
        owner.coroutineContext.job.cancelAndJoin()
        val newOwner = backgroundScope.childScope()
        val restarted = NodeSelectionStore(SavedStateHandle(saved), temporary.root, newOwner) { throw it }
        restarted.ready.first { it }
        assertEquals(setOf(100L), restarted.ids.value)
        restarted.replace(emptySet())
        restarted.flush()
        newOwner.coroutineContext.job.cancelAndJoin()
        val cleared = NodeSelectionStore(SavedStateHandle(saved), temporary.root, backgroundScope) { throw it }
        cleared.ready.first { it }
        assertTrue(cleared.ids.value.isEmpty())
    }

    @Test fun corruptSelectionIsReportedAndCanBeReplaced() = runTest {
        val state = SavedStateHandle()
        val owner = backgroundScope.childScope()
        val store = NodeSelectionStore(state, temporary.root, owner) { throw it }
        store.ready.first { it }
        store.replace(listOf(1L))
        store.flush()
        owner.coroutineContext.job.cancelAndJoin()
        val file = File(temporary.root, state.get<String>(state.keys().single())!!)
        file.writeBytes(byteArrayOf(1))
        var failures = 0
        val restarted = NodeSelectionStore(state, temporary.root, backgroundScope) { failures++ }
        restarted.ready.first { it }
        assertEquals(1, failures)
        assertTrue(restarted.ids.value.isEmpty())
        restarted.replace(listOf(2L))
        restarted.flush()
        assertTrue(file.length() > 1)
    }
}
