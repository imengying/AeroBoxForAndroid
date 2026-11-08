package com.aerobox.core.logging

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

@OptIn(ExperimentalCoroutinesApi::class)
class RuntimeLogStoreTest {
    @get:Rule val temporaryFolder = TemporaryFolder()
    private fun file() = File(temporaryFolder.root, "errors.json")
    private val previous = RuntimeLogEntry(1, "Previous failure")
    private val current = RuntimeLogEntry(2, "Current failure")

    @Test fun restoresErrorsWithoutLosingEarlyStartupErrors() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val original = RuntimeLogStore(dispatcher)
        original.persistTo(file(), backgroundScope) { throw it }
        original.append(previous)
        runCurrent()

        val restarted = RuntimeLogStore(dispatcher)
        restarted.append(current)
        restarted.persistTo(file(), backgroundScope) { throw it }
        runCurrent()
        assertEquals(listOf(previous, current), restarted.lines.value)
        assertTrue(file().readText().contains("Current failure"))
    }

    @Test fun clearRemovesDiskHistoryAndQueuedWritesCannotRestoreIt() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val original = RuntimeLogStore(dispatcher)
        original.persistTo(file(), backgroundScope) { throw it }
        original.append(previous)
        runCurrent()
        original.append(current)
        original.clear()
        runCurrent()

        val restarted = RuntimeLogStore(dispatcher)
        restarted.persistTo(file(), backgroundScope) { throw it }
        runCurrent()
        assertTrue(restarted.lines.value.isEmpty())
        assertEquals("[]", file().readText())
    }

    @Test fun clearBeforeInitializationDoesNotRestoreOldHistory() = runTest {
        file().writeText("""[{"timestamp":1,"message":"Previous failure"}]""")
        val store = RuntimeLogStore(StandardTestDispatcher(testScheduler))
        store.clear()
        store.persistTo(file(), backgroundScope) { throw it }
        runCurrent()
        assertTrue(store.lines.value.isEmpty())
        assertEquals("[]", file().readText())
    }

    @Test fun corruptHistoryDoesNotHideNewErrors() = runTest {
        file().writeText("invalid JSON")
        var failures = 0
        val store = RuntimeLogStore(StandardTestDispatcher(testScheduler))
        store.persistTo(file(), backgroundScope) { failures++ }
        store.append(current)
        runCurrent()
        assertEquals(1, failures)
        assertEquals(listOf(current), store.lines.value)
        assertTrue(file().readText().contains("Current failure"))
    }

    @Test fun historyIsBoundedEvenForVeryLargeErrors() = runTest {
        val store = RuntimeLogStore(StandardTestDispatcher(testScheduler))
        store.persistTo(file(), backgroundScope) { throw it }
        repeat(600) { store.append(RuntimeLogEntry(it + 1L, "error $it")) }
        assertEquals(500, store.lines.value.size)
        repeat(20) { store.append(RuntimeLogEntry(it + 1000L, "\u0000".repeat(10_000))) }
        runCurrent()
        assertTrue(store.lines.value.sumOf { it.message.length } <= 32 * 1024)
        assertTrue(store.lines.value.all { it.message.length <= 4096 })
        assertTrue(file().length() <= 256 * 1024)
    }
}
