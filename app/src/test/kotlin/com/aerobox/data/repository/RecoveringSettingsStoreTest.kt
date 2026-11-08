package com.aerobox.data.repository

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.stringPreferencesKey
import com.aerobox.data.database.PendingRestore
import com.aerobox.data.database.PendingRestoreDao
import java.io.IOException
import java.io.File
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test
import org.junit.Rule
import org.junit.rules.TemporaryFolder

class RecoveringSettingsStoreTest {
    @get:Rule val temporary = TemporaryFolder()
    private val valueKey = stringPreferencesKey("value")
    private val record = PendingRestore(token = "restore-1", settings = "restored", selectedNodeId = 42)
    private val journal = Journal()
    private val disk = SettingsDisk()
    private var applications = 0
    private fun store() = RecoveringSettingsStore(disk, { journal }) { current, pending ->
        applications++
        current.toMutablePreferences().apply { this[valueKey] = pending.settings }
    }

    @Test fun restartAfterDatabaseCommitCompletesSettingsBeforeFirstRead() = runTest {
        journal.insert(record) // The previous process committed rows and journal, then died.
        assertEquals("restored", store().data.first()[valueKey])
        assertNull(journal.read())
        assertEquals(1, applications)
    }

    @Test fun failedDatabaseTransactionDoesNotApplySettings() = runTest {
        try {
            store().commitRestore { throw IOException("database transaction failed") }
            fail("Expected database failure")
        } catch (_: IOException) {
            assertNull(disk.data.value[valueKey])
            assertNull(journal.read())
        }
    }

    @Test fun settingsFailureRetainsJournalForTheNextProcess() = runTest {
        disk.failWrites = true
        try {
            store().commitRestore { journal.insert(record) }
            fail("Expected incomplete recovery")
        } catch (_: RestoreCompletionException) {
            assertEquals(record, journal.read())
        }
        disk.failWrites = false
        assertEquals("restored", store().data.first()[valueKey])
        assertNull(journal.read())
    }

    @Test fun restartAfterSettingsCommitDoesNotApplyTheSameRestoreTwice() = runTest {
        journal.failClear = true
        try {
            store().commitRestore { journal.insert(record) }
            fail("Expected journal cleanup failure")
        } catch (_: RestoreCompletionException) {
            assertEquals("restored", disk.data.value[valueKey])
        }
        journal.failClear = false
        val restarted = store()
        restarted.updateData { it.toMutablePreferences().apply { this[valueKey] = "new user choice" } }
        assertEquals("new user choice", restarted.data.first()[valueKey])
        assertEquals(1, applications)
        assertNull(journal.read())
    }

    @Test fun normalWriteWaitsForRestoreAndKeepsItsNewValue() = runTest {
        val entered = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        val store = store()
        val restoring = async {
            store.commitRestore { entered.complete(Unit); release.await(); journal.insert(record) }
        }
        entered.await()
        val writing = async { store.updateData { it.toMutablePreferences().apply { this[valueKey] = "new" } } }
        release.complete(Unit)
        restoring.await()
        writing.await()
        assertEquals("new", store.data.first()[valueKey])
    }

    @Test fun screenCancellationFinishesRecoveryAfterCommit() = runTest {
        val entered = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        val store = store()
        val restoring = async {
            store.commitRestore { journal.insert(record); entered.complete(Unit); release.await() }
        }
        entered.await()
        restoring.cancel()
        release.complete(Unit)
        restoring.join()
        assertEquals("restored", store.data.first()[valueKey])
        assertNull(journal.read())
    }

    @Test fun appliedTokenSurvivesClosingAndReopeningARealPreferencesFile() = runTest {
        val file = File(temporary.root, "settings.preferences_pb")
        val firstScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        val secondScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        fun persistentStore(scope: CoroutineScope) = RecoveringSettingsStore(
            PreferenceDataStoreFactory.create(scope = scope, produceFile = { file }), { journal }
        ) { prefs, pending ->
            applications++
            prefs.toMutablePreferences().apply { this[valueKey] = pending.settings }
        }
        try {
            journal.failClear = true
            try {
                persistentStore(firstScope).commitRestore { journal.insert(record) }
                fail("Expected journal cleanup failure")
            } catch (_: RestoreCompletionException) {
                assertTrue(file.length() > 0)
            }
            firstScope.coroutineContext.job.cancelAndJoin()
            journal.failClear = false
            val reopened = persistentStore(secondScope)
            assertEquals("restored", reopened.data.first()[valueKey])
            assertEquals(1, applications)
            assertNull(journal.read())
        } finally {
            firstScope.coroutineContext.job.cancelAndJoin()
            secondScope.coroutineContext.job.cancelAndJoin()
        }
    }

    private class Journal : PendingRestoreDao {
        var record: PendingRestore? = null
        var failClear = false
        override suspend fun read() = record
        override suspend fun insert(pending: PendingRestore) { check(record == null); record = pending }
        override suspend fun clear(token: String) {
            if (failClear) throw IOException("disk unavailable")
            if (record?.token == token) record = null
        }
    }

    private class SettingsDisk : DataStore<Preferences> {
        override val data = MutableStateFlow(emptyPreferences())
        private val mutex = Mutex()
        var failWrites = false
        override suspend fun updateData(transform: suspend (Preferences) -> Preferences): Preferences = mutex.withLock {
            if (failWrites) throw IOException("disk unavailable")
            transform(data.value).also { data.value = it }
        }
    }
}
