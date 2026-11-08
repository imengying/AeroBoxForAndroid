package com.aerobox.data.repository

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.stringPreferencesKey
import com.aerobox.data.database.PendingRestore
import com.aerobox.data.database.PendingRestoreDao
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.emitAll
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

internal class RestoreCompletionException(cause: Exception) : Exception("Restore settings pending", cause)

/** Serializes normal writes with recovery; settings become visible only after durable application. */
class RecoveringSettingsStore(
    private val delegate: DataStore<Preferences>,
    private val pending: () -> PendingRestoreDao,
    private val applyBackup: (Preferences, PendingRestore) -> Preferences
) : DataStore<Preferences> {
    private val mutex = Mutex()

    override val data: Flow<Preferences> = flow {
        recover()
        emitAll(delegate.data)
    }

    override suspend fun updateData(transform: suspend (Preferences) -> Preferences): Preferences = mutex.withLock {
        recoverLocked()
        delegate.updateData(transform)
    }

    suspend fun recover() = mutex.withLock { recoverLocked() }

    /** The callback must atomically commit the imported rows and the pending record. */
    suspend fun commitRestore(commit: suspend () -> Unit) = mutex.withLock {
        recoverLocked()
        withContext(NonCancellable) {
            commit()
            try {
                recoverLocked()
            } catch (error: Exception) {
                // Rows are committed. Keep the record so subsequent access/restart completes it.
                throw RestoreCompletionException(error)
            }
        }
    }

    private suspend fun recoverLocked() {
        val dao = pending()
        val record = dao.read() ?: return
        delegate.updateData { current ->
            if (current[APPLIED_RESTORE] == record.token) current else
                applyBackup(current, record).toMutablePreferences().apply { this[APPLIED_RESTORE] = record.token }
        }
        // A crash after settings commit is harmless: the durable token prevents applying twice.
        dao.clear(record.token)
    }

    private companion object {
        val APPLIED_RESTORE = stringPreferencesKey("applied_restore_token")
    }
}
