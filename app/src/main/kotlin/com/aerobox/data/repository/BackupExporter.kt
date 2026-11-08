package com.aerobox.data.repository

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/** Capture a consistent snapshot before handing it to a potentially slow document provider. */
internal class BackupExporter(private val settingsMutex: Mutex) {
    suspend fun export(capture: suspend () -> ByteArray, write: suspend (ByteArray) -> Unit) {
        val snapshot = settingsMutex.withLock { capture() }
        write(snapshot)
    }
}
