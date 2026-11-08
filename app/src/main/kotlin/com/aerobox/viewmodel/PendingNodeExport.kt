package com.aerobox.viewmodel

import androidx.lifecycle.SavedStateHandle
import java.io.File
import java.io.IOException
import java.util.UUID
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext

/** Only a request ID enters saved state; the potentially large selection stays in private storage. */
internal class PendingNodeExport(private val state: SavedStateHandle, private val directory: File) {
    val requestId: String? get() = state[STATE_KEY]

    suspend fun prepare(ids: List<Long>) {
        NodeIdFile.validate(ids, allowEmpty = false)
        val previousId = requestId
        val id = UUID.randomUUID().toString()
        try {
            withContext(Dispatchers.IO) {
                NodeIdFile.removeExpired(directory, previousId)
                NodeIdFile.write(File(directory, id), ids.toSet())
            }
        } catch (error: Exception) {
            withContext(NonCancellable + Dispatchers.IO) { File(directory, id).delete() }
            throw error
        }
        // SavedStateHandle belongs to the main thread. Publish only after the file is durable.
        state[STATE_KEY] = id
        withContext(NonCancellable + Dispatchers.IO) { fileFor(previousId)?.delete() }
    }

    suspend fun load(id: String?): List<Long>? = withContext(Dispatchers.IO) {
        val file = fileFor(id) ?: return@withContext null
        try {
            NodeIdFile.read(file, allowEmpty = false)
        } catch (_: IOException) {
            null
        } catch (_: IllegalArgumentException) {
            null
        }
    }

    suspend fun clear(id: String?) {
        if (requestId == id) state.remove<String>(STATE_KEY)
        withContext(Dispatchers.IO) { fileFor(id)?.delete() }
    }

    private fun fileFor(id: String?): File? =
        id?.takeIf(NodeIdFile::isValidToken)?.let { File(directory, it) }

    private companion object {
        const val STATE_KEY = "node_export_request"
    }
}
