package com.aerobox.viewmodel

import androidx.lifecycle.SavedStateHandle
import java.io.File
import java.util.UUID
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/** Stable file token survives saved-state capture while selection contents keep changing. */
internal class NodeSelectionStore(
    savedState: SavedStateHandle,
    private val directory: File,
    scope: CoroutineScope,
    private val onFailure: (Exception) -> Unit
) {
    private val token = savedState.get<String>(STATE_KEY)?.takeIf(NodeIdFile::isValidToken)
        ?: UUID.randomUUID().toString().also { savedState[STATE_KEY] = it }
    private val file = File(directory, token)
    private val mutex = Mutex()
    private var lastSaved: Set<Long>? = null // Access only while holding mutex.
    private val changes = Channel<Unit>(Channel.CONFLATED)
    private val mutableIds = MutableStateFlow<Set<Long>>(emptySet())
    val ids = mutableIds.asStateFlow()
    private val mutableReady = MutableStateFlow(false)
    val ready = mutableReady.asStateFlow()

    init {
        scope.launch {
            try {
                mutableIds.value = withContext(Dispatchers.IO) { read() }
            } catch (error: kotlinx.coroutines.CancellationException) {
                throw error
            } catch (error: Exception) {
                onFailure(error)
            }
            mutableReady.value = true
            for (ignored in changes) {
                try {
                    flush()
                } catch (error: kotlinx.coroutines.CancellationException) {
                    throw error
                } catch (error: Exception) {
                    onFailure(error)
                }
            }
        }
    }

    fun replace(ids: Collection<Long>) {
        check(ready.value) { "Selection is still loading" }
        NodeIdFile.validate(ids)
        mutableIds.value = ids.toSet()
        changes.trySend(Unit)
    }

    suspend fun flush() = withContext(Dispatchers.IO) {
        mutex.withLock {
            val snapshot = ids.value
            if (snapshot == lastSaved) return@withLock
            NodeIdFile.write(file, snapshot)
            lastSaved = snapshot
        }
    }

    private fun read(): Set<Long> {
        NodeIdFile.removeExpired(directory, token)
        if (!file.exists()) return emptySet()
        return NodeIdFile.read(file).toSet()
    }

    private companion object {
        const val STATE_KEY = "node_selection_file"
    }
}
