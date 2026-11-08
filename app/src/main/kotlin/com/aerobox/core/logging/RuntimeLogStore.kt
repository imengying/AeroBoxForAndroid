package com.aerobox.core.logging

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.StandardCopyOption

/** Bounded, already-redacted errors; disk work is serialized and stays off the UI thread. */
internal class RuntimeLogStore(private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO) {
    private val stateLock = Any()
    private val diskMutex = Mutex()
    private val changes = Channel<Unit>(Channel.CONFLATED)
    private val _lines = MutableStateFlow<List<RuntimeLogEntry>>(emptyList())
    val lines = _lines.asStateFlow()
    private var cleared = false
    private var historyFile: File? = null

    fun persistTo(file: File, scope: CoroutineScope, onFailure: (Exception) -> Unit) {
        synchronized(stateLock) {
            check(historyFile == null) { "Log persistence already initialized" }
            historyFile = file
        }
        scope.launch(ioDispatcher) {
            diskMutex.withLock {
                val restored = try {
                    read(file)
                } catch (error: Exception) {
                    onFailure(error)
                    emptyList()
                }
                synchronized(stateLock) {
                    // Appends during startup survive restoration; a clear must not resurrect history.
                    if (!cleared) _lines.value = bounded((restored + _lines.value).sortedBy { it.timestamp })
                }
            }
            for (ignored in changes) {
                diskMutex.withLock {
                    try {
                        write(file, lines.value)
                    } catch (error: Exception) {
                        onFailure(error)
                    }
                }
            }
        }
    }

    fun append(entry: RuntimeLogEntry) {
        synchronized(stateLock) {
            _lines.value = bounded(_lines.value + entry.copy(message = entry.message.take(MAX_MESSAGE_CHARS)))
        }
        changes.trySend(Unit)
    }

    suspend fun clear(): Unit = withContext(ioDispatcher) {
        synchronized(stateLock) {
            cleared = true
            _lines.value = emptyList()
        }
        changes.trySend(Unit)
        diskMutex.withLock {
            // Read the current snapshot after acquiring the disk lock, so queued writes cannot
            // put pre-clear entries back. New errors arriving during clear are retained.
            historyFile?.let { write(it, lines.value) }
        }
    }

    private fun bounded(entries: List<RuntimeLogEntry>): List<RuntimeLogEntry> {
        var characters = 0
        return entries.takeLast(MAX_LINES).asReversed().takeWhile {
            characters += it.message.length
            characters <= MAX_TOTAL_CHARS
        }.asReversed()
    }

    private fun read(file: File): List<RuntimeLogEntry> {
        if (!file.exists()) return emptyList()
        require(file.length() <= MAX_FILE_BYTES) { "Log history exceeds size limit" }
        val entries = JSONArray(file.readText(Charsets.UTF_8))
        return (maxOf(0, entries.length() - MAX_LINES) until entries.length()).mapNotNull { index ->
            val entry = entries.optJSONObject(index) ?: return@mapNotNull null
            val timestamp = entry.optLong("timestamp")
            val message = entry.optString("message").take(MAX_MESSAGE_CHARS)
            if (timestamp > 0 && message.isNotBlank()) RuntimeLogEntry(timestamp, message) else null
        }
    }

    private fun write(file: File, entries: List<RuntimeLogEntry>) {
        val json = JSONArray()
        entries.forEach { json.put(JSONObject().put("timestamp", it.timestamp).put("message", it.message)) }
        val bytes = json.toString().toByteArray(Charsets.UTF_8)
        check(bytes.size <= MAX_FILE_BYTES) { "Log history exceeds size limit" }
        check(file.parentFile?.let { it.isDirectory || it.mkdirs() } == true)
        val pending = File(file.parentFile, "${file.name}.tmp")
        try {
            FileOutputStream(pending).use { output ->
                output.write(bytes)
                output.fd.sync()
            }
            Files.move(pending.toPath(), file.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
        } finally {
            pending.delete()
        }
    }

    private companion object {
        const val MAX_LINES = 500
        const val MAX_MESSAGE_CHARS = 4096
        const val MAX_TOTAL_CHARS = 32 * 1024
        const val MAX_FILE_BYTES = 256 * 1024
    }
}
