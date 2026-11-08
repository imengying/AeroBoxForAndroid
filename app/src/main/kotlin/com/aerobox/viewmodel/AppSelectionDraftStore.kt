package com.aerobox.viewmodel

import com.aerobox.utils.writeAtomically
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

data class AppSelectionDraft(val original: Set<String>, val selected: Set<String> = original) {
    val changed: Boolean get() = selected != original

    // Apply only this page's changes if settings were updated while it was open.
    fun applyTo(current: Set<String>): Set<String> = (current - (original - selected)) + (selected - original)
}

/** Only the file token enters saved state, even on devices with many installed packages. */
class AppSelectionDraftStore(private val file: File) {
    private val mutex = Mutex()

    suspend fun read(): AppSelectionDraft? = withContext(Dispatchers.IO) {
        mutex.withLock {
            NodeIdFile.removeExpired(requireNotNull(file.parentFile), file.name)
            if (!file.exists()) return@withLock null
            require(file.length() <= MAX_BYTES)
            val data = JSONObject(file.readText())
            require(data.getInt("version") == 1)
            AppSelectionDraft(readPackages(data.getJSONArray("original")), readPackages(data.getJSONArray("selected")))
        }
    }

    suspend fun write(draft: AppSelectionDraft) = withContext(NonCancellable + Dispatchers.IO) {
        mutex.withLock {
            validate(draft.original)
            validate(draft.selected)
            val data = JSONObject().put("version", 1)
                .put("original", JSONArray(draft.original.toList()))
                .put("selected", JSONArray(draft.selected.toList()))
                .toString().toByteArray(Charsets.UTF_8)
            require(data.size <= MAX_BYTES)
            file.writeAtomically { it.write(data) }
        }
    }

    suspend fun clear() = withContext(NonCancellable + Dispatchers.IO) {
        mutex.withLock { check(!file.exists() || file.delete()) }
    }

    private fun readPackages(array: JSONArray): Set<String> {
        require(array.length() <= MAX_PACKAGES)
        return (0 until array.length()).map {
            require(array.get(it) is String)
            array.getString(it)
        }.toSet().also(::validate)
    }

    private fun validate(packages: Set<String>) {
        require(packages.size <= MAX_PACKAGES && packages.all { it.isNotBlank() && it.length <= 255 })
    }

    private companion object {
        const val MAX_PACKAGES = 10_000
        const val MAX_BYTES = 2 * 1024 * 1024
    }
}
