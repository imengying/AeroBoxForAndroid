package com.aerobox.viewmodel.nodeeditor

import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.connectionFingerprint
import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONObject

data class StoredNodeDraft(val nodeId: Long, val fingerprint: String, val edits: Map<String, String>)

/** Private draft contents never enter the activity Bundle. The saved-state token names this file. */
class NodeDraftStore(private val file: File) {
    private val mutex = Mutex()

    suspend fun read(): StoredNodeDraft? = withContext(Dispatchers.IO) {
        mutex.withLock {
            val expiry = System.currentTimeMillis() - 7 * 24 * 60 * 60 * 1000L
            file.parentFile?.listFiles().orEmpty().filter { it.name != file.name && it.lastModified() < expiry }
                .forEach { it.delete() }
            if (!file.exists()) return@withLock null
            require(file.length() <= MAX_BYTES)
            val data = JSONObject(file.readText())
            require(data.getInt("version") == 1)
            val values = data.getJSONObject("edits")
            val edits = values.keys().asSequence().associateWith { key ->
                require(key in NodeEditFields.byKey && values.get(key) is String)
                values.getString(key)
            }
            StoredNodeDraft(data.getLong("nodeId"), data.getString("fingerprint"), edits)
        }
    }

    suspend fun write(draft: NodeEditDraft) = withContext(NonCancellable + Dispatchers.IO) {
        mutex.withLock {
            val data = JSONObject().put("version", 1).put("nodeId", draft.original.id)
                .put("fingerprint", draft.sourceFingerprint).put("edits", JSONObject(draft.edits))
                .toString().toByteArray(Charsets.UTF_8)
            require(data.size <= MAX_BYTES)
            val parent = requireNotNull(file.parentFile)
            check(parent.isDirectory || parent.mkdirs())
            val temporary = File(parent, "${file.name}.tmp")
            try {
                FileOutputStream(temporary).use { stream -> stream.write(data); stream.fd.sync() }
                Files.move(temporary.toPath(), file.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            } finally { temporary.delete() }
        }
    }

    suspend fun clear() = withContext(NonCancellable + Dispatchers.IO) {
        mutex.withLock { check(!file.exists() || file.delete()) }
    }

    companion object {
        private const val MAX_BYTES = 4 * 1024 * 1024
        fun fingerprint(node: ProxyNode): String = MessageDigest.getInstance("SHA-256")
            .digest(node.connectionFingerprint().toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
