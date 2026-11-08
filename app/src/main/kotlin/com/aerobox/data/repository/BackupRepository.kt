package com.aerobox.data.repository

import android.content.Context
import android.database.Cursor
import android.net.Uri
import androidx.room.withTransaction
import androidx.sqlite.db.SupportSQLiteDatabase
import com.aerobox.AeroBoxApplication
import com.aerobox.BuildConfig
import com.aerobox.R
import com.aerobox.data.model.ProxyType
import com.aerobox.service.VpnStateManager
import com.aerobox.utils.PreferenceManager
import com.aerobox.work.SubscriptionUpdateScheduler
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

/** Versioned, lossless row backup. SQL identifiers come only from our local Room schema. */
class BackupRepository(private val context: Context) {
    private val database get() = AeroBoxApplication.database
    private val tables = listOf("subscriptions", "proxy_nodes")

    suspend fun export(uri: Uri) = withContext(Dispatchers.IO) {
        AeroBoxApplication.vpnRepository.runtimeSettingsMutex.withLock {
            val backup = database.withTransaction {
                JSONObject().put("format", "aerobox-backup").put("version", 1)
                    .put("schema", database.openHelper.readableDatabase.version)
                    .put("appVersion", BuildConfig.VERSION_NAME)
                    .put("settings", PreferenceManager.exportSettings(context))
                    .apply { tables.forEach { put(it, readTable(it)) } }
            }
            DocumentIo.write(context, uri, backup.toString())
        }
    }

    suspend fun restore(uri: Uri): Int = withContext(Dispatchers.IO) {
        val backup = JSONObject(DocumentIo.read(context, uri))
        require(backup.getString("format") == "aerobox-backup" && backup.getInt("version") == 1) {
            context.getString(R.string.backup_invalid)
        }
        val settings = backup.getJSONObject("settings")
        PreferenceManager.validateSettings(settings)
        val subscriptions = backup.getJSONArray("subscriptions")
        val nodes = backup.getJSONArray("proxy_nodes")
        require(subscriptions.length() <= 10_000 && nodes.length() <= 50_000)
        AeroBoxApplication.vpnRepository.runtimeSettingsMutex.withLock {
            check(!VpnStateManager.serviceActive.value) { context.getString(R.string.backup_stop_vpn) }
            val previousSettings = PreferenceManager.exportSettings(context)
            // Room and DataStore have separate transactions. Complete or compensate the settings
            // write even if the screen is closed while committing the database transaction.
            withContext(NonCancellable) {
                try {
                    database.withTransaction {
                        val db = database.openHelper.writableDatabase
                        require(backup.getInt("schema") == db.version) { context.getString(R.string.backup_invalid) }
                        tables.forEach { validateRows(db, it, backup.getJSONArray(it)) }
                        val groupIds = mutableMapOf(0L to 0L)
                        groupIds.putAll(insertRows(db, "subscriptions", subscriptions) { row ->
                            val url = row.getString("url")
                            require(url.isBlank() || AeroBoxApplication.subscriptionRepository.isValidRemoteSubscriptionUrl(url))
                            require(row.getLong("updateInterval") > 0L)
                            row.put("nodeCount", 0)
                        })
                        val nodeIds = insertRows(db, "proxy_nodes", nodes) { row ->
                            ProxyType.valueOf(row.getString("type"))
                            require(row.getInt("port") in 1..65535 && row.getString("server").isNotBlank())
                            val groupId = requireNotNull(groupIds[row.getLong("subscriptionId")])
                            row.put("subscriptionId", groupId)
                        }
                        groupIds.values.filter { it > 0 }.forEach { id ->
                            database.subscriptionDao().updateNodeCount(id, database.proxyNodeDao().countBySubscription(id))
                        }
                        val selectedId = nodeIds[settings.getLong("last_selected_node_id")]
                            ?: nodeIds.values.firstOrNull() ?: previousSettings.getLong("last_selected_node_id")
                        PreferenceManager.restoreSettings(context, settings, selectedId)
                    }
                } catch (error: Exception) {
                    PreferenceManager.restoreSettings(context, previousSettings, previousSettings.getLong("last_selected_node_id"))
                    throw error
                }
                SubscriptionUpdateScheduler.reconfigure(context)
            }
        }
        nodes.length()
    }

    private fun readTable(table: String): JSONArray {
        return JSONArray().apply {
            database.openHelper.readableDatabase.query("SELECT * FROM $table ORDER BY id").use { cursor ->
                while (cursor.moveToNext()) {
                    put(JSONObject().apply {
                        cursor.columnNames.forEachIndexed { index, name ->
                            put(name, when (cursor.getType(index)) {
                                Cursor.FIELD_TYPE_NULL -> JSONObject.NULL
                                Cursor.FIELD_TYPE_INTEGER -> cursor.getLong(index)
                                Cursor.FIELD_TYPE_STRING -> cursor.getString(index)
                                else -> error("Unsupported backup column: $name")
                            })
                        }
                    })
                }
            }
        }
    }

    private fun validateRows(db: SupportSQLiteDatabase, table: String, rows: JSONArray) {
        data class Column(val name: String, val type: String, val required: Boolean)
        val columns = db.query("PRAGMA table_info($table)").use { cursor ->
            buildList {
                while (cursor.moveToNext()) add(Column(cursor.getString(1), cursor.getString(2), cursor.getInt(3) != 0))
            }
        }
        val names = columns.map { it.name }.toSet()
        repeat(rows.length()) { index ->
            val row = rows.getJSONObject(index)
            require(row.keys().asSequence().toSet() == names) { context.getString(R.string.backup_invalid) }
            columns.forEach { column ->
                val value = row.get(column.name)
                require(when {
                    value == JSONObject.NULL -> !column.required
                    column.type == "TEXT" -> value is String
                    column.type == "INTEGER" -> value is Int || value is Long
                    else -> false
                }) { context.getString(R.string.backup_invalid) }
            }
        }
    }

    private fun insertRows(
        db: SupportSQLiteDatabase,
        table: String,
        rows: JSONArray,
        prepare: (JSONObject) -> Unit
    ): Map<Long, Long> {
        val columns = db.query("SELECT * FROM $table LIMIT 0").use { it.columnNames.filter { name -> name != "id" } }
        val sql = "INSERT INTO $table (${columns.joinToString(",") { "`$it`" }}) VALUES (${columns.joinToString(",") { "?" }})"
        val ids = mutableMapOf<Long, Long>()
        db.compileStatement(sql).use { statement ->
            repeat(rows.length()) { rowIndex ->
                val row = rows.getJSONObject(rowIndex)
                val id = row.getLong("id")
                require(id > 0 && id !in ids)
                prepare(row)
                columns.forEachIndexed { index, name ->
                    when (val value = row.get(name)) {
                        JSONObject.NULL -> statement.bindNull(index + 1)
                        is Number -> statement.bindLong(index + 1, value.toLong())
                        is String -> statement.bindString(index + 1, value)
                        else -> error("Invalid backup value")
                    }
                }
                ids[id] = statement.executeInsert()
            }
        }
        return ids
    }
}

internal object DocumentIo {
    private const val MAX_BYTES = 32 * 1024 * 1024

    fun read(context: Context, uri: Uri): String {
        return requireNotNull(context.contentResolver.openInputStream(uri)).use { input ->
            val output = java.io.ByteArrayOutputStream()
            val buffer = ByteArray(8192)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                require(output.size() + count <= MAX_BYTES) { context.getString(R.string.backup_invalid) }
                output.write(buffer, 0, count)
            }
            output.toString(Charsets.UTF_8.name())
        }
    }

    fun write(context: Context, uri: Uri, content: String) {
        requireNotNull(context.contentResolver.openOutputStream(uri, "wt")).bufferedWriter().use { it.write(content) }
    }
}
