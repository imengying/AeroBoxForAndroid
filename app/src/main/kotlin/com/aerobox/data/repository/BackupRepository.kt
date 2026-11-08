package com.aerobox.data.repository

import android.content.Context
import android.database.Cursor
import android.net.Uri
import androidx.room.withTransaction
import androidx.sqlite.db.SupportSQLiteDatabase
import com.aerobox.BuildConfig
import com.aerobox.data.database.AppDatabase
import com.aerobox.data.database.PendingRestore
import java.util.UUID
import kotlinx.coroutines.sync.Mutex
import com.aerobox.R
import com.aerobox.core.errors.LocalizedException
import com.aerobox.data.model.ProxyType
import com.aerobox.utils.PreferenceManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject

/** Versioned, lossless row backup. SQL identifiers come only from our local Room schema. */
class BackupRepository(
    private val context: Context,
    private val database: AppDatabase,
    private val settingsStore: RecoveringSettingsStore,
    private val runtimeMutex: Mutex,
    private val vpnActive: () -> Boolean,
    private val validSubscriptionUrl: (String) -> Boolean,
    private val rescheduleUpdates: suspend () -> Unit
) {
    private val tables = listOf("subscriptions", "proxy_nodes")
    private val codec = BackupCodec()

    suspend fun export(uri: Uri) = withContext(Dispatchers.IO) {
        try {
            BackupExporter(runtimeMutex).export(
                capture = {
                    val settings = PreferenceManager.exportSettings(context)
                    database.withTransaction {
                        val db = database.openHelper.readableDatabase
                        // Own both cursors here so a size/count rejection also closes them.
                        db.query("SELECT * FROM subscriptions ORDER BY id").use { subscriptions ->
                            db.query("SELECT * FROM proxy_nodes ORDER BY id").use { nodes ->
                                codec.encode(db.version, BuildConfig.VERSION_NAME, settings,
                                    rows(subscriptions), rows(nodes))
                            }
                        }
                    }
                },
                write = { DocumentIo.write(context, uri, it) }
            )
        } catch (error: BackupLimitExceededException) {
            throw LocalizedException(R.string.backup_too_large, cause = error)
        }
    }

    suspend fun restore(uri: Uri): Int = withContext(Dispatchers.IO) {
        val backup = try {
            BackupMigrations.upgrade(
                DocumentIo.read(context, uri, codec::read), database.openHelper.readableDatabase.version
            )
        } catch (error: BackupLimitExceededException) {
            throw LocalizedException(R.string.backup_too_large, cause = error)
        } catch (error: JSONException) {
            throw LocalizedException(R.string.backup_invalid, cause = error)
        } catch (error: IllegalArgumentException) {
            throw LocalizedException(R.string.backup_invalid, cause = error)
        }
        require(backup.getString("format") == "aerobox-backup" && backup.getInt("version") == 1) {
            context.getString(R.string.backup_invalid)
        }
        val settings = backup.getJSONObject("settings")
        PreferenceManager.validateSettings(settings)
        val subscriptions = backup.getJSONArray("subscriptions")
        val nodes = backup.getJSONArray("proxy_nodes")
        runtimeMutex.withLock {
            check(!vpnActive()) { context.getString(R.string.backup_stop_vpn) }
            val previousSettings = PreferenceManager.exportSettings(context)
            try {
                settingsStore.commitRestore {
                    database.withTransaction {
                        val db = database.openHelper.writableDatabase
                        require(backup.getInt("schema") == db.version) { context.getString(R.string.backup_invalid) }
                        tables.forEach { validateRows(db, it, backup.getJSONArray(it)) }
                        val groupIds = mutableMapOf(0L to 0L)
                        groupIds.putAll(insertRows(db, "subscriptions", subscriptions) { row ->
                            val url = row.getString("url")
                            require(url.isBlank() || validSubscriptionUrl(url))
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
                        database.pendingRestoreDao().insert(PendingRestore(
                            token = UUID.randomUUID().toString(), settings = settings.toString(), selectedNodeId = selectedId
                        ))
                    }
                }
            } catch (error: RestoreCompletionException) {
                throw LocalizedException(R.string.backup_restore_pending, cause = error)
            }
            rescheduleUpdates()
        }
        nodes.length()
    }

    private fun rows(cursor: Cursor): Sequence<JSONObject> = generateSequence {
        if (!cursor.moveToNext()) null else JSONObject().apply {
            cursor.columnNames.forEachIndexed { index, name ->
                put(name, when (cursor.getType(index)) {
                    Cursor.FIELD_TYPE_NULL -> JSONObject.NULL
                    Cursor.FIELD_TYPE_INTEGER -> cursor.getLong(index)
                    Cursor.FIELD_TYPE_STRING -> cursor.getString(index)
                    else -> error("Unsupported backup column: $name")
                })
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
