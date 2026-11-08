package com.aerobox.data.repository

import com.aerobox.data.database.SchemaV2
import org.json.JSONArray
import org.json.JSONObject

/** Upgrade an owned, parsed document before validating against the destination database. */
internal object BackupMigrations {
    fun upgrade(backup: JSONObject, targetSchema: Int, limits: BackupLimits = BackupLimits()): JSONObject {
        require(backup.getString("format") == "aerobox-backup" && backup.getInt("version") == 1)
        var schema = backup.getInt("schema")
        require(schema in 1..targetSchema)
        while (schema < targetSchema) {
            when (schema) {
                1 -> {
                    // Defaults can expand a small legacy file significantly. Bound the upgraded
                    // document while converting each row, before retaining its expanded object.
                    val envelope = JSONObject()
                    backup.keys().asSequence().filter { it != "subscriptions" && it != "proxy_nodes" }
                        .forEach { envelope.put(it, backup.get(it)) }
                    envelope.put("schema", 2).put("subscriptions", JSONArray()).put("proxy_nodes", JSONArray())
                    var remaining = limits.maxBytes - envelope.toString().toByteArray(Charsets.UTF_8).size
                    if (remaining < 0) throw BackupLimitExceededException()
                    val reserve: (JSONObject, Int) -> Unit = { row, index ->
                        val bytes = row.toString().toByteArray(Charsets.UTF_8).size + if (index > 0) 1 else 0
                        if (bytes > remaining) throw BackupLimitExceededException()
                        remaining -= bytes
                    }
                    migrateRows(backup.getJSONArray("subscriptions"), SchemaV2.subscriptionColumns,
                        setOf("id", "name", "url"), reserve)
                    migrateRows(backup.getJSONArray("proxy_nodes"), SchemaV2.proxyNodeColumns,
                        setOf("id", "name", "type", "server", "port", "subscriptionId"), reserve)
                }
                // Schema 3 adds only the internal recovery journal; exported rows are unchanged.
                2 -> Unit
                else -> error("Unsupported backup schema migration: $schema")
            }
            schema++
            backup.put("schema", schema)
        }
        return backup
    }

    private fun migrateRows(
        rows: JSONArray,
        columns: List<SchemaV2.Column>,
        required: Set<String>,
        reserve: (JSONObject, Int) -> Unit
    ) {
        val allowed = columns.flatMap { it.sourceNames }.toSet()
        repeat(rows.length()) { index ->
            val original = rows.getJSONObject(index)
            require(original.keys().asSequence().all { it in allowed })
            require(required.all { original.has(it) && !original.isNull(it) })
            val migrated = JSONObject()
            columns.forEach { column ->
                val source = column.sourceNames.firstOrNull(original::has)
                val value = if (source != null) original.get(source) else when {
                    column.fallback == "NULL" -> JSONObject.NULL
                    column.fallback.startsWith("'") -> column.fallback.removeSurrounding("'")
                    else -> column.fallback.toLong()
                }
                migrated.put(column.name, value)
            }
            reserve(migrated, index)
            rows.put(index, migrated)
        }
    }
}
