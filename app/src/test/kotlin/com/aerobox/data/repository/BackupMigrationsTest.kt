package com.aerobox.data.repository

import java.io.File
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class BackupMigrationsTest {
    private fun legacy() = JSONObject().put("format", "aerobox-backup").put("version", 1).put("schema", 1)
        .put("settings", JSONObject().put("last_selected_node_id", 42L))
        .put("subscriptions", JSONArray().put(JSONObject().put("id", 7L).put("name", "legacy").put("url", "")))
        .put("proxy_nodes", JSONArray().put(JSONObject().put("id", 42L).put("name", "legacy node")
            .put("type", "NAIVE").put("server", "example.invalid").put("port", 443).put("subscriptionId", 7L)
            .put("password", "fixture-only").put("httpHeaders", "{\"X-Test\":\"value\"}")
            .put("transportPermitWithoutStream", 1).put("naiveCertificate", "fixture certificate")
            .put("naiveEchEnabled", 1)))

    @Test fun legacyAliasesDefaultsAndReferencesMigrateToTheCurrentRoomSchema() {
        val migrated = BackupMigrations.upgrade(legacy(), 2)
        assertEquals(2, migrated.getInt("schema"))
        assertEquals(42L, migrated.getJSONObject("settings").getLong("last_selected_node_id"))
        val node = migrated.getJSONArray("proxy_nodes").getJSONObject(0)
        assertEquals(7L, node.getLong("subscriptionId"))
        assertEquals("fixture-only", node.getString("password"))
        assertEquals("{\"X-Test\":\"value\"}", node.getString("transportHeaders"))
        assertEquals(1, node.getInt("grpcPermitWithoutStream"))
        assertEquals("fixture certificate", node.getString("tlsCertificate"))
        assertEquals(1, node.getInt("echEnabled"))
        assertEquals(-1, node.getInt("latency"))
        assertTrue(node.isNull("tcpKeepAlive"))
        assertFalse(node.has("naiveCertificate"))

        val schema = JSONObject(File(System.getProperty("aerobox.schemaDirectory"),
            "com.aerobox.data.database.AppDatabase/2.json").readText())
        val entities = schema.getJSONObject("database").getJSONArray("entities")
        repeat(entities.length()) { index ->
            val entity = entities.getJSONObject(index)
            val fields = entity.getJSONArray("fields")
            val row = migrated.getJSONArray(entity.getString("tableName")).getJSONObject(0)
            assertEquals((0 until fields.length()).map { fields.getJSONObject(it).getString("columnName") }.toSet(),
                row.keys().asSequence().toSet())
            repeat(fields.length()) { fieldIndex ->
                val field = fields.getJSONObject(fieldIndex)
                val value = row.get(field.getString("columnName"))
                if (field.optBoolean("notNull", false)) assertNotEquals(JSONObject.NULL, value)
                if (value != JSONObject.NULL) {
                    assertTrue(when (field.getString("affinity")) {
                        "TEXT" -> value is String
                        "INTEGER" -> value is Int || value is Long
                        else -> false
                    })
                }
            }
        }
    }

    @Test fun currentBackupsRemainUnchangedAndMigrationIsIdempotent() {
        val current = BackupMigrations.upgrade(legacy(), 2)
        val before = current.toString()
        BackupMigrations.upgrade(current, 2)
        assertEquals(before, current.toString())
    }

    @Test fun journalSchemaDoesNotChangeExportedRowsOrSettings() {
        val v2 = BackupMigrations.upgrade(legacy(), 2)
        val expected = JSONObject(v2.toString()).put("schema", 3).toString()
        val upgraded = BackupMigrations.upgrade(v2, 3)
        assertEquals(expected, upgraded.toString())
        assertEquals(expected, BackupMigrations.upgrade(upgraded, 3).toString())
        assertEquals(expected, BackupMigrations.upgrade(legacy(), 3).toString())
        assertFalse(upgraded.has("pending_restore"))
    }

    @Test fun canonicalFieldsWinOverLegacyAliases() {
        val backup = legacy()
        backup.getJSONArray("proxy_nodes").getJSONObject(0).put("tlsCertificate", "current certificate")
        assertEquals("current certificate", BackupMigrations.upgrade(backup, 2)
            .getJSONArray("proxy_nodes").getJSONObject(0).getString("tlsCertificate"))
    }

    @Test fun expansionByDefaultFieldsObeysTheSameUtf8ByteLimit() {
        val upgradedBytes = BackupMigrations.upgrade(legacy(), 2).toString().toByteArray(Charsets.UTF_8).size
        assertTrue(legacy().toString().toByteArray(Charsets.UTF_8).size < upgradedBytes)
        BackupMigrations.upgrade(legacy(), 2, BackupLimits(maxBytes = upgradedBytes))
        assertThrows(BackupLimitExceededException::class.java) {
            BackupMigrations.upgrade(legacy(), 2, BackupLimits(maxBytes = upgradedBytes - 1))
        }
    }

    @Test fun unknownVersionsColumnsAndMissingEndpointsAreRejected() {
        for (invalid in listOf(
            legacy().put("version", 99), legacy().put("schema", 99),
            legacy().apply { getJSONArray("proxy_nodes").getJSONObject(0).put("unrecognized", true) },
            legacy().apply { getJSONArray("proxy_nodes").getJSONObject(0).remove("server") }
        )) {
            assertThrows(IllegalArgumentException::class.java) { BackupMigrations.upgrade(invalid, 2) }
        }
    }
}
