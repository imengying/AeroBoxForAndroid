package com.aerobox.data.database

import androidx.sqlite.db.SupportSQLiteDatabase
import java.io.File
import java.lang.reflect.Proxy
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class RestoreJournalMigrationTest {
    private fun entities(version: Int): Map<String, JSONObject> {
        val schema = JSONObject(File(System.getProperty("aerobox.schemaDirectory"),
            "com.aerobox.data.database.AppDatabase/$version.json").readText())
        val rows = schema.getJSONObject("database").getJSONArray("entities")
        return (0 until rows.length()).map { rows.getJSONObject(it) }.associateBy { it.getString("tableName") }
    }

    @Test fun migrationCreatesTheRoomJournalSchemaWithoutChangingExistingTables() {
        val statements = mutableListOf<String>()
        val db = Proxy.newProxyInstance(javaClass.classLoader, arrayOf(SupportSQLiteDatabase::class.java)) { _, method, args ->
            check(method.name == "execSQL") { "Unexpected database operation: ${method.name}" }
            statements += args!![0] as String
            null
        } as SupportSQLiteDatabase
        AppDatabase.MIGRATION_2_3.migrate(db)
        val schema = entities(3)
        val journalSql = schema.getValue("pending_restore").getString("createSql")
            .replace("\${TABLE_NAME}", "pending_restore")
        assertEquals(listOf(journalSql), statements)
        entities(2).forEach { (name, previous) ->
            assertEquals(previous.toString(), schema.getValue(name).toString())
        }
    }
}
