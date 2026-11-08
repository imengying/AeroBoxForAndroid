package com.aerobox.data.database

import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

internal object DatabaseMigration1To2 : Migration(1, 2) {
    override fun migrate(db: SupportSQLiteDatabase) {
        rebuildTable(db, "subscriptions", SchemaV2.subscriptionColumns)
        rebuildTable(db, "proxy_nodes", SchemaV2.proxyNodeColumns)
        db.execSQL(
            "CREATE INDEX IF NOT EXISTS `index_proxy_nodes_subscriptionId` " +
                "ON `proxy_nodes` (`subscriptionId`)"
        )
    }

    private fun rebuildTable(
        db: SupportSQLiteDatabase,
        tableName: String,
        columns: List<SchemaV2.Column>
    ) {
        val sourceColumns = tableColumns(db, tableName)
        val oldTableName = "${tableName}_v1"
        db.execSQL("ALTER TABLE `$tableName` RENAME TO `$oldTableName`")
        db.execSQL(
            columns.joinToString(
                prefix = "CREATE TABLE `$tableName` (",
                postfix = ")"
            ) { column -> "`${column.name}` ${column.definition}" }
        )

        val targetNames = columns.joinToString { "`${it.name}`" }
        val sourceValues = columns.joinToString { column ->
            column.sourceNames
                .firstOrNull(sourceColumns::contains)
                ?.let { "`$it`" }
                ?: column.fallback
        }
        db.execSQL(
            "INSERT INTO `$tableName` ($targetNames) " +
                "SELECT $sourceValues FROM `$oldTableName`"
        )
        db.execSQL("DROP TABLE `$oldTableName`")
    }

    private fun tableColumns(db: SupportSQLiteDatabase, tableName: String): Set<String> {
        return buildSet {
            db.query("PRAGMA table_info(`$tableName`)").use { cursor ->
                val nameIndex = cursor.getColumnIndexOrThrow("name")
                while (cursor.moveToNext()) add(cursor.getString(nameIndex))
            }
        }
    }

}
