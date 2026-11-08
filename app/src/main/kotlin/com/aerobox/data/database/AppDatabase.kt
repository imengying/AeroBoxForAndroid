package com.aerobox.data.database

import androidx.room.Database
import androidx.room.RoomDatabase
import androidx.room.TypeConverters
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase
import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.Subscription

@Database(entities = [ProxyNode::class, Subscription::class, PendingRestore::class], version = 3, exportSchema = true)
@TypeConverters(Converters::class)
abstract class AppDatabase : RoomDatabase() {
    abstract fun subscriptionDao(): SubscriptionDao
    abstract fun proxyNodeDao(): ProxyNodeDao
    abstract fun pendingRestoreDao(): PendingRestoreDao

    companion object {
        val MIGRATION_1_2: Migration = DatabaseMigration1To2
        val MIGRATION_2_3: Migration = object : Migration(2, 3) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("CREATE TABLE IF NOT EXISTS `pending_restore` (`id` INTEGER NOT NULL, " +
                    "`token` TEXT NOT NULL, `settings` TEXT NOT NULL, `selectedNodeId` INTEGER NOT NULL, PRIMARY KEY(`id`))")
            }
        }
    }
}
