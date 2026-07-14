package com.aerobox.data.database

import androidx.room.Database
import androidx.room.RoomDatabase
import androidx.room.TypeConverters
import androidx.room.migration.Migration
import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.Subscription

@Database(entities = [ProxyNode::class, Subscription::class], version = 2, exportSchema = true)
@TypeConverters(Converters::class)
abstract class AppDatabase : RoomDatabase() {
    abstract fun subscriptionDao(): SubscriptionDao
    abstract fun proxyNodeDao(): ProxyNodeDao

    companion object {
        val MIGRATION_1_2: Migration = DatabaseMigration1To2
    }
}
