package com.aerobox.data.database

import androidx.room.Database
import androidx.room.RoomDatabase
import androidx.room.TypeConverters
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase
import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.Subscription

@Database(entities = [ProxyNode::class, Subscription::class], version = 2, exportSchema = false)
@TypeConverters(Converters::class)
abstract class AppDatabase : RoomDatabase() {
    abstract fun subscriptionDao(): SubscriptionDao
    abstract fun proxyNodeDao(): ProxyNodeDao

    companion object {
        /**
         * Schema v1 → v2: adds multiplex tuning, ShadowTLS handshake layer,
         * and dial-level TCP keep-alive columns to `proxy_nodes`. All new
         * columns are nullable INTEGER/TEXT, so existing rows simply get
         * NULL and parsers will refill them on the next subscription
         * refresh / inline import.
         */
        val MIGRATION_1_2 = object : Migration(1, 2) {
            override fun migrate(db: SupportSQLiteDatabase) {
                val newColumns = listOf(
                    "muxProtocol TEXT",
                    "muxMaxConnections INTEGER",
                    "muxMinStreams INTEGER",
                    "muxMaxStreams INTEGER",
                    "muxPadding INTEGER",
                    "muxBrutalEnabled INTEGER",
                    "muxBrutalUpMbps INTEGER",
                    "muxBrutalDownMbps INTEGER",
                    "shadowTlsVersion INTEGER",
                    "shadowTlsPassword TEXT",
                    "shadowTlsServerName TEXT",
                    "shadowTlsAlpn TEXT",
                    "disableTcpKeepAlive INTEGER",
                    "tcpKeepAlive TEXT",
                    "tcpKeepAliveInterval TEXT"
                )
                newColumns.forEach { spec ->
                    db.execSQL("ALTER TABLE proxy_nodes ADD COLUMN $spec")
                }
            }
        }
    }
}
