package com.aerobox

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.os.Build
import androidx.room.Room
import com.aerobox.data.database.AppDatabase

class AeroBoxApplication : Application() {

    override fun onCreate() {
        super.onCreate()
        appInstance = this

        // Ensure singleton initialization happens once for the process.
        val unusedDatabase = database
        createNotificationChannel()
        runCatching { System.loadLibrary("box") }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return

        val channel = NotificationChannel(
            NOTIFICATION_CHANNEL_ID,
            "AeroBox VPN",
            NotificationManager.IMPORTANCE_LOW
        )
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.createNotificationChannel(channel)
    }

    companion object {
        const val NOTIFICATION_CHANNEL_ID = "aerobox_vpn_channel"

        private lateinit var appInstance: AeroBoxApplication

        val database: AppDatabase by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
            Room.databaseBuilder(
                appInstance,
                AppDatabase::class.java,
                "aerobox.db"
            ).fallbackToDestructiveMigration().build()
        }
    }
}
