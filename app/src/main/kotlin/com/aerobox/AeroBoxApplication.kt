package com.aerobox

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.net.ConnectivityManager
import android.os.Build
import androidx.room.Room
import com.aerobox.data.database.AppDatabase
import com.aerobox.core.native.SingBoxNative

class AeroBoxApplication : Application() {

    override fun onCreate() {
        super.onCreate()
        _appInstance = this

        // Ensure singleton initialization
        database
        createNotificationChannel()
        SingBoxNative.setup(this)
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

        private lateinit var _appInstance: AeroBoxApplication

        val appInstance: AeroBoxApplication get() = _appInstance

        val connectivity: ConnectivityManager
            get() = _appInstance.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

        val database: AppDatabase by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
            Room.databaseBuilder(
                _appInstance,
                AppDatabase::class.java,
                "aerobox.db"
            ).fallbackToDestructiveMigrationOnDowngrade().build()
        }
    }
}

