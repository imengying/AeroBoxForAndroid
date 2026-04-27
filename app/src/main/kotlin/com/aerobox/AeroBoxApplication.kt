package com.aerobox

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.net.ConnectivityManager
import androidx.room.Room
import com.aerobox.core.logging.RuntimeLogBuffer
import com.aerobox.data.database.AppDatabase
import com.aerobox.core.geo.GeoAssetManager
import com.aerobox.core.native.SingBoxNative
import com.aerobox.data.repository.VpnRepository
import com.aerobox.service.VpnStateManager
import com.aerobox.work.SubscriptionUpdateScheduler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

class AeroBoxApplication : Application() {
    private val applicationScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    override fun onCreate() {
        super.onCreate()
        _appInstance = this

        // Ensure singleton initialization
        database
        RuntimeLogBuffer.initialize(this)
        VpnStateManager.resetTrafficSession()
        createNotificationChannel()
        SingBoxNative.setup(this)

        applicationScope.launch(Dispatchers.IO) {
            GeoAssetManager.ensureBundledAssets(this@AeroBoxApplication)
        }

        applicationScope.launch {
            SubscriptionUpdateScheduler.reconfigure(this@AeroBoxApplication)
        }
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            NOTIFICATION_CHANNEL_ID,
            getString(R.string.app_name),
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
            )
                .build()
        }

        val vpnRepository: VpnRepository by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
            VpnRepository(_appInstance)
        }
    }
}
