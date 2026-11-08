package com.aerobox

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.net.ConnectivityManager
import com.aerobox.core.logging.CrashDiagnostics
import com.aerobox.core.logging.RuntimeLogBuffer
import com.aerobox.core.native.SingBoxNative
import com.aerobox.service.VpnStateManager
import com.aerobox.work.SubscriptionUpdateScheduler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

class AeroBoxApplication : Application() {
    private val applicationScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    val container by lazy { AppContainer(this, applicationScope) }

    override fun onCreate() {
        super.onCreate()
        _appInstance = this

        RuntimeLogBuffer.initialize(this, applicationScope)
        CrashDiagnostics.install(this, applicationScope)
        VpnStateManager.resetTrafficSession()
        createNotificationChannel()
        SingBoxNative.initialize(this, applicationScope)

        applicationScope.launch {
            container.settingsStore.recover()
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

    }
}
