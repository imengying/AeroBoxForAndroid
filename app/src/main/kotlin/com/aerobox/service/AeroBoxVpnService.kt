package com.aerobox.service

import android.app.Notification
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import com.aerobox.AeroBoxApplication
import com.aerobox.MainActivity
import com.aerobox.R
import com.aerobox.core.native.SingBoxNative
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import com.aerobox.utils.PreferenceManager
import com.aerobox.utils.NetworkUtils

class AeroBoxVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.aerobox.action.START"
        const val ACTION_STOP = "com.aerobox.action.STOP"
        const val EXTRA_CONFIG = "extra_config"
        const val NOTIFICATION_ID = 1001

        private val _isRunning = MutableStateFlow(false)
        val isRunning: StateFlow<Boolean> = _isRunning.asStateFlow()
    }

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var vpnInterface: ParcelFileDescriptor? = null
    private var speedTickerJob: Job? = null

    override fun onBind(intent: Intent?): IBinder? = super.onBind(intent)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> {
                val config = intent.getStringExtra(EXTRA_CONFIG).orEmpty()
                startVpn(config)
            }

            ACTION_STOP -> {
                stopVpn()
                stopSelf()
            }
        }
        return START_STICKY
    }

    private fun startVpn(config: String) {
        serviceScope.launch {
            runCatching {
                startForeground(
                    NOTIFICATION_ID,
                    buildNotification(getString(R.string.notification_connecting))
                )

                vpnInterface?.close()
                val builder = Builder()
                    .setSession("AeroBox VPN")
                    .addAddress("172.19.0.1", 30)
                    .addRoute("0.0.0.0", 0)
                    .addDnsServer("8.8.8.8")
                    .setMtu(9000)

                // Per-app proxy
                val perAppEnabled = runBlocking {
                    PreferenceManager.perAppProxyEnabledFlow(applicationContext).first()
                }
                if (perAppEnabled) {
                    val mode = runBlocking {
                        PreferenceManager.perAppProxyModeFlow(applicationContext).first()
                    }
                    val packages = runBlocking {
                        PreferenceManager.perAppProxyPackagesFlow(applicationContext).first()
                    }
                    packages.forEach { pkg ->
                        runCatching {
                            if (mode == "whitelist") {
                                builder.addAllowedApplication(pkg)
                            } else {
                                builder.addDisallowedApplication(pkg)
                            }
                        }
                    }
                }

                vpnInterface = builder.establish()

                val fd = vpnInterface?.fd ?: -1
                if (fd < 0) {
                    throw IllegalStateException("Failed to establish VPN interface")
                }

                val started = SingBoxNative.startService(config, fd)
                if (!started) {
                    throw IllegalStateException("Failed to start sing-box service")
                }

                _isRunning.value = true
                startForeground(
                    NOTIFICATION_ID,
                    buildNotification(getString(R.string.notification_connected))
                )

                // Start speed ticker for notification
                startSpeedTicker()
            }.onFailure {
                stopVpn()
            }
        }
    }

    private fun stopVpn() {
        speedTickerJob?.cancel()
        speedTickerJob = null
        runCatching {
            SingBoxNative.stopService()
            vpnInterface?.close()
            vpnInterface = null
        }
        _isRunning.value = false
        VpnStateManager.updateConnectionState(false, null)
        VpnStateManager.resetStats()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }
    }

    private fun buildNotification(contentText: String): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, AeroBoxApplication.NOTIFICATION_CHANNEL_ID)
            .setContentTitle(getString(R.string.notification_title))
            .setContentText(contentText)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .setSilent(true)
            .build()
    }

    private fun startSpeedTicker() {
        speedTickerJob?.cancel()
        speedTickerJob = serviceScope.launch {
            while (isActive) {
                delay(2000)
                val stats = VpnStateManager.trafficStats.value
                val upSpeed = NetworkUtils.formatBytes(stats.uploadSpeed) + "/s"
                val downSpeed = NetworkUtils.formatBytes(stats.downloadSpeed) + "/s"
                val text = "↑ $upSpeed  ↓ $downSpeed"
                val notification = buildNotification(text)
                val nm = getSystemService(NOTIFICATION_SERVICE) as android.app.NotificationManager
                nm.notify(NOTIFICATION_ID, notification)
            }
        }
    }

    override fun onDestroy() {
        stopVpn()
        serviceScope.cancel()
        super.onDestroy()
    }
}
