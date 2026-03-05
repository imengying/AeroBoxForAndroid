package com.aerobox.receiver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat
import com.aerobox.AeroBoxApplication
import com.aerobox.data.repository.VpnRepository
import com.aerobox.service.AeroBoxVpnService
import com.aerobox.service.VpnStateManager
import com.aerobox.utils.PreferenceManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

class BootCompletedReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        if (intent?.action != Intent.ACTION_BOOT_COMPLETED) return

        val pendingResult = goAsync()
        CoroutineScope(Dispatchers.IO).launch {
            runCatching {
                val autoConnect = PreferenceManager.autoConnectFlow(context).first()
                if (!autoConnect) return@runCatching
                if (android.net.VpnService.prepare(context) != null) return@runCatching

                val nodeId = PreferenceManager.lastSelectedNodeIdFlow(context).first()
                if (nodeId <= 0L) return@runCatching

                val node = AeroBoxApplication.database.proxyNodeDao().getNodeById(nodeId) ?: return@runCatching

                val vpnRepository = VpnRepository(context)
                val config = vpnRepository.buildConfig(node)
                VpnStateManager.updateConnectionState(true, node)

                val startIntent = Intent(context, AeroBoxVpnService::class.java).apply {
                    action = AeroBoxVpnService.ACTION_START
                    putExtra(AeroBoxVpnService.EXTRA_CONFIG, config)
                }
                ContextCompat.startForegroundService(context, startIntent)
            }
            pendingResult.finish()
        }
    }
}

