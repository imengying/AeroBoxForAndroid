package com.aerobox.receiver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import com.aerobox.AeroBoxApplication
import com.aerobox.core.connection.ConnectionDiagnostics
import com.aerobox.data.repository.VpnConnectionResult
import com.aerobox.data.repository.VpnRepository
import com.aerobox.utils.PreferenceManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

class BootCompletedReceiver : BroadcastReceiver() {
    private companion object {
        const val TAG = "BootCompletedReceiver"
    }

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

                when (val result = VpnRepository(context).connectNode(node, refreshDueSubscriptions = true)) {
                    is VpnConnectionResult.Success -> Unit
                    VpnConnectionResult.NoNodeAvailable -> Unit
                    is VpnConnectionResult.InvalidConfig,
                    is VpnConnectionResult.Failure -> {
                        Log.w(
                            TAG,
                            ConnectionDiagnostics.logFailureMessage(
                                result,
                                "Auto-connect failed after boot"
                            )
                        )
                    }
                }
            }
            pendingResult.finish()
        }
    }
}
