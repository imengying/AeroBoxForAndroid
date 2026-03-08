package com.aerobox.service

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.graphics.drawable.Icon
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import android.util.Log
import com.aerobox.R
import com.aerobox.core.connection.ConnectionDiagnostics
import com.aerobox.data.repository.VpnConnectionResult
import com.aerobox.data.repository.VpnRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * Quick Settings tile to toggle VPN proxy on/off from the status bar.
 */
class AeroBoxTileService : TileService() {

    companion object {
        private const val TAG = "AeroBoxTileService"
        private const val ACTION_TILE_STATE_CHANGED = "com.aerobox.action.TILE_STATE_CHANGED"
        private const val EXTRA_TILE_ACTIVE = "extra_tile_active"
        private const val EXTRA_TILE_LABEL = "extra_tile_label"
        private val mainHandler = Handler(Looper.getMainLooper())

        @Volatile
        private var listeningService: AeroBoxTileService? = null

        @Volatile
        private var activeTileHint = false

        @Volatile
        private var activeTileLabelHint: String? = null

        fun showActive(label: String? = null) {
            publishState(active = true, label = label)
        }

        fun clearActiveHint() {
            publishState(active = false, label = null)
        }

        fun publishState(active: Boolean, label: String? = null) {
            activeTileHint = active
            activeTileLabelHint = label?.takeIf { it.isNotBlank() }
            dispatchTileState(activeTileHint, activeTileLabelHint)
            requestRefresh()
        }

        private fun dispatchTileState(active: Boolean, label: String?) {
            val context = runCatching { com.aerobox.AeroBoxApplication.appInstance }.getOrNull() ?: return
            val intent = Intent(ACTION_TILE_STATE_CHANGED)
                .setPackage(context.packageName)
                .putExtra(EXTRA_TILE_ACTIVE, active)
                .putExtra(EXTRA_TILE_LABEL, label)
            context.sendBroadcast(intent)
        }

        fun requestRefresh() {
            val activeService = listeningService ?: return
            mainHandler.post { activeService.updateTileState() }
        }
    }

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var tileStateReceiverRegistered = false
    private val tileStateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action != ACTION_TILE_STATE_CHANGED) return
            updateTile(
                active = intent.getBooleanExtra(EXTRA_TILE_ACTIVE, false),
                labelOverride = intent.getStringExtra(EXTRA_TILE_LABEL)
            )
        }
    }

    override fun onStartListening() {
        super.onStartListening()
        listeningService = this
        registerTileStateReceiver()
        updateTileState()
    }

    override fun onStopListening() {
        unregisterTileStateReceiver()
        listeningService = null
        super.onStopListening()
    }

    private fun registerTileStateReceiver() {
        if (tileStateReceiverRegistered) return
        val filter = IntentFilter(ACTION_TILE_STATE_CHANGED)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(tileStateReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("DEPRECATION")
            registerReceiver(tileStateReceiver, filter)
        }
        tileStateReceiverRegistered = true
    }

    private fun unregisterTileStateReceiver() {
        if (!tileStateReceiverRegistered) return
        runCatching { unregisterReceiver(tileStateReceiver) }
        tileStateReceiverRegistered = false
    }

    override fun onClick() {
        super.onClick()

        val isServiceActive = AeroBoxVpnService.isServiceActive.value

        if (isServiceActive) {
            // Stop VPN
            clearActiveHint()
            val intent = Intent(this, AeroBoxVpnService::class.java).apply {
                action = AeroBoxVpnService.ACTION_STOP
            }
            startService(intent)
            updateTile(false)
        } else {
            // Start VPN — need VPN permission first
            val permissionIntent = VpnService.prepare(this)
            if (permissionIntent != null) {
                // Cannot grant VPN permission from TileService directly;
                // need to start activity to handle permission
                val launchIntent = Intent(this, com.aerobox.MainActivity::class.java).apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    putExtra("action", "toggle_vpn")
                }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                    startActivityAndCollapse(
                        PendingIntent.getActivity(
                            this, 0, launchIntent,
                            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
                        )
                    )
                } else {
                    @Suppress("DEPRECATION")
                    startActivityAndCollapse(launchIntent)
                }
                return
            }
            startVpnFromTile()
        }
    }

    private fun startVpnFromTile() {
        serviceScope.launch {
            when (val result = VpnRepository(applicationContext).connectSelectedNode()) {
                VpnConnectionResult.NoNodeAvailable -> {
                    Log.w(TAG, "No node selected, cannot start VPN from tile")
                }

                is VpnConnectionResult.Success -> {
                    showActive(result.node.name)
                    updateTile(
                        active = true,
                        labelOverride = result.node.name.takeIf { it.isNotBlank() }
                    )
                }

                is VpnConnectionResult.InvalidConfig -> {
                    Log.e(
                        TAG,
                        ConnectionDiagnostics.logFailureMessage(result, "Config error")
                    )
                }

                is VpnConnectionResult.Failure -> {
                    Log.e(
                        TAG,
                        ConnectionDiagnostics.logFailureMessage(result, "Failed to start VPN from tile"),
                        result.throwable
                    )
                }
            }
        }
    }

    private fun updateTileState() {
        val active = AeroBoxVpnService.isServiceActive.value || activeTileHint
        updateTile(active = active, labelOverride = activeTileLabelHint)
    }

    private fun updateTile(active: Boolean, labelOverride: String? = null) {
        val tile = qsTile ?: return
        tile.state = if (active) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.icon = Icon.createWithResource(this, R.drawable.ic_qs_aerobox)
        tile.label = if (active) {
            labelOverride
                ?: VpnStateManager.vpnState.value.currentNode
                    ?.name
                    ?.takeIf { it.isNotBlank() }
                ?: getString(R.string.tile_label)
        } else {
            getString(R.string.tile_label)
        }
        tile.subtitle = if (active) {
            getString(R.string.tile_action_open)
        } else {
            getString(R.string.tile_action_close)
        }
        tile.updateTile()
    }

    override fun onDestroy() {
        unregisterTileStateReceiver()
        if (listeningService === this) {
            listeningService = null
        }
        serviceScope.cancel()
        super.onDestroy()
    }
}
