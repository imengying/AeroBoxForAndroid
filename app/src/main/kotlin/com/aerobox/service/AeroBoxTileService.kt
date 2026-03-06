package com.aerobox.service

import android.content.Intent
import android.graphics.drawable.Icon
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import android.util.Log
import com.aerobox.AeroBoxApplication
import com.aerobox.R
import com.aerobox.data.repository.VpnRepository
import com.aerobox.utils.PreferenceManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

/**
 * Quick Settings tile to toggle VPN proxy on/off from the status bar.
 */
class AeroBoxTileService : TileService() {

    companion object {
        private const val TAG = "AeroBoxTileService"
    }

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override fun onStartListening() {
        super.onStartListening()
        updateTileState()
    }

    override fun onClick() {
        super.onClick()

        val isRunning = AeroBoxVpnService.isRunning.value

        if (isRunning) {
            // Stop VPN
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
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                    startActivityAndCollapse(
                        Intent(this, com.aerobox.MainActivity::class.java).apply {
                            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                            putExtra("action", "toggle_vpn")
                        }
                    )
                } else {
                    @Suppress("DEPRECATION")
                    startActivityAndCollapse(
                        Intent(this, com.aerobox.MainActivity::class.java).apply {
                            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                            putExtra("action", "toggle_vpn")
                        }
                    )
                }
                return
            }
            startVpnFromTile()
        }
    }

    private fun startVpnFromTile() {
        serviceScope.launch {
            runCatching {
                val db = AeroBoxApplication.database
                val nodeId = PreferenceManager.lastSelectedNodeIdFlow(applicationContext).first()
                val allNodes = db.proxyNodeDao().getAllNodes().first()
                val node = allNodes.firstOrNull { it.id == nodeId } ?: allNodes.firstOrNull()

                if (node == null) {
                    Log.w(TAG, "No node selected, cannot start VPN from tile")
                    return@launch
                }

                val vpnRepository = VpnRepository(applicationContext)
                val config = vpnRepository.buildConfig(node)

                val configError = vpnRepository.checkConfig(config)
                if (configError != null) {
                    Log.e(TAG, "Config error: $configError")
                    return@launch
                }

                vpnRepository.startVpn(config, node.id)
                updateTileState()
            }.onFailure { e ->
                Log.e(TAG, "Failed to start VPN from tile", e)
                VpnStateManager.updateConnectionState(false, null)
            }
        }
    }

    private fun updateTileState() {
        updateTile(AeroBoxVpnService.isRunning.value)
    }

    private fun updateTile(active: Boolean) {
        val tile = qsTile ?: return
        tile.state = if (active) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.icon = Icon.createWithResource(this, R.drawable.ic_qs_aerobox)
        tile.label = if (active) {
            VpnStateManager.vpnState.value.currentNode
                ?.name
                ?.takeIf { it.isNotBlank() }
                ?: getString(R.string.tile_label)
        } else {
            getString(R.string.tile_label)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            tile.subtitle = if (active) {
                getString(R.string.tile_action_open)
            } else {
                getString(R.string.tile_action_close)
            }
        }
        tile.updateTile()
    }

    override fun onDestroy() {
        serviceScope.cancel()
        super.onDestroy()
    }
}
