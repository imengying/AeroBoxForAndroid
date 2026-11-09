package com.aerobox.service

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.ComponentName
import android.content.Intent
import android.graphics.drawable.Icon
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import android.util.Log
import com.aerobox.appContainer
import com.aerobox.R
import com.aerobox.core.connection.ConnectionDiagnostics
import com.aerobox.data.model.VpnState
import com.aerobox.data.repository.VpnConnectionResult
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Quick Settings tile to toggle VPN proxy on/off from the status bar.
 */
class AeroBoxTileService : TileService() {

    companion object {
        private const val TAG = "AeroBoxTileService"

        fun requestTileRefresh(context: android.content.Context) {
            runCatching {
                requestListeningState(context, ComponentName(context, AeroBoxTileService::class.java))
            }
        }
    }

    private enum class PendingAction {
        START,
        STOP
    }

    private enum class VisualState {
        INACTIVE,
        CONNECTING,
        CONNECTED,
        STOPPING
    }

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private var tileStateJob: Job? = null
    private var toggleJob: Job? = null
    private var pendingAction: PendingAction? = null

    override fun onStartListening() {
        super.onStartListening()
        tileStateJob?.cancel()
        tileStateJob = serviceScope.launch {
            VpnStateManager.vpnState.collect { state ->
                reconcilePendingAction(state)
                updateTileFromState(state)
            }
        }
    }

    override fun onStopListening() {
        tileStateJob?.cancel()
        tileStateJob = null
        super.onStopListening()
    }

    override fun onClick() {
        super.onClick()
        if (isLocked) {
            unlockAndRun(::handleToggle)
        } else {
            handleToggle()
        }
    }

    private fun handleToggle() {
        val vpnState = VpnStateManager.vpnState.value
        val shouldStop = vpnState.serviceActive || vpnState.isConnected

        if (shouldStop) {
            toggleJob?.cancel()
            pendingAction = PendingAction.STOP
            updateTileFromState(vpnState)
            appContainer.vpnRepository.stopVpn()
            return
        }

        val permissionIntent = VpnService.prepare(this)
        if (permissionIntent != null) {
            pendingAction = null
            val launchIntent = Intent(this, com.aerobox.VpnPermissionActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            startPermissionActivity(launchIntent)
            return
        }

        pendingAction = PendingAction.START
        updateTileFromState(vpnState)
        toggleJob?.cancel()
        toggleJob = serviceScope.launch(Dispatchers.IO) {
            val result = appContainer.vpnRepository.connectSelectedNode()
            withContext(Dispatchers.Main.immediate) {
                when (result) {
                    VpnConnectionResult.NoNodeAvailable -> {
                        pendingAction = null
                        Log.w(TAG, "No node selected, cannot start VPN from tile")
                    }

                    is VpnConnectionResult.Success -> Unit

                    is VpnConnectionResult.InvalidConfig -> {
                        pendingAction = null
                        Log.e(
                            TAG,
                            ConnectionDiagnostics.failureMessage(
                                result,
                                "Config error"
                            )
                        )
                    }

                    is VpnConnectionResult.Failure -> {
                        pendingAction = null
                        Log.e(
                            TAG,
                            ConnectionDiagnostics.failureMessage(
                                result,
                                "Failed to start VPN from tile"
                            ),
                            result.throwable
                        )
                    }
                }
                requestTileRefresh(applicationContext)
            }
        }
    }

    @SuppressLint("StartActivityAndCollapseDeprecated")
    @Suppress("DEPRECATION")
    private fun startPermissionActivity(launchIntent: Intent) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startActivityAndCollapse(
                PendingIntent.getActivity(
                    this,
                    0,
                    launchIntent,
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
                )
            )
        } else {
            // Android 12 and 13 do not provide the PendingIntent overload.
            startActivityAndCollapse(launchIntent)
        }
    }

    private fun reconcilePendingAction(vpnState: VpnState) {
        pendingAction = when (pendingAction) {
            PendingAction.START -> when {
                vpnState.isConnected -> null
                vpnState.serviceActive -> PendingAction.START
                toggleJob?.isActive == true -> PendingAction.START
                else -> null
            }
            PendingAction.STOP -> if (!vpnState.serviceActive && !vpnState.isConnected) null else PendingAction.STOP
            null -> null
        }
    }

    private fun updateTileFromState(vpnState: VpnState) {
        val visualState = when {
            vpnState.phase == com.aerobox.data.model.VpnPhase.STOPPING -> VisualState.STOPPING
            pendingAction == PendingAction.STOP && (vpnState.serviceActive || vpnState.isConnected) -> VisualState.STOPPING
            vpnState.isConnected -> VisualState.CONNECTED
            pendingAction == PendingAction.START || vpnState.serviceActive -> VisualState.CONNECTING
            else -> VisualState.INACTIVE
        }
        updateTile(visualState = visualState)
    }

    private fun updateTile(visualState: VisualState) {
        val tile = qsTile ?: return
        tile.state = when (visualState) {
            VisualState.CONNECTED, VisualState.CONNECTING -> Tile.STATE_ACTIVE
            VisualState.STOPPING -> Tile.STATE_UNAVAILABLE
            VisualState.INACTIVE -> Tile.STATE_INACTIVE
        }
        tile.icon = Icon.createWithResource(this, R.drawable.ic_qs_aerobox)
        tile.label = getString(R.string.tile_label)
        tile.subtitle = when (visualState) {
            VisualState.CONNECTED -> getString(R.string.connected)
            VisualState.CONNECTING -> getString(R.string.connecting)
            VisualState.STOPPING -> getString(R.string.tile_status_stopping)
            VisualState.INACTIVE -> getString(R.string.disconnected)
        }
        tile.updateTile()
    }

    override fun onDestroy() {
        tileStateJob?.cancel()
        tileStateJob = null
        toggleJob?.cancel()
        toggleJob = null
        serviceScope.cancel()
        super.onDestroy()
    }
}
