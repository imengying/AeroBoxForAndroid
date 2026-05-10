package com.aerobox.service

import android.app.PendingIntent
import android.content.ComponentName
import android.content.Intent
import android.graphics.drawable.Icon
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import android.util.Log
import com.aerobox.AeroBoxApplication
import com.aerobox.R
import com.aerobox.core.connection.ConnectionDiagnostics
import com.aerobox.data.model.VpnState
import com.aerobox.data.repository.VpnConnectionResult
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.combine
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
            combine(
                VpnStateManager.serviceActive,
                VpnStateManager.vpnState
            ) { serviceActive, vpnState ->
                Pair(serviceActive, vpnState)
            }.collect { (serviceActive, vpnState) ->
                reconcilePendingAction(serviceActive, vpnState)
                updateTileFromState(serviceActive, vpnState)
            }
        }
        reconcilePendingAction(
            serviceActive = VpnStateManager.serviceActive.value,
            vpnState = VpnStateManager.vpnState.value
        )
        updateTileFromState(
            serviceActive = VpnStateManager.serviceActive.value,
            vpnState = VpnStateManager.vpnState.value
        )
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
        val serviceActive = VpnStateManager.serviceActive.value
        val vpnState = VpnStateManager.vpnState.value
        val shouldStop = serviceActive || vpnState.isConnected

        if (shouldStop) {
            toggleJob?.cancel()
            pendingAction = PendingAction.STOP
            updateTileFromState(serviceActive, vpnState)
            AeroBoxApplication.vpnRepository.stopVpn()
            return
        }

        val permissionIntent = VpnService.prepare(this)
        if (permissionIntent != null) {
            pendingAction = null
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

        pendingAction = PendingAction.START
        updateTileFromState(serviceActive = false, vpnState = vpnState)
        toggleJob?.cancel()
        toggleJob = serviceScope.launch(Dispatchers.IO) {
            val result = AeroBoxApplication.vpnRepository.connectSelectedNode()
            withContext(Dispatchers.Main.immediate) {
                when (result) {
                    VpnConnectionResult.NoNodeAvailable -> {
                        pendingAction = null
                        Log.w(TAG, "No node selected, cannot start VPN from tile")
                        requestTileRefresh(applicationContext)
                    }

                    is VpnConnectionResult.Success -> {
                        requestTileRefresh(applicationContext)
                    }

                    is VpnConnectionResult.InvalidConfig -> {
                        pendingAction = null
                        Log.e(
                            TAG,
                            ConnectionDiagnostics.logFailureMessage(
                                result,
                                "Config error"
                            )
                        )
                        requestTileRefresh(applicationContext)
                    }

                    is VpnConnectionResult.Failure -> {
                        pendingAction = null
                        Log.e(
                            TAG,
                            ConnectionDiagnostics.logFailureMessage(
                                result,
                                "Failed to start VPN from tile"
                            ),
                            result.throwable
                        )
                        requestTileRefresh(applicationContext)
                    }
                }
            }
        }
    }

    private fun reconcilePendingAction(serviceActive: Boolean, vpnState: VpnState) {
        pendingAction = when (pendingAction) {
            PendingAction.START -> when {
                vpnState.isConnected -> null
                serviceActive -> PendingAction.START
                toggleJob?.isActive == true -> PendingAction.START
                else -> null
            }
            PendingAction.STOP -> if (!serviceActive && !vpnState.isConnected) null else PendingAction.STOP
            null -> null
        }
    }

    private fun updateTileFromState(serviceActive: Boolean, vpnState: VpnState) {
        val visualState = when {
            pendingAction == PendingAction.STOP && (serviceActive || vpnState.isConnected) -> VisualState.STOPPING
            vpnState.isConnected -> VisualState.CONNECTED
            pendingAction == PendingAction.START || serviceActive -> VisualState.CONNECTING
            else -> VisualState.INACTIVE
        }
        updateTile(visualState = visualState, labelOverride = vpnState.currentNode?.name)
    }

    private fun updateTile(visualState: VisualState, labelOverride: String? = null) {
        val tile = qsTile ?: return
        tile.state = when (visualState) {
            VisualState.CONNECTED, VisualState.CONNECTING -> Tile.STATE_ACTIVE
            VisualState.STOPPING -> Tile.STATE_UNAVAILABLE
            VisualState.INACTIVE -> Tile.STATE_INACTIVE
        }
        tile.icon = Icon.createWithResource(this, R.drawable.ic_qs_aerobox)
        tile.label = when (visualState) {
            VisualState.CONNECTED -> {
                labelOverride
                    ?: VpnStateManager.vpnState.value.currentNode
                        ?.name
                        ?.takeIf { it.isNotBlank() }
                    ?: getString(R.string.tile_label)
            }
            else -> getString(R.string.tile_label)
        }
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
