package com.aerobox

import android.Manifest
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import androidx.lifecycle.lifecycleScope
import com.aerobox.core.connection.ConnectionDiagnostics
import com.aerobox.data.repository.VpnConnectionResult
import com.aerobox.service.AeroBoxTileService
import com.aerobox.utils.AppLocaleManager
import com.aerobox.utils.PreferenceManager
import com.aerobox.utils.needsNotificationPermission
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

/** Handles the Quick Settings tile permission flow without exposing a command on MainActivity. */
class VpnPermissionActivity : ComponentActivity() {
    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            ensureNotificationPermissionThenConnect()
        } else {
            showMessage(R.string.permission_required)
            finishAction()
        }
    }

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (!granted) {
            showMessage(R.string.notification_permission_hint)
        }
        connectSelectedNode()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (savedInstanceState != null) return

        val permissionIntent = VpnService.prepare(this)
        if (permissionIntent != null) {
            vpnPermissionLauncher.launch(permissionIntent)
        } else {
            ensureNotificationPermissionThenConnect()
        }
    }

    private fun ensureNotificationPermissionThenConnect() {
        if (needsNotificationPermission()) {
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else {
            connectSelectedNode()
        }
    }

    private fun connectSelectedNode() {
        lifecycleScope.launch {
            when (val result = AeroBoxApplication.vpnRepository.connectSelectedNode()) {
                is VpnConnectionResult.Success -> Unit
                VpnConnectionResult.NoNodeAvailable -> {
                    showMessage(R.string.add_node_first)
                    startActivity(Intent(this@VpnPermissionActivity, MainActivity::class.java))
                }
                is VpnConnectionResult.InvalidConfig,
                is VpnConnectionResult.Failure -> {
                    val message = ConnectionDiagnostics.userFacingFailureMessage(
                        result = result,
                        operationFailedText = appString(R.string.operation_failed)
                    )
                    Toast.makeText(this@VpnPermissionActivity, message, Toast.LENGTH_LONG).show()
                }
            }
            finishAction()
        }
    }

    private fun showMessage(resId: Int) {
        Toast.makeText(this, getString(resId), Toast.LENGTH_LONG).show()
    }

    private suspend fun appString(resId: Int, vararg formatArgs: Any): String {
        val languageTag = PreferenceManager.languageTagFlow(applicationContext).first()
        return AppLocaleManager.string(this, languageTag, resId, *formatArgs)
    }

    private fun finishAction() {
        AeroBoxTileService.requestTileRefresh(applicationContext)
        finish()
    }
}
