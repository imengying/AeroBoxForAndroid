package com.aerobox

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Bundle
import android.os.Build
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.compose.setContent
import androidx.core.content.ContextCompat
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.runtime.getValue
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.aerobox.core.connection.ConnectionDiagnostics
import com.aerobox.data.repository.VpnConnectionResult
import com.aerobox.data.repository.VpnRepository
import com.aerobox.service.AeroBoxVpnService
import com.aerobox.ui.navigation.AppNavigation
import com.aerobox.ui.theme.SingBoxVPNTheme
import com.aerobox.utils.PreferenceManager
import com.aerobox.core.AppEventBus
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    private companion object {
        const val EXTRA_ACTION = "action"
        const val ACTION_TOGGLE_VPN = "toggle_vpn"
    }

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            ensureNotificationPermissionThenStartVpn()
        } else {
            Toast.makeText(this, R.string.permission_required, Toast.LENGTH_SHORT).show()
        }
    }
    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (!granted) {
            Toast.makeText(this, R.string.notification_permission_hint, Toast.LENGTH_SHORT).show()
        }
        startVpnFromIntent()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        setContent {
            val context = LocalContext.current
            val darkMode by PreferenceManager.darkModeFlow(context)
                .collectAsStateWithLifecycle(initialValue = "system")
            val dynamicColor by PreferenceManager.dynamicColorFlow(context)
                .collectAsStateWithLifecycle(initialValue = true)

            val useDarkTheme = when (darkMode) {
                "on" -> true
                "off" -> false
                else -> isSystemInDarkTheme()
            }

            SingBoxVPNTheme(
                darkTheme = useDarkTheme,
                dynamicColor = dynamicColor
            ) {
                AppNavigation()
            }
        }

        consumeActionIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        consumeActionIntent(intent)
    }

    private fun consumeActionIntent(intent: Intent?) {
        if (intent?.action == AeroBoxVpnService.ACTION_SWITCH) {
            intent.action = null
            AppEventBus.showNodeSelector.tryEmit(Unit)
            return
        }
        val action = intent?.getStringExtra(EXTRA_ACTION) ?: return
        if (action == ACTION_TOGGLE_VPN) {
            intent.removeExtra(EXTRA_ACTION)
            toggleVpnFromIntent()
        }
    }

    private fun toggleVpnFromIntent() {
        if (AeroBoxVpnService.isServiceActive.value) {
            startService(
                Intent(this, AeroBoxVpnService::class.java).apply {
                    this.action = AeroBoxVpnService.ACTION_STOP
                }
            )
            return
        }

        val permissionIntent = VpnService.prepare(this)
        if (permissionIntent != null) {
            vpnPermissionLauncher.launch(permissionIntent)
        } else {
            ensureNotificationPermissionThenStartVpn()
        }
    }

    private fun ensureNotificationPermissionThenStartVpn() {
        val needsPermission = Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(
                this,
                Manifest.permission.POST_NOTIFICATIONS
            ) != PackageManager.PERMISSION_GRANTED

        if (needsPermission) {
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else {
            startVpnFromIntent()
        }
    }

    private fun startVpnFromIntent() {
        lifecycleScope.launch {
            when (val result = VpnRepository(applicationContext).connectSelectedNode()) {
                VpnConnectionResult.NoNodeAvailable -> {
                    Toast.makeText(
                        this@MainActivity,
                        R.string.add_node_first,
                        Toast.LENGTH_SHORT
                    ).show()
                }

                is VpnConnectionResult.Success -> Unit
                is VpnConnectionResult.InvalidConfig,
                is VpnConnectionResult.Failure -> {
                    Toast.makeText(
                        this@MainActivity,
                        ConnectionDiagnostics.userFacingFailureMessage(
                            result = result,
                            operationFailedText = getString(R.string.operation_failed)
                        ),
                        Toast.LENGTH_SHORT
                    ).show()
                }
            }
        }
    }
}
