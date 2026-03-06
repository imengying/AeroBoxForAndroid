package com.aerobox

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.compose.setContent
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.aerobox.data.repository.VpnRepository
import com.aerobox.service.AeroBoxVpnService
import com.aerobox.ui.navigation.AppNavigation
import com.aerobox.ui.theme.SingBoxVPNTheme
import com.aerobox.utils.PreferenceManager
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    private companion object {
        const val EXTRA_ACTION = "action"
        const val ACTION_TOGGLE_VPN = "toggle_vpn"
        const val ACTION_QS_TILE_PREFERENCES = "android.service.quicksettings.action.QS_TILE_PREFERENCES"
        const val MAIN_PAGE_HOME = 0
        const val MAIN_PAGE_SETTINGS = 1
    }

    private var initialMainPage = mutableIntStateOf(MAIN_PAGE_HOME)
    private var openMainRouteToken = mutableIntStateOf(0)

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            startVpnFromIntent()
        } else {
            Toast.makeText(this, R.string.permission_required, Toast.LENGTH_SHORT).show()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        applyEntryIntent(intent)

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
                AppNavigation(
                    initialMainPage = initialMainPage.intValue,
                    openMainRouteToken = openMainRouteToken.intValue
                )
            }
        }

        consumeActionIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        applyEntryIntent(intent)
        consumeActionIntent(intent)
    }

    private fun applyEntryIntent(intent: Intent?) {
        if (intent?.action == ACTION_QS_TILE_PREFERENCES) {
            initialMainPage.intValue = MAIN_PAGE_SETTINGS
            openMainRouteToken.intValue += 1
        } else {
            initialMainPage.intValue = MAIN_PAGE_HOME
        }
    }

    private fun consumeActionIntent(intent: Intent?) {
        val action = intent?.getStringExtra(EXTRA_ACTION) ?: return
        if (action == ACTION_TOGGLE_VPN) {
            intent.removeExtra(EXTRA_ACTION)
            toggleVpnFromIntent()
        }
    }

    private fun toggleVpnFromIntent() {
        if (AeroBoxVpnService.isRunning.value) {
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
            startVpnFromIntent()
        }
    }

    private fun startVpnFromIntent() {
        lifecycleScope.launch {
            runCatching {
                val nodeId = PreferenceManager.lastSelectedNodeIdFlow(applicationContext).first()
                val allNodes = AeroBoxApplication.database.proxyNodeDao().getAllNodes().first()
                val node = allNodes.firstOrNull { it.id == nodeId } ?: allNodes.firstOrNull()

                if (node == null) {
                    Toast.makeText(
                        this@MainActivity,
                        R.string.add_node_first,
                        Toast.LENGTH_SHORT
                    ).show()
                    return@launch
                }

                val vpnRepository = VpnRepository(applicationContext)
                val config = vpnRepository.buildConfig(node)
                val configError = vpnRepository.checkConfig(config)
                if (configError != null) {
                    Toast.makeText(
                        this@MainActivity,
                        getString(R.string.operation_failed),
                        Toast.LENGTH_SHORT
                    ).show()
                    return@launch
                }

                vpnRepository.startVpn(config, node.id)
            }.onFailure {
                Toast.makeText(
                    this@MainActivity,
                    getString(R.string.operation_failed),
                    Toast.LENGTH_SHORT
                ).show()
            }
        }
    }
}
