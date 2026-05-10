package com.aerobox

import android.Manifest
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.aerobox.core.connection.ConnectionDiagnostics
import com.aerobox.data.repository.VpnConnectionResult
import com.aerobox.imports.ExternalImportParser
import com.aerobox.imports.ExternalImportRequest
import com.aerobox.service.AeroBoxVpnService
import com.aerobox.ui.components.AppSnackbarHost
import com.aerobox.ui.navigation.AppNavigation
import com.aerobox.ui.theme.SingBoxVPNTheme
import com.aerobox.utils.AppLocaleManager
import com.aerobox.utils.needsNotificationPermission
import com.aerobox.utils.PreferenceManager
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    private companion object {
        const val EXTRA_ACTION = "action"
        const val ACTION_TOGGLE_VPN = "toggle_vpn"
    }

    private val uiMessage = MutableSharedFlow<String>(extraBufferCapacity = 1)
    private val pendingExternalImport = MutableStateFlow<ExternalImportRequest?>(null)

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            ensureNotificationPermissionThenStartVpn()
        } else {
            uiMessage.tryEmit(getString(R.string.permission_required))
        }
    }
    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (!granted) {
            uiMessage.tryEmit(getString(R.string.notification_permission_hint))
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
            val languageTag by PreferenceManager.languageTagFlow(context)
                .collectAsStateWithLifecycle(initialValue = "")
            val localizedContext = remember(context, languageTag) {
                AppLocaleManager.localizedContext(context, languageTag)
            }

            val useDarkTheme = when (darkMode) {
                "on" -> true
                "off" -> false
                else -> isSystemInDarkTheme()
            }

            CompositionLocalProvider(LocalContext provides localizedContext) {
                SingBoxVPNTheme(
                    darkTheme = useDarkTheme,
                    dynamicColor = dynamicColor
                ) {
                    val snackbarHostState = remember { SnackbarHostState() }
                    val importRequest by pendingExternalImport.collectAsStateWithLifecycle()
                    LaunchedEffect(Unit) {
                        uiMessage.collectLatest { message ->
                            snackbarHostState.showSnackbar(message)
                        }
                    }
                    Box(modifier = Modifier.fillMaxSize()) {
                        AppNavigation(
                            pendingExternalImport = importRequest,
                            onExternalImportHandled = { requestId ->
                                val current = pendingExternalImport.value
                                if (current?.id == requestId) {
                                    pendingExternalImport.value = null
                                }
                            }
                        )
                        AppSnackbarHost(
                            hostState = snackbarHostState,
                            modifier = Modifier.align(Alignment.BottomCenter)
                        )
                    }
                }
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
        ExternalImportParser.fromIntent(intent)?.let { request ->
            pendingExternalImport.value = request
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
        if (needsNotificationPermission()) {
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else {
            startVpnFromIntent()
        }
    }

    private fun startVpnFromIntent() {
        lifecycleScope.launch {
            when (val result = AeroBoxApplication.vpnRepository.connectSelectedNode()) {
                VpnConnectionResult.NoNodeAvailable -> {
                    uiMessage.tryEmit(getString(R.string.add_node_first))
                }

                is VpnConnectionResult.Success -> Unit
                is VpnConnectionResult.InvalidConfig,
                is VpnConnectionResult.Failure -> {
                    uiMessage.tryEmit(
                        ConnectionDiagnostics.userFacingFailureMessage(
                            result = result,
                            operationFailedText = getString(R.string.operation_failed),
                            resolveTitle = ::getString
                        )
                    )
                }
            }
        }
    }
}
