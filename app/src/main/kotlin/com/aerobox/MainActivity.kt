package com.aerobox

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.enableEdgeToEdge
import androidx.activity.compose.setContent
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.runtime.getValue
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.aerobox.imports.ExternalImportParser
import com.aerobox.imports.ExternalImportRequest
import com.aerobox.ui.components.ProvideAppLocale
import com.aerobox.ui.navigation.AppNavigation
import com.aerobox.ui.theme.SingBoxVPNTheme
import com.aerobox.utils.PreferenceManager
import kotlinx.coroutines.flow.MutableStateFlow

class MainActivity : ComponentActivity() {
    private val pendingExternalImport = MutableStateFlow<ExternalImportRequest?>(null)
    private var externalImportHandled = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        externalImportHandled = savedInstanceState?.getBoolean(EXTERNAL_IMPORT_HANDLED) ?: false
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
                val importRequest by pendingExternalImport.collectAsStateWithLifecycle()
                ProvideAppLocale {
                    AppNavigation(
                        pendingExternalImport = importRequest,
                        onExternalImportHandled = { requestId ->
                            val current = pendingExternalImport.value
                            if (current?.id == requestId) {
                                externalImportHandled = true
                                pendingExternalImport.value = null
                            }
                        }
                    )
                }
            }
        }

        // The launch Intent survives recreation. Replaying a handled link would
        // navigate away from the restored screen and reopen the import dialog.
        if (!externalImportHandled) consumeActionIntent(intent)
    }

    override fun onSaveInstanceState(outState: Bundle) {
        outState.putBoolean(EXTERNAL_IMPORT_HANDLED, externalImportHandled)
        super.onSaveInstanceState(outState)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        externalImportHandled = false
        consumeActionIntent(intent)
    }

    private fun consumeActionIntent(intent: Intent?) {
        ExternalImportParser.fromIntent(intent)?.let { request ->
            pendingExternalImport.value = request
        }
    }

    private companion object {
        const val EXTERNAL_IMPORT_HANDLED = "external_import_handled"
    }
}
