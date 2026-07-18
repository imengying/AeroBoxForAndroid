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
                val importRequest by pendingExternalImport.collectAsStateWithLifecycle()
                ProvideAppLocale {
                    AppNavigation(
                        pendingExternalImport = importRequest,
                        onExternalImportHandled = { requestId ->
                            val current = pendingExternalImport.value
                            if (current?.id == requestId) {
                                pendingExternalImport.value = null
                            }
                        }
                    )
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
        }
    }
}
