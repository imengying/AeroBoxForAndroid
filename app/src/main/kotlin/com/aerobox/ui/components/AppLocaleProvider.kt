package com.aerobox.ui.components

import android.content.res.Configuration
import androidx.activity.compose.LocalActivityResultRegistryOwner
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.aerobox.utils.AppLocaleManager
import com.aerobox.utils.PreferenceManager
import com.aerobox.utils.findComponentActivity

private val LocalAppLanguageTag = staticCompositionLocalOf { AppLocaleManager.SYSTEM_LANGUAGE_TAG }

@Composable
fun ProvideAppLocale(content: @Composable () -> Unit) {
    val context = LocalContext.current
    val activityResultRegistryOwner =
        LocalActivityResultRegistryOwner.current ?: context.findComponentActivity()
    val parentLanguageTag = LocalAppLanguageTag.current
    val languageTag by PreferenceManager.languageTagFlow(context)
        .collectAsStateWithLifecycle(initialValue = parentLanguageTag)
    val localizedContext = remember(context, languageTag) {
        AppLocaleManager.localizedContext(context, languageTag)
    }
    val localizedConfiguration = remember(localizedContext, languageTag) {
        Configuration(localizedContext.resources.configuration)
    }

    if (activityResultRegistryOwner != null) {
        CompositionLocalProvider(
            LocalAppLanguageTag provides languageTag,
            LocalContext provides localizedContext,
            LocalConfiguration provides localizedConfiguration,
            LocalActivityResultRegistryOwner provides activityResultRegistryOwner
        ) {
            content()
        }
    } else {
        CompositionLocalProvider(
            LocalAppLanguageTag provides languageTag,
            LocalContext provides localizedContext,
            LocalConfiguration provides localizedConfiguration
        ) {
            content()
        }
    }
}
