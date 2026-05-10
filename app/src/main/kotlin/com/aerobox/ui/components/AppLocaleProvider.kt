package com.aerobox.ui.components

import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.aerobox.utils.AppLocaleManager
import com.aerobox.utils.PreferenceManager

@Composable
fun ProvideAppLocale(content: @Composable () -> Unit) {
    val context = LocalContext.current
    val languageTag by PreferenceManager.languageTagFlow(context)
        .collectAsStateWithLifecycle(initialValue = AppLocaleManager.SYSTEM_LANGUAGE_TAG)
    val localizedContext = remember(context, languageTag) {
        AppLocaleManager.localizedContext(context, languageTag)
    }

    CompositionLocalProvider(LocalContext provides localizedContext) {
        content()
    }
}
