package com.aerobox.ui.theme

import android.app.Activity
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat

private val DarkColorScheme = darkColorScheme(
    primary = FallbackDarkPrimary,
    onPrimary = FallbackDarkOnPrimary,
    secondary = FallbackDarkSecondary,
    onSecondary = FallbackDarkOnSecondary,
    error = FallbackDarkError,
    onError = FallbackDarkOnError,
    background = FallbackDarkBackground,
    onBackground = FallbackDarkOnBackground,
    surface = FallbackDarkSurface,
    onSurface = FallbackDarkOnSurface,
    onSurfaceVariant = FallbackDarkOnSurfaceVariant,
    outline = FallbackDarkOutline,
    secondaryContainer = FallbackDarkSecondaryContainer,
    tertiaryContainer = FallbackDarkTertiaryContainer,
    surfaceContainerLow = FallbackDarkSurfaceContainerLow
)

private val LightColorScheme = lightColorScheme(
    primary = FallbackLightPrimary,
    onPrimary = FallbackLightOnPrimary,
    secondary = FallbackLightSecondary,
    onSecondary = FallbackLightOnSecondary,
    error = FallbackLightError,
    onError = FallbackLightOnError,
    background = FallbackLightBackground,
    onBackground = FallbackLightOnBackground,
    surface = FallbackLightSurface,
    onSurface = FallbackLightOnSurface,
    onSurfaceVariant = FallbackLightOnSurfaceVariant,
    outline = FallbackLightOutline,
    secondaryContainer = FallbackLightSecondaryContainer,
    tertiaryContainer = FallbackLightTertiaryContainer,
    surfaceContainerLow = FallbackLightSurfaceContainerLow
)

@Composable
fun SingBoxVPNTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    dynamicColor: Boolean = true,
    content: @Composable () -> Unit
) {
    val context = LocalContext.current
    val colorScheme = when {
        dynamicColor -> {
            if (darkTheme) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        }

        darkTheme -> DarkColorScheme
        else -> LightColorScheme
    }

    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as? Activity)?.window ?: return@SideEffect
            val insetsController = WindowCompat.getInsetsController(window, view)
            insetsController.isAppearanceLightStatusBars = !darkTheme
            insetsController.isAppearanceLightNavigationBars = !darkTheme
        }
    }

    MaterialTheme(
        colorScheme = colorScheme,
        typography = AppTypography,
        content = content
    )
}
