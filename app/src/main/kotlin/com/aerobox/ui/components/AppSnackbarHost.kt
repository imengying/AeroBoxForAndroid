package com.aerobox.ui.components

import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Snackbar
import androidx.compose.material3.SnackbarDuration
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay

@Composable
fun AppSnackbarHost(
    hostState: SnackbarHostState,
    modifier: Modifier = Modifier
) {
    SnackbarHost(
        hostState = hostState,
        modifier = modifier.padding(16.dp)
    ) { data ->
        LaunchedEffect(data) {
            val timeoutMs = when (data.visuals.duration) {
                SnackbarDuration.Indefinite -> null
                else -> 1_600L
            }
            timeoutMs?.let {
                delay(it)
                data.dismiss()
            }
        }
        Snackbar(
            snackbarData = data,
            containerColor = MaterialTheme.colorScheme.primaryContainer,
            contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
            actionColor = MaterialTheme.colorScheme.primary
        )
    }
}
