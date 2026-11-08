package com.aerobox.ui.screens

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Share
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import com.aerobox.viewmodel.AppViewModelFactory
import androidx.lifecycle.viewmodel.compose.viewModel
import com.aerobox.viewmodel.DataTransferViewModel
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.aerobox.R
import com.aerobox.ui.components.AppSnackbarHost
import com.aerobox.ui.icons.AppIcons
import com.aerobox.core.logging.CrashDiagnostics
import com.aerobox.core.logging.RuntimeLogBuffer
import com.aerobox.core.logging.RuntimeLogEntry
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LogScreen(
    onNavigateBack: () -> Unit,
    onNavigateToConnections: () -> Unit,
    viewModel: DataTransferViewModel = viewModel(factory = AppViewModelFactory)
) {
    val context = LocalContext.current
    val runtimeLines by RuntimeLogBuffer.lines.collectAsStateWithLifecycle()
    val crashLines by CrashDiagnostics.entries.collectAsStateWithLifecycle()
    val logLines = remember(runtimeLines, crashLines) {
        (crashLines + runtimeLines).sortedBy { it.timestamp }
    }
    val listState = rememberLazyListState()
    val snackbarHostState = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    val busy by viewModel.busy.collectAsStateWithLifecycle()
    val message by viewModel.message.collectAsStateWithLifecycle()
    val export = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/json")) { uri ->
        uri?.let(viewModel::exportDiagnostics)
    }
    LaunchedEffect(message) {
        message?.let { snackbarHostState.showSnackbar(it); viewModel.dismissMessage() }
    }

    // Auto-scroll to bottom only when user is already near the bottom
    LaunchedEffect(logLines.size) {
        if (logLines.isNotEmpty()) {
            val lastVisibleItem = listState.layoutInfo.visibleItemsInfo.lastOrNull()?.index ?: 0
            val isNearBottom = lastVisibleItem >= logLines.size - 3
            if (isNearBottom) {
                listState.animateScrollToItem(logLines.size - 1)
            }
        }
    }

    val largeText = LocalDensity.current.fontScale >= 1.5f
    val logActions: @Composable RowScope.() -> Unit = {
        IconButton(onClick = onNavigateToConnections) {
            Icon(AppIcons.Route, contentDescription = stringResource(R.string.connections_title))
        }
        IconButton(onClick = { export.launch("AeroBox-diagnostics.json") }, enabled = !busy) {
            Icon(Icons.Filled.Share, contentDescription = stringResource(R.string.export_diagnostics))
        }
        val logCopiedMessage = stringResource(R.string.log_copied)
        IconButton(
            onClick = {
                copyAllLogEntries(context, logLines)
                scope.launch {
                    snackbarHostState.showSnackbar(logCopiedMessage)
                }
            },
            enabled = logLines.isNotEmpty()
        ) {
            Icon(AppIcons.ContentCopy, contentDescription = stringResource(R.string.log_action_copy_all))
        }
        IconButton(onClick = {
            scope.launch {
                try {
                    CrashDiagnostics.clear()
                    RuntimeLogBuffer.clear()
                } catch (error: CancellationException) {
                    throw error
                } catch (error: Exception) {
                    RuntimeLogBuffer.appendError("Failed to clear crash summaries: ${error.message ?: error}")
                }
            }
        }) {
            Icon(Icons.Filled.Delete, contentDescription = stringResource(R.string.log_action_clear))
        }
    }

    Scaffold(
        snackbarHost = {
            AppSnackbarHost(hostState = snackbarHostState)
        },
        topBar = {
            Column {
                TopAppBar(
                    title = { Text(stringResource(R.string.log_screen_title)) },
                    navigationIcon = {
                        IconButton(onClick = onNavigateBack) {
                            Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = null)
                        }
                    },
                    actions = { if (!largeText) logActions() },
                    colors = TopAppBarDefaults.topAppBarColors(
                        containerColor = MaterialTheme.colorScheme.surface
                    )
                )
                if (largeText) {
                    Row(
                        modifier = Modifier.fillMaxWidth()
                            .windowInsetsPadding(TopAppBarDefaults.windowInsets.only(WindowInsetsSides.Horizontal)),
                        horizontalArrangement = Arrangement.End,
                        content = logActions
                    )
                }
            }
        }
    ) { innerPadding ->
        if (logLines.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    text = stringResource(R.string.log_empty),
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        } else {
            LazyColumn(
                state = listState,
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding),
                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp),
                verticalArrangement = Arrangement.spacedBy(2.dp)
            ) {
                items(logLines) { entry ->
                    LogEntryRow(entry = entry)
                }
            }
        }
    }
}

@Composable
private fun LogEntryRow(entry: RuntimeLogEntry) {
    val timeFormat = remember { SimpleDateFormat("HH:mm:ss", Locale.getDefault()) }
    val time = remember(entry.timestamp) { timeFormat.format(Date(entry.timestamp)) }

    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(8.dp),
        color = MaterialTheme.colorScheme.surfaceContainerLow
    ) {
        Text(
            text = "$time [error] ${entry.message}",
            style = MaterialTheme.typography.bodySmall.copy(
                fontFamily = FontFamily.Monospace,
                fontSize = 12.sp,
                lineHeight = 16.sp,
                textDirection = TextDirection.Ltr,
                textAlign = TextAlign.Left
            ),
            color = MaterialTheme.colorScheme.error,
            modifier = Modifier.padding(horizontal = 4.dp, vertical = 2.dp)
        )
    }
}

private fun copyAllLogEntries(context: Context, entries: List<RuntimeLogEntry>) {
    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    val timeFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.getDefault())
    // Keep the same order as the current UI: oldest at top, newest at bottom.
    val text = entries.joinToString(separator = "\n") { entry ->
        "${timeFormat.format(Date(entry.timestamp))} [error] ${entry.message}"
    }
    clipboard.setPrimaryClip(
        ClipData.newPlainText(
            "runtime-log",
            text
        )
    )
}
