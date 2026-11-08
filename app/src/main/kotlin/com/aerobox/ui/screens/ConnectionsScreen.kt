package com.aerobox.ui.screens

import android.os.PowerManager
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.repeatOnLifecycle
import com.aerobox.R
import com.aerobox.service.AeroBoxVpnService
import com.aerobox.utils.NetworkUtils
import com.aerobox.ui.components.AppSnackbarHost
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ConnectionsScreen(onNavigateBack: () -> Unit) {
    val context = LocalContext.current
    val operationFailed by rememberUpdatedState(stringResource(R.string.operation_failed))
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    var connections by remember { mutableStateOf(emptyList<JSONObject>()) }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }
    LaunchedEffect(lifecycle) {
        lifecycle.repeatOnLifecycle(Lifecycle.State.RESUMED) {
            try {
                val power = context.getSystemService(PowerManager::class.java)
                while (isActive) {
                    if (power.isInteractive) {
                        try {
                            connections = withContext(Dispatchers.IO) {
                                val rows = JSONArray(AeroBoxVpnService.connectionSnapshot())
                                (0 until rows.length()).map { rows.getJSONObject(it) }
                            }
                            error = null
                        } catch (e: CancellationException) {
                            throw e
                        } catch (e: Exception) {
                            error = e.message ?: operationFailed
                        }
                    } else {
                        AeroBoxVpnService.stopConnectionTracking()
                    }
                    delay(1_000)
                }
            } finally {
                withContext(NonCancellable) { AeroBoxVpnService.stopConnectionTracking() }
                connections = emptyList()
            }
        }
    }
    Scaffold(
        topBar = {
            TopAppBar(title = { Text(stringResource(R.string.connections_title)) }, navigationIcon = {
                IconButton(onClick = onNavigateBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, null) }
            })
        },
        snackbarHost = { AppSnackbarHost(snackbar) }
    ) { padding ->
        LazyColumn(Modifier.fillMaxSize().padding(padding), contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)) {
            if (error != null) item { Text(error.orEmpty(), color = MaterialTheme.colorScheme.error) }
            if (connections.isEmpty()) item { Text(stringResource(R.string.connections_empty)) }
            items(connections, key = { it.getString("id") }) { row ->
                Column(Modifier.fillMaxWidth()) {
                    Row(Modifier.fillMaxWidth()) {
                        Text(row.optString("domain").ifBlank { row.getString("destination") },
                            Modifier.weight(1f), style = MaterialTheme.typography.titleSmall)
                        IconButton(onClick = {
                            scope.launch {
                                try {
                                    AeroBoxVpnService.closeTrackedConnection(row.getString("id"))
                                } catch (e: CancellationException) {
                                    throw e
                                } catch (e: Exception) {
                                    snackbar.showSnackbar(e.message ?: operationFailed)
                                }
                            }
                        }) { Icon(Icons.Filled.Close, stringResource(R.string.close_connection)) }
                    }
                    Text("${row.getString("network")}  ${row.getString("source")} → ${row.getString("destination")}",
                        style = MaterialTheme.typography.bodySmall)
                    Text(listOf(row.optString("process"), row.optString("outbound"), row.optString("rule"))
                        .filter { it.isNotBlank() }.joinToString(" · "), style = MaterialTheme.typography.bodySmall)
                    Text("↑ ${NetworkUtils.formatBytes(row.getLong("upload"))}  ↓ ${NetworkUtils.formatBytes(row.getLong("download"))}",
                        style = MaterialTheme.typography.bodySmall)
                    HorizontalDivider(Modifier.padding(top = 12.dp))
                }
            }
        }
    }
}
