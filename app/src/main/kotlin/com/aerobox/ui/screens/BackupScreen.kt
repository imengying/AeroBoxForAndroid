package com.aerobox.ui.screens

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.core.net.toUri
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.aerobox.R
import com.aerobox.service.VpnStateManager
import com.aerobox.ui.components.AppSnackbarHost
import com.aerobox.ui.icons.AppIcons
import com.aerobox.viewmodel.DataTransferViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BackupScreen(onNavigateBack: () -> Unit, viewModel: DataTransferViewModel = viewModel()) {
    val busy by viewModel.busy.collectAsStateWithLifecycle()
    val message by viewModel.message.collectAsStateWithLifecycle()
    val serviceActive by VpnStateManager.serviceActive.collectAsStateWithLifecycle()
    val snackbar = remember { SnackbarHostState() }
    var restoreUri by rememberSaveable { mutableStateOf<String?>(null) }
    val export = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/json")) { uri: Uri? ->
        uri?.let(viewModel::exportBackup)
    }
    val restore = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        restoreUri = uri?.toString()
    }
    LaunchedEffect(message) {
        message?.let { snackbar.showSnackbar(it); viewModel.dismissMessage() }
    }
    Scaffold(
        topBar = {
            TopAppBar(title = { Text(stringResource(R.string.backup_title)) }, navigationIcon = {
                IconButton(onClick = onNavigateBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, null) }
            })
        },
        snackbarHost = { AppSnackbarHost(snackbar) }
    ) { padding ->
        Column(Modifier.padding(padding).padding(16.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
            Text(stringResource(R.string.backup_credentials), style = MaterialTheme.typography.bodyMedium)
            Button(onClick = { export.launch("AeroBox-backup.json") }, enabled = !busy, modifier = Modifier.fillMaxWidth()) {
                Icon(AppIcons.ContentCopy, null, Modifier.padding(end = 8.dp))
                Text(stringResource(R.string.backup_export))
            }
            OutlinedButton(onClick = { restore.launch(arrayOf("application/json", "text/plain", "application/octet-stream")) },
                enabled = !busy && !serviceActive, modifier = Modifier.fillMaxWidth()) {
                Icon(AppIcons.Add, null, Modifier.padding(end = 8.dp))
                Text(stringResource(R.string.backup_restore))
            }
            if (serviceActive) Text(stringResource(R.string.backup_stop_vpn))
            if (busy) LinearProgressIndicator(Modifier.fillMaxWidth())
        }
    }
    restoreUri?.let { uri ->
        AlertDialog(
            onDismissRequest = { restoreUri = null },
            title = { Text(stringResource(R.string.backup_restore)) },
            text = { Text(stringResource(R.string.backup_merge_confirm)) },
            confirmButton = {
                TextButton(onClick = { restoreUri = null; viewModel.restoreBackup(uri.toUri()) }, enabled = !busy && !serviceActive) {
                    Text(stringResource(R.string.confirm))
                }
            },
            dismissButton = { TextButton(onClick = { restoreUri = null }) { Text(stringResource(R.string.cancel)) } }
        )
    }
}
