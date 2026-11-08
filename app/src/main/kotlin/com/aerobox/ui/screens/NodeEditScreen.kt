package com.aerobox.ui.screens

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Check
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuAnchorType
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.LocalTextStyle
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.aerobox.R
import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.ProxyType
import com.aerobox.service.VpnStateManager
import com.aerobox.ui.components.AppSnackbarHost
import com.aerobox.viewmodel.AppViewModelFactory
import com.aerobox.viewmodel.NodeEditViewModel
import com.aerobox.viewmodel.nodeeditor.EditorInput
import com.aerobox.viewmodel.nodeeditor.EditorSection
import com.aerobox.viewmodel.nodeeditor.NodeEditField
import com.aerobox.viewmodel.nodeeditor.NodeEditFields

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NodeEditScreen(
    nodeId: Long,
    onNavigateBack: () -> Unit,
    viewModel: NodeEditViewModel = viewModel(factory = AppViewModelFactory)
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val vpn by VpnStateManager.vpnState.collectAsStateWithLifecycle()
    val draft = state.draft
    val node = remember(draft) { draft?.node() }
    val errors = remember(draft) { draft?.errors().orEmpty() }
    val largeText = LocalDensity.current.fontScale >= 1.5f
    var advanced by rememberSaveable(nodeId) { mutableStateOf(false) }
    // Both actions discard edits, but only after explicit confirmation.
    var confirmDiscard by rememberSaveable(nodeId) { mutableStateOf<String?>(null) }
    val snackbar = remember { SnackbarHostState() }
    val message = state.message?.let { stringResource(it) }
    LaunchedEffect(message, state.details) {
        if (message != null) {
            snackbar.showSnackbar(listOfNotNull(message, state.details?.takeIf(String::isNotBlank)).joinToString(": "))
            viewModel.dismissMessage()
        }
    }
    LaunchedEffect(state.completed) { if (state.completed) onNavigateBack() }
    val goBack: () -> Unit = {
        if (!state.saving) {
            if (draft?.changed == true) confirmDiscard = "close" else viewModel.discardAndClose()
        }
    }
    BackHandler(onBack = goBack)

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.edit_node)) },
                navigationIcon = {
                    IconButton(onClick = goBack, enabled = !state.saving) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.node_edit_back))
                    }
                },
                actions = {
                    val canSave = draft?.changed == true && errors.isEmpty() &&
                        !state.loading && !state.saving && !state.conflict && !state.missing
                    if (largeText) {
                        IconButton(onClick = viewModel::save, enabled = canSave) {
                            Icon(Icons.Filled.Check, contentDescription = stringResource(R.string.save))
                        }
                    } else {
                        TextButton(onClick = viewModel::save, enabled = canSave) {
                            Text(stringResource(R.string.save))
                        }
                    }
                }
            )
        },
        snackbarHost = { AppSnackbarHost(hostState = snackbar) }
    ) { padding ->
        if (state.loading) {
            Box(Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.Center) {
                CircularProgressIndicator()
            }
        } else if (node == null || draft == null) {
            Column(Modifier.padding(padding).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(stringResource(if (state.missing) R.string.node_edit_missing else R.string.operation_failed))
                TextButton(onClick = { viewModel.reload(discard = false) }, enabled = !state.saving) {
                    Text(stringResource(R.string.node_edit_reload))
                }
            }
        } else {
            val visible = remember(node, advanced, errors) {
                NodeEditFields.all.filter { it.visible(node) && (!it.advanced || advanced || it.key in errors) }
                    .groupBy { it.section }
            }
            LazyColumn(
                modifier = Modifier.fillMaxSize().padding(padding),
                contentPadding = PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                if (state.saving) item { LinearProgressIndicator(Modifier.fillMaxWidth()) }
                if (state.remote) item { EditorHint(R.string.node_edit_remote_hint) }
                if (vpn.serviceActive && vpn.currentNode?.id == nodeId) item { EditorHint(R.string.node_edit_active_hint) }
                if (state.conflict || state.missing) item {
                    Column {
                        EditorHint(if (state.missing) R.string.node_edit_missing else R.string.node_edit_conflict)
                        if (!state.missing) TextButton(onClick = { confirmDiscard = "reload" }, enabled = !state.saving) {
                            Text(stringResource(R.string.node_edit_reload))
                        }
                    }
                }
                item {
                    Text(stringResource(R.string.node_edit_protocol) + ": " + node.type.displayName(),
                        style = MaterialTheme.typography.bodyMedium)
                }
                item {
                    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                        Text(stringResource(R.string.node_edit_advanced), Modifier.weight(1f))
                        Switch(checked = advanced, onCheckedChange = { advanced = it }, enabled = !state.saving)
                    }
                }
                if (errors.isNotEmpty()) item {
                    Text(stringResource(R.string.node_edit_error_count, errors.size), color = MaterialTheme.colorScheme.error)
                }
                for (section in EditorSection.entries) {
                    val fields = visible[section].orEmpty()
                    if (fields.isEmpty()) continue
                    item(key = "section-$section") {
                        Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                            HorizontalDivider()
                            Text(stringResource(section.title), style = MaterialTheme.typography.titleSmall,
                                color = MaterialTheme.colorScheme.primary)
                        }
                    }
                    items(fields, key = { it.key }) { field ->
                        EditorField(field, draft.value(field), node, errors[field.key], !state.saving && !state.missing) {
                            viewModel.change(field.key, it)
                        }
                    }
                }
            }
        }
    }
    if (confirmDiscard != null) AlertDialog(
        onDismissRequest = { confirmDiscard = null },
        title = { Text(stringResource(R.string.node_edit_unsaved_title)) },
        text = { Text(stringResource(R.string.node_edit_unsaved_message)) },
        confirmButton = {
            TextButton(onClick = {
                val action = confirmDiscard
                confirmDiscard = null
                if (action == "reload") viewModel.reload() else viewModel.discardAndClose()
            }) { Text(stringResource(R.string.node_edit_discard)) }
        },
        dismissButton = {
            TextButton(onClick = { confirmDiscard = null }) { Text(stringResource(R.string.node_edit_keep_editing)) }
        }
    )
}

@Composable
private fun EditorHint(message: Int) {
    Text(stringResource(message), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
}

@Composable
private fun EditorField(field: NodeEditField, value: String, node: ProxyNode, error: Int?, enabled: Boolean, onChange: (String) -> Unit) {
    val label = stringResource(field.label)
    val realityTls = field.key == "tls" && node.type == ProxyType.VLESS && !node.publicKey.isNullOrBlank()
    if (field.input == EditorInput.BOOLEAN) {
        Column {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text(label, Modifier.weight(1f))
                Switch(checked = realityTls || value == "true", onCheckedChange = { onChange(it.toString()) }, enabled = enabled && !realityTls)
            }
            if (realityTls) EditorHint(R.string.node_edit_reality_tls_hint)
        }
        return
    }
    val choices = field.choices(node)
    if (field.input == EditorInput.OPTIONAL_BOOLEAN || choices.isNotEmpty()) {
        val options = if (field.input == EditorInput.OPTIONAL_BOOLEAN) listOf("", "true", "false") else choices
        val labels = (options + value).distinct().associateWith { option ->
            when {
                field.input == EditorInput.OPTIONAL_BOOLEAN && option == "true" -> stringResource(R.string.node_edit_on)
                field.input == EditorInput.OPTIONAL_BOOLEAN && option == "false" -> stringResource(R.string.node_edit_off)
                option.isEmpty() && field.key == "transportType" -> stringResource(R.string.node_edit_transport_none)
                option.isEmpty() -> stringResource(R.string.node_edit_default)
                else -> option
            }
        }
        EditorChoice(label, value, labels, error, enabled,
            editable = field.key in setOf("method", "fingerprint", "security"), onChange = onChange)
        return
    }
    var revealed by remember(field.key) { mutableStateOf(false) }
    val secret = field.input == EditorInput.SECRET
    val multiline = field.input == EditorInput.MULTILINE || field.key == "tlsClientKey"
    OutlinedTextField(
        value = value, onValueChange = onChange, modifier = Modifier.fillMaxWidth(), enabled = enabled,
        textStyle = if (field.key == "name") LocalTextStyle.current else LocalTextStyle.current.copy(
            textDirection = TextDirection.Ltr, textAlign = TextAlign.Left
        ),
        label = { Text(label) }, singleLine = !multiline, minLines = if (multiline) 3 else 1, maxLines = if (multiline) 6 else 1,
        placeholder = when (field.key) {
            "transportHeaders", "naiveExtraHeaders" -> { { Text("Host: example.com") } }
            "serverPorts" -> { { Text("443,1000:2000") } }
            "alpn" -> { { Text("h2,http/1.1") } }
            "hopInterval", "heartbeat", "connectTimeout", "transportIdleTimeout", "transportPingTimeout",
            "fallbackDelay", "tlsFragmentFallbackDelay", "tcpKeepAlive", "tcpKeepAliveInterval" -> { { Text("5s") } }
            else -> null
        },
        isError = error != null,
        supportingText = error?.let { { Text(stringResource(it)) } },
        visualTransformation = if (secret && !revealed) PasswordVisualTransformation() else VisualTransformation.None,
        trailingIcon = if (secret) {
            { TextButton(onClick = { revealed = !revealed }) { Text(stringResource(if (revealed) R.string.node_edit_hide else R.string.node_edit_show)) } }
        } else null,
        keyboardOptions = KeyboardOptions(autoCorrectEnabled = false, keyboardType = when {
            field.input == EditorInput.NUMBER -> KeyboardType.Number
            secret -> KeyboardType.Password
            else -> KeyboardType.Text
        })
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun EditorChoice(label: String, value: String, labels: Map<String, String>, error: Int?, enabled: Boolean, editable: Boolean, onChange: (String) -> Unit) {
    var expanded by remember { mutableStateOf(false) }
    ExposedDropdownMenuBox(expanded = expanded && enabled, onExpandedChange = { if (enabled) expanded = it }) {
        OutlinedTextField(
            value = if (editable) value else labels.getValue(value), onValueChange = onChange, readOnly = !editable, enabled = enabled,
            textStyle = if (editable) LocalTextStyle.current.copy(
                textDirection = TextDirection.Ltr, textAlign = TextAlign.Left
            ) else LocalTextStyle.current,
            modifier = Modifier.fillMaxWidth().menuAnchor(if (editable) ExposedDropdownMenuAnchorType.PrimaryEditable else ExposedDropdownMenuAnchorType.PrimaryNotEditable, enabled),
            label = { Text(label) }, singleLine = true, isError = error != null,
            supportingText = error?.let { { Text(stringResource(it)) } },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) }
        )
        ExposedDropdownMenu(expanded = expanded && enabled, onDismissRequest = { expanded = false }) {
            labels.forEach { (key, title) ->
                DropdownMenuItem(text = { Text(title) }, onClick = { onChange(key); expanded = false })
            }
        }
    }
}
