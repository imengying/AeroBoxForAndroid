package com.aerobox.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.Checkbox
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.aerobox.viewmodel.AppViewModelFactory
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import com.aerobox.R
import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.Subscription
import com.aerobox.data.model.isLocalGroup
import com.aerobox.ui.components.AppDialog
import com.aerobox.ui.components.DialogActions
import com.aerobox.ui.components.AppSnackbarHost
import com.aerobox.ui.components.GroupPickerDialog
import com.aerobox.ui.icons.AppIcons
import com.aerobox.viewmodel.DataTransferViewModel
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch

private data class SubscriptionSnapshot(val value: Subscription?)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun GroupNodesScreen(
    subscriptionId: Long,
    onEditNode: (Long) -> Unit,
    onNavigateBack: () -> Unit,
    viewModel: DataTransferViewModel = viewModel(factory = AppViewModelFactory)
) {
    val isUngrouped = subscriptionId == 0L
    val subscriptionSnapshot by remember(viewModel, subscriptionId) {
        viewModel.observeSubscription(subscriptionId).map { SubscriptionSnapshot(it) }
    }
        .collectAsStateWithLifecycle(initialValue = null)
    val subscription = subscriptionSnapshot?.value
    val nodes by viewModel.observeNodes(subscriptionId)
        .collectAsStateWithLifecycle(initialValue = emptyList())
    val scope = rememberCoroutineScope()
    val localGroups by viewModel.observeLocalGroups().collectAsStateWithLifecycle(initialValue = emptyList())
    val operationBusy by viewModel.busy.collectAsStateWithLifecycle()
    val selectionReady by viewModel.selectionReady.collectAsStateWithLifecycle()
    val busy = operationBusy || !selectionReady
    val message by viewModel.message.collectAsStateWithLifecycle()
    val snackbar = remember { SnackbarHostState() }
    var query by rememberSaveable { mutableStateOf("") }
    val selected by viewModel.selectedNodes.collectAsStateWithLifecycle()
    var showCopyDialog by remember { mutableStateOf(false) }
    var showBatchDelete by remember { mutableStateOf(false) }
    val visibleNodes = remember(nodes, query) {
        nodes.filter { it.name.contains(query, true) || it.server.contains(query, true) || it.type.name.contains(query, true) }
    }
    val nodeIds = remember(nodes) { nodes.map { it.id }.toSet() }
    val selectedIds = remember(selected, nodeIds) { selected.intersect(nodeIds) }
    val export = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/json")) { uri ->
        if (uri != null) viewModel.exportNodes(uri) else viewModel.cancelNodeExport()
    }
    LaunchedEffect(message) {
        message?.let { snackbar.showSnackbar(it); viewModel.dismissMessage() }
    }

    var deleteNodeTarget by remember { mutableStateOf<ProxyNode?>(null) }
    var showRenameDialog by remember { mutableStateOf(false) }
    var showDeleteGroupDialog by remember { mutableStateOf(false) }

    // Wait for a database result before treating a missing row as deleted.
    // A newly restored composition briefly has no value when returning from the editor.
    LaunchedEffect(subscriptionSnapshot, operationBusy) {
        if (!isUngrouped && subscriptionSnapshot != null && subscription == null && !operationBusy) {
            onNavigateBack()
        }
    }

    val editableSubscription = subscription?.takeIf { !isUngrouped && it.isLocalGroup() }
    val groupName = if (isUngrouped) stringResource(R.string.group_ungrouped) else subscription?.name.orEmpty()

    Scaffold(
        snackbarHost = { AppSnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = groupName.ifBlank { stringResource(R.string.edit_group) },
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = null)
                    }
                },
                actions = {
                    if (editableSubscription != null) {
                        IconButton(onClick = { showRenameDialog = true }, enabled = !busy) {
                            Icon(
                                Icons.Filled.Edit,
                                contentDescription = stringResource(R.string.rename_group)
                            )
                        }
                        IconButton(onClick = { showDeleteGroupDialog = true }, enabled = !busy) {
                            Icon(
                                Icons.Filled.Delete,
                                contentDescription = stringResource(R.string.delete_group),
                                tint = MaterialTheme.colorScheme.error
                            )
                        }
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface
                )
            )
        }
    ) { innerPadding ->
        Column(Modifier.fillMaxSize().padding(innerPadding)) {
            OutlinedTextField(
                value = query, onValueChange = { query = it }, singleLine = true,
                label = { Text(stringResource(R.string.search_nodes)) },
                leadingIcon = { Icon(Icons.Filled.Search, null) },
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp)
            )
            Row(Modifier.fillMaxWidth().padding(horizontal = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                Checkbox(
                    checked = visibleNodes.isNotEmpty() && visibleNodes.all { it.id in selectedIds },
                    onCheckedChange = { checked ->
                        val visibleIds = visibleNodes.map { it.id }.toSet()
                        viewModel.selectNodes(if (checked) selectedIds + visibleIds else selectedIds - visibleIds)
                    }, enabled = !busy && visibleNodes.isNotEmpty()
                )
                Text(stringResource(R.string.nodes_selected, selectedIds.size), Modifier.weight(1f))
                IconButton(onClick = { showCopyDialog = true }, enabled = !busy && selectedIds.isNotEmpty()) {
                    Icon(AppIcons.ContentCopy, stringResource(R.string.copy_to_group))
                }
                IconButton(onClick = {
                    scope.launch {
                        if (viewModel.prepareNodeExport(selectedIds.toList())) export.launch("AeroBox-nodes.json")
                    }
                }, enabled = !busy && selectedIds.isNotEmpty()) {
                    Icon(Icons.Filled.Share, stringResource(R.string.export_nodes))
                }
                IconButton(onClick = { showBatchDelete = true }, enabled = !busy && selectedIds.isNotEmpty()) {
                    Icon(Icons.Filled.Delete, stringResource(R.string.delete_node))
                }
            }
            if (subscription?.isLocalGroup() == false) {
                Text(stringResource(R.string.remote_nodes_overwritten), Modifier.padding(horizontal = 16.dp),
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            if (busy) LinearProgressIndicator(Modifier.fillMaxWidth())
        if (visibleNodes.isEmpty()) {
            Box(
                modifier = Modifier.fillMaxSize(),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    text = stringResource(R.string.group_empty_nodes),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        } else {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                contentPadding = PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                items(visibleNodes, key = { it.id }) { node ->
                    NodeRow(
                        node = node,
                        onEdit = { onEditNode(node.id) },
                        onDelete = { deleteNodeTarget = node },
                        selected = node.id in selectedIds,
                        onSelect = { checked -> viewModel.selectNodes(if (checked) selectedIds + node.id else selectedIds - node.id) },
                        enabled = !busy
                    )
                }
            }
        }
        }
    }

    if (showCopyDialog) GroupPickerDialog(
        nodeCount = selectedIds.size, suggestedName = "", localGroups = localGroups,
        onConfirm = { target -> showCopyDialog = false; viewModel.copyNodes(selectedIds.toList(), target) },
        onDismiss = { showCopyDialog = false }
    )
    if (showBatchDelete) AlertDialog(
        onDismissRequest = { showBatchDelete = false },
        title = { Text(stringResource(R.string.delete_node)) },
        text = { Text(pluralStringResource(R.plurals.delete_nodes_confirm, selectedIds.size, selectedIds.size)) },
        confirmButton = { TextButton(onClick = {
            showBatchDelete = false
            viewModel.deleteNodes(selectedIds.toList())
            viewModel.selectNodes(emptyList())
        }, enabled = !busy) { Text(stringResource(R.string.confirm)) } },
        dismissButton = { TextButton(onClick = { showBatchDelete = false }) { Text(stringResource(R.string.cancel)) } }
    )

    deleteNodeTarget?.let { node ->
        AppDialog(onDismissRequest = { deleteNodeTarget = null }) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Text(
                    text = stringResource(R.string.delete_node),
                    style = MaterialTheme.typography.titleMedium
                )
                Text(
                    text = stringResource(
                        R.string.delete_node_confirm,
                        node.name.ifBlank { node.server }
                    ),
                    style = MaterialTheme.typography.bodyMedium
                )
                DialogActions {
                    TextButton(onClick = { deleteNodeTarget = null }) {
                        Text(stringResource(R.string.cancel))
                    }
                    TextButton(onClick = {
                        viewModel.deleteNodes(listOf(node.id))
                        deleteNodeTarget = null
                    }) {
                        Text(stringResource(R.string.delete), color = MaterialTheme.colorScheme.error)
                    }
                }
            }
        }
    }

    if (showRenameDialog && editableSubscription != null) {
        RenameGroupDialog(
            initialName = editableSubscription.name,
            onDismiss = { showRenameDialog = false },
            onConfirm = { newName ->
                scope.launch {
                    viewModel.renameLocalGroup(editableSubscription, newName)
                }
                showRenameDialog = false
            }
        )
    }

    if (showDeleteGroupDialog && editableSubscription != null) {
        AppDialog(onDismissRequest = { showDeleteGroupDialog = false }) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Text(
                    text = stringResource(R.string.delete_group),
                    style = MaterialTheme.typography.titleMedium
                )
                Text(
                    text = stringResource(
                        R.string.delete_local_group_confirm,
                        editableSubscription.name
                    ),
                    style = MaterialTheme.typography.bodyMedium
                )
                DialogActions {
                    TextButton(onClick = { showDeleteGroupDialog = false }) {
                        Text(stringResource(R.string.cancel))
                    }
                    TextButton(onClick = {
                        showDeleteGroupDialog = false
                        viewModel.deleteGroup(editableSubscription)
                    }) {
                        Text(stringResource(R.string.delete), color = MaterialTheme.colorScheme.error)
                    }
                }
            }
        }
    }
}

@Composable
private fun NodeRow(
    node: ProxyNode,
    onEdit: () -> Unit,
    onDelete: () -> Unit,
    selected: Boolean,
    onSelect: (Boolean) -> Unit,
    enabled: Boolean
) {
    Card(
        onClick = onEdit,
        enabled = enabled,
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainerLow
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Checkbox(checked = selected, onCheckedChange = onSelect, enabled = enabled)
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = node.name.ifBlank { "${node.server}:${node.port}" },
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    text = "${node.type.displayName()} · ${node.server}:${node.port}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }

            Spacer(Modifier.width(8.dp))

            IconButton(onClick = onEdit, enabled = enabled) {
                Icon(
                    Icons.Filled.Edit,
                    contentDescription = stringResource(R.string.edit_node)
                )
            }
            IconButton(onClick = onDelete, enabled = enabled) {
                Icon(
                    Icons.Filled.Delete,
                    contentDescription = stringResource(R.string.delete_node),
                    tint = MaterialTheme.colorScheme.error
                )
            }
        }
    }
}

@Composable
private fun RenameGroupDialog(
    initialName: String,
    onDismiss: () -> Unit,
    onConfirm: (String) -> Unit
) {
    var name by remember(initialName) { mutableStateOf(initialName) }
    AppDialog(onDismissRequest = onDismiss) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text(
                text = stringResource(R.string.rename_group),
                style = MaterialTheme.typography.titleMedium
            )
            OutlinedTextField(
                value = name,
                onValueChange = { name = it },
                label = { Text(stringResource(R.string.group_new_name_hint)) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            DialogActions {
                TextButton(onClick = onDismiss) {
                    Text(stringResource(R.string.cancel))
                }
                TextButton(
                    onClick = { onConfirm(name.trim()) },
                    enabled = name.isNotBlank()
                ) {
                    Text(stringResource(R.string.save))
                }
            }
        }
    }
}
