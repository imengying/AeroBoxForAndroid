package com.aerobox.ui.screens

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.animateContentSize
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.gestures.detectDragGesturesAfterLongPress
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
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.zIndex
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.aerobox.R
import com.aerobox.data.model.Subscription
import com.aerobox.data.model.isLocalGroup
import com.aerobox.data.repository.ImportGroupTarget
import com.aerobox.imports.ExternalImportParser
import com.aerobox.imports.ExternalImportRequest
import com.aerobox.ui.components.AppSnackbarHost
import com.aerobox.ui.components.GroupPickerDialog
import com.aerobox.ui.components.GroupPickerSection
import com.aerobox.ui.components.ProvideAppLocale
import com.aerobox.ui.components.rememberGroupPickerState
import com.aerobox.ui.scanner.AeroBoxQrCaptureActivity
import com.aerobox.utils.NetworkUtils
import com.aerobox.viewmodel.SubscriptionViewModel
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SubscriptionScreen(
    onNavigateBack: () -> Unit,
    onNavigateToGroupNodes: (Long) -> Unit = {},
    pendingExternalImport: ExternalImportRequest? = null,
    onExternalImportHandled: (Long) -> Unit = {},
    viewModel: SubscriptionViewModel = viewModel()
) {
    val context = LocalContext.current
    val subscriptions by viewModel.subscriptions.collectAsStateWithLifecycle()
    val localGroups by viewModel.localGroups.collectAsStateWithLifecycle()
    val ungroupedNodeCount by viewModel.ungroupedNodeCount.collectAsStateWithLifecycle()
    val isLoading by viewModel.isLoading.collectAsStateWithLifecycle()
    val pendingImport by viewModel.pendingImport.collectAsStateWithLifecycle()
    val pendingSubscriptionLink by viewModel.pendingSubscriptionLink.collectAsStateWithLifecycle()
    var showImportMenu by remember { mutableStateOf(false) }
    var showAddSubscriptionDialog by remember { mutableStateOf(false) }
    var showAddNodeDialog by remember { mutableStateOf(false) }
    var editTarget by remember { mutableStateOf<Subscription?>(null) }
    var deleteTarget by remember { mutableStateOf<Subscription?>(null) }
    val snackbarHostState = remember { SnackbarHostState() }
    val coroutineScope = rememberCoroutineScope()
    val listState = rememberLazyListState()
    var orderedSubscriptions by remember { mutableStateOf(subscriptions) }
    var draggingSubscriptionId by remember { mutableStateOf<Long?>(null) }
    var draggingOffsetY by remember { mutableFloatStateOf(0f) }
    val qrScanLauncher = rememberLauncherForActivityResult(ScanContract()) { result ->
        val importRequest = ExternalImportParser.fromText(result.contents)
        if (importRequest != null) {
            viewModel.importExternalSource(
                source = importRequest.source,
                nameHint = importRequest.suggestedName.orEmpty()
            )
        } else if (!result.contents.isNullOrBlank()) {
            viewModel.importExternalSource(
                source = result.contents,
                nameHint = ""
            )
        }
    }
    val cameraPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (granted) {
            qrScanLauncher.launch(buildQrScanOptions(context))
        } else {
            coroutineScope.launch {
                snackbarHostState.showSnackbar(
                    context.getString(R.string.scan_qr_permission_required)
                )
            }
        }
    }
    val localFileLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        uri?.let(viewModel::importLocalFile)
    }
    val refreshRotation = if (isLoading) {
        val transition = rememberInfiniteTransition(label = "subscription_refresh")
        val rotation by transition.animateFloat(
            initialValue = 0f,
            targetValue = 360f,
            animationSpec = infiniteRepeatable(
                animation = tween(durationMillis = 900, easing = LinearEasing),
                repeatMode = RepeatMode.Restart
            ),
            label = "subscription_refresh_rotation"
        )
        rotation
    } else {
        0f
    }

    LaunchedEffect(viewModel) {
        viewModel.uiMessage.collectLatest { message ->
            snackbarHostState.showSnackbar(message)
        }
    }

    LaunchedEffect(pendingExternalImport?.id) {
        pendingExternalImport?.let { request ->
            viewModel.importExternalSource(
                source = request.source,
                nameHint = request.suggestedName.orEmpty()
            )
            onExternalImportHandled(request.id)
        }
    }


    LaunchedEffect(subscriptions) {
        if (draggingSubscriptionId == null) {
            orderedSubscriptions = subscriptions
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.subscription_management)) },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = null)
                    }
                },
                actions = {
                    IconButton(
                        onClick = { viewModel.updateAllSubscriptions() },
                        enabled = !isLoading
                    ) {
                        Icon(
                            Icons.Filled.Refresh,
                            contentDescription = stringResource(R.string.refresh),
                            modifier = Modifier.graphicsLayer {
                                rotationZ = refreshRotation
                            }
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface
                )
            )
        },
        snackbarHost = { AppSnackbarHost(hostState = snackbarHostState) },
        floatingActionButton = {
            Box {
                val openQrImport = {
                    showImportMenu = false
                    val hasCameraPermission = context.checkSelfPermission(Manifest.permission.CAMERA) ==
                        PackageManager.PERMISSION_GRANTED
                    if (hasCameraPermission) {
                        qrScanLauncher.launch(buildQrScanOptions(context))
                    } else {
                        cameraPermissionLauncher.launch(Manifest.permission.CAMERA)
                    }
                }
                val openLocalImport = {
                    showImportMenu = false
                    localFileLauncher.launch(arrayOf("*/*"))
                }
                val addViaSubscriptionLinkText = context.getString(R.string.add_via_subscription_link)
                val addViaNodesText = context.getString(R.string.add_via_nodes)
                val scanQrText = context.getString(R.string.scan_qr)
                val addViaLocalFileText = context.getString(R.string.add_via_local_file)

                DropdownMenu(
                    expanded = showImportMenu,
                    onDismissRequest = { showImportMenu = false }
                ) {
                    ProvideAppLocale {
                        DropdownMenuItem(
                            text = {
                                Text(
                                    text = addViaSubscriptionLinkText,
                                    modifier = Modifier.fillMaxWidth(),
                                    textAlign = TextAlign.Center
                                )
                            },
                            onClick = {
                                showImportMenu = false
                                showAddSubscriptionDialog = true
                            }
                        )
                        DropdownMenuItem(
                            text = {
                                Text(
                                    text = addViaNodesText,
                                    modifier = Modifier.fillMaxWidth(),
                                    textAlign = TextAlign.Center
                                )
                            },
                            onClick = {
                                showImportMenu = false
                                showAddNodeDialog = true
                            }
                        )
                        DropdownMenuItem(
                            text = {
                                Text(
                                    text = scanQrText,
                                    modifier = Modifier.fillMaxWidth(),
                                    textAlign = TextAlign.Center
                                )
                            },
                            onClick = openQrImport
                        )
                        DropdownMenuItem(
                            text = {
                                Text(
                                    text = addViaLocalFileText,
                                    modifier = Modifier.fillMaxWidth(),
                                    textAlign = TextAlign.Center
                                )
                            },
                            onClick = openLocalImport
                        )
                    }
                }
                FloatingActionButton(onClick = { showImportMenu = !showImportMenu }) {
                    Icon(Icons.Filled.Add, contentDescription = stringResource(R.string.add_subscription))
                }
            }
        }
    ) { innerPadding ->
        val hasContent = subscriptions.isNotEmpty() || ungroupedNodeCount > 0
        if (!hasContent) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding),
                contentAlignment = Alignment.Center
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    if (isLoading) {
                        CircularProgressIndicator()
                        Spacer(Modifier.height(12.dp))
                        Text(
                            text = stringResource(R.string.subscription_loading),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    } else {
                        Text(
                            text = stringResource(R.string.no_subscription),
                            style = MaterialTheme.typography.bodyLarge,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(Modifier.height(8.dp))
                        Text(
                            text = stringResource(R.string.hint_add_subscription),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.outline
                        )
                    }
                }
            }
        } else {
            LazyColumn(
                state = listState,
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding),
                contentPadding = PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                // Virtual "未分组" card — shown when there are nodes with subscriptionId = 0
                if (ungroupedNodeCount > 0) {
                    item(key = "ungrouped") {
                        UngroupedCard(
                            nodeCount = ungroupedNodeCount,
                            onClick = { onNavigateToGroupNodes(0L) }
                        )
                    }
                }

                items(orderedSubscriptions, key = { it.id }) { subscription ->
                    SubscriptionItem(
                        subscription = subscription,
                        onOpen = {
                            if (subscription.isLocalGroup()) {
                                onNavigateToGroupNodes(subscription.id)
                            } else {
                                editTarget = subscription
                            }
                        },
                        onEdit = { editTarget = subscription },
                        onUpdate = { viewModel.updateSubscription(subscription) },
                        onDelete = { deleteTarget = subscription },
                        isLoading = isLoading,
                        isDragging = draggingSubscriptionId == subscription.id,
                        draggingOffsetY = if (draggingSubscriptionId == subscription.id) draggingOffsetY else 0f,
                        onMove = { dragAmount ->
                            if (!isLoading) {
                                val currentId = draggingSubscriptionId ?: subscription.id
                                if (draggingSubscriptionId == null) {
                                    draggingSubscriptionId = currentId
                                }
                                draggingOffsetY += dragAmount
                                val visibleItems = listState.layoutInfo.visibleItemsInfo
                                val currentItem = visibleItems.firstOrNull { it.key == currentId }
                                val currentIndex = orderedSubscriptions.indexOfFirst { it.id == currentId }
                                if (currentItem != null && currentIndex >= 0) {
                                    val currentCenter = currentItem.offset + draggingOffsetY + currentItem.size / 2f
                                    val targetItem = visibleItems
                                        .filter { it.key != currentId }
                                        .firstOrNull { item ->
                                            currentCenter in item.offset.toFloat()..(item.offset + item.size).toFloat()
                                        }
                                    if (targetItem != null) {
                                        val targetIndex = orderedSubscriptions.indexOfFirst { it.id == targetItem.key }
                                        if (targetIndex >= 0 && targetIndex != currentIndex) {
                                            val mutable = orderedSubscriptions.toMutableList()
                                            val moved = mutable.removeAt(currentIndex)
                                            mutable.add(targetIndex, moved)
                                            orderedSubscriptions = mutable
                                            draggingOffsetY += currentItem.offset - targetItem.offset
                                        }
                                    }
                                }
                            }
                        },
                        onDragStart = {
                            if (!isLoading) {
                                draggingSubscriptionId = subscription.id
                                draggingOffsetY = 0f
                            }
                        },
                        onDragEnd = {
                            if (draggingSubscriptionId != null) {
                                viewModel.reorderSubscriptions(orderedSubscriptions)
                            }
                            draggingSubscriptionId = null
                            draggingOffsetY = 0f
                        },
                        onDragCancel = {
                            draggingSubscriptionId = null
                            draggingOffsetY = 0f
                            orderedSubscriptions = subscriptions
                        }
                    )
                }
            }
        }
    }

    // Add subscription dialog
    if (showAddSubscriptionDialog) {
        SubscriptionEditorDialog(
            title = context.getString(R.string.add_subscription),
            confirmText = context.getString(R.string.add),
            cancelText = context.getString(R.string.cancel),
            groupNameLabel = context.getString(R.string.group_new_name_hint),
            subscriptionNameLabel = context.getString(R.string.subscription_name),
            subscriptionUrlLabel = context.getString(R.string.subscription_url),
            autoUpdateText = context.getString(R.string.subscription_auto_update),
            updateIntervalLabel = context.getString(R.string.subscription_update_interval_minutes),
            updateIntervalHint = context.getString(R.string.subscription_update_interval_hint),
            invalidIntervalText = context.getString(R.string.subscription_auto_update_invalid_interval),
            onDismiss = { showAddSubscriptionDialog = false },
            onConfirm = { name, url, autoUpdate, updateInterval ->
                viewModel.addSubscription(
                    name = name,
                    url = url,
                    autoUpdate = autoUpdate,
                    updateInterval = updateInterval
                )
                showAddSubscriptionDialog = false
            }
        )
    }

    if (showAddNodeDialog) {
        NodeImportDialog(
            localGroups = localGroups,
            title = context.getString(R.string.add_via_nodes),
            nodeContentLabel = context.getString(R.string.node_content),
            addText = context.getString(R.string.add),
            cancelText = context.getString(R.string.cancel),
            defaultLocalGroupName = context.getString(R.string.local_group_label),
            chooseGroupText = context.getString(R.string.import_choose_group),
            ungroupedText = context.getString(R.string.group_ungrouped),
            newGroupText = context.getString(R.string.group_new),
            newGroupNameHint = context.getString(R.string.group_new_name_hint),
            nodeCountSuffix = { count -> context.getString(R.string.group_node_count_suffix, count) },
            onDismiss = { showAddNodeDialog = false },
            onConfirm = { content, target ->
                viewModel.importNodeContent(source = content, target = target)
                showAddNodeDialog = false
            }
        )
    }

    pendingImport?.let { pending ->
        GroupPickerDialog(
            nodeCount = pending.nodeCount,
            suggestedName = pending.suggestedName,
            localGroups = localGroups,
            chooseGroupText = context.getString(R.string.import_choose_group),
            importNodeCountText = context.getString(R.string.import_node_count, pending.nodeCount),
            confirmText = context.getString(R.string.confirm),
            cancelText = context.getString(R.string.cancel),
            defaultLocalGroupName = context.getString(R.string.local_group_label),
            ungroupedText = context.getString(R.string.group_ungrouped),
            newGroupText = context.getString(R.string.group_new),
            newGroupNameHint = context.getString(R.string.group_new_name_hint),
            nodeCountSuffix = { count -> context.getString(R.string.group_node_count_suffix, count) },
            onConfirm = { target -> viewModel.confirmPendingImport(target) },
            onDismiss = { viewModel.cancelPendingImport() }
        )
    }

    pendingSubscriptionLink?.let { link ->
        SubscriptionEditorDialog(
            title = context.getString(R.string.add_subscription),
            confirmText = context.getString(R.string.add),
            cancelText = context.getString(R.string.cancel),
            groupNameLabel = context.getString(R.string.group_new_name_hint),
            subscriptionNameLabel = context.getString(R.string.subscription_name),
            subscriptionUrlLabel = context.getString(R.string.subscription_url),
            autoUpdateText = context.getString(R.string.subscription_auto_update),
            updateIntervalLabel = context.getString(R.string.subscription_update_interval_minutes),
            updateIntervalHint = context.getString(R.string.subscription_update_interval_hint),
            invalidIntervalText = context.getString(R.string.subscription_auto_update_invalid_interval),
            initialName = link.suggestedName,
            initialUrl = link.url,
            initialAutoUpdate = link.autoUpdate,
            initialUpdateInterval = link.updateInterval,
            onDismiss = { viewModel.cancelPendingSubscriptionLink() },
            onConfirm = { name, url, autoUpdate, updateInterval ->
                viewModel.confirmPendingSubscriptionLink(
                    name = name,
                    url = url,
                    autoUpdate = autoUpdate,
                    updateInterval = updateInterval
                )
            }
        )
    }

    editTarget?.let { subscription ->
        SubscriptionEditorDialog(
            title = context.getString(
                if (subscription.isLocalGroup()) R.string.edit_group else R.string.edit_subscription
            ),
            confirmText = context.getString(R.string.save),
            cancelText = context.getString(R.string.cancel),
            groupNameLabel = context.getString(R.string.group_new_name_hint),
            subscriptionNameLabel = context.getString(R.string.subscription_name),
            subscriptionUrlLabel = context.getString(R.string.subscription_url),
            autoUpdateText = context.getString(R.string.subscription_auto_update),
            updateIntervalLabel = context.getString(R.string.subscription_update_interval_minutes),
            updateIntervalHint = context.getString(R.string.subscription_update_interval_hint),
            invalidIntervalText = context.getString(R.string.subscription_auto_update_invalid_interval),
            isLocalGroup = subscription.isLocalGroup(),
            initialName = subscription.name,
            initialUrl = subscription.url,
            initialAutoUpdate = subscription.autoUpdate,
            initialUpdateInterval = subscription.updateInterval,
            onDismiss = { editTarget = null },
            onConfirm = { name, url, autoUpdate, updateInterval ->
                viewModel.editSubscription(
                    subscription = subscription,
                    name = name,
                    url = url,
                    autoUpdate = autoUpdate,
                    updateInterval = updateInterval
                )
                editTarget = null
            }
        )
    }

    // Delete confirmation dialog
    deleteTarget?.let { subscription ->
        val isLocal = subscription.isLocalGroup()
        val deleteTitle = context.getString(
            if (isLocal) R.string.delete_group else R.string.delete_subscription
        )
        val deleteMessage = context.getString(
            if (isLocal) R.string.delete_local_group_confirm else R.string.delete_subscription_confirm,
            subscription.name
        )
        val deleteText = context.getString(R.string.delete)
        val cancelText = context.getString(R.string.cancel)
        ProvideAppLocale {
            AlertDialog(
                onDismissRequest = { deleteTarget = null },
                title = { Text(deleteTitle) },
                text = { Text(deleteMessage) },
                confirmButton = {
                    TextButton(onClick = {
                        viewModel.deleteSubscription(subscription)
                        deleteTarget = null
                    }) {
                        Text(deleteText, color = MaterialTheme.colorScheme.error)
                    }
                },
                dismissButton = {
                    TextButton(onClick = { deleteTarget = null }) {
                        Text(cancelText)
                    }
                }
            )
        }
    }
}

private fun buildQrScanOptions(context: android.content.Context): ScanOptions {
    return ScanOptions().apply {
        setCaptureActivity(AeroBoxQrCaptureActivity::class.java)
        setPrompt(context.getString(R.string.qr_scan_prompt))
        setDesiredBarcodeFormats(ScanOptions.QR_CODE)
        setBeepEnabled(false)
        setOrientationLocked(false)
    }
}

@Composable
private fun NodeImportDialog(
    localGroups: List<Subscription>,
    title: String,
    nodeContentLabel: String,
    addText: String,
    cancelText: String,
    defaultLocalGroupName: String,
    chooseGroupText: String,
    ungroupedText: String,
    newGroupText: String,
    newGroupNameHint: String,
    nodeCountSuffix: (Int) -> String,
    onDismiss: () -> Unit,
    onConfirm: (content: String, target: ImportGroupTarget) -> Unit
) {
    var content by remember { mutableStateOf("") }
    val holder = rememberGroupPickerState(
        suggestedName = "",
        localGroups = localGroups
    )

    ProvideAppLocale {
        AlertDialog(
            onDismissRequest = onDismiss,
            title = { Text(title) },
            text = {
                Column {
                    OutlinedTextField(
                        value = content,
                        onValueChange = { content = it },
                        label = { Text(nodeContentLabel) },
                        minLines = 4,
                        modifier = Modifier.fillMaxWidth()
                    )
                    Spacer(Modifier.height(12.dp))
                    GroupPickerSection(
                        holder = holder,
                        localGroups = localGroups,
                        chooseGroupText = chooseGroupText,
                        ungroupedText = ungroupedText,
                        newGroupText = newGroupText,
                        newGroupNameHint = newGroupNameHint,
                        nodeCountSuffix = nodeCountSuffix
                    )
                }
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        val target = holder.state.toTarget(
                            fallbackName = "",
                            defaultName = defaultLocalGroupName
                        )
                        onConfirm(content.trim(), target)
                    },
                    enabled = content.isNotBlank() && holder.state.isValid
                ) {
                    Text(addText)
                }
            },
            dismissButton = {
                TextButton(onClick = onDismiss) {
                    Text(cancelText)
                }
            }
        )
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun SubscriptionItem(
    subscription: Subscription,
    onOpen: () -> Unit,
    onEdit: () -> Unit,
    onUpdate: () -> Unit,
    onDelete: () -> Unit,
    isLoading: Boolean,
    isDragging: Boolean,
    draggingOffsetY: Float,
    onMove: (Float) -> Unit,
    onDragStart: () -> Unit,
    onDragEnd: () -> Unit,
    onDragCancel: () -> Unit
) {
    val context = LocalContext.current
    val isLocalGroup = subscription.isLocalGroup()
    val containerColor by animateColorAsState(
        targetValue = if (isDragging) {
            MaterialTheme.colorScheme.surfaceContainerHigh
        } else {
            MaterialTheme.colorScheme.surfaceContainerLow
        },
        label = "subscription_drag_color"
    )
    val trafficText = if (!isLocalGroup && subscription.trafficBytes > 0) {
        "${stringResource(R.string.subscription_traffic)} ${NetworkUtils.formatBytes(subscription.trafficBytes)}"
    } else {
        null
    }
    val expiryText = if (!isLocalGroup && subscription.expireTimestamp > 0) {
        "${stringResource(R.string.subscription_expire)} ${formatSubscriptionDate(subscription.expireTimestamp)}"
    } else {
        null
    }
    val localGroupSubtitle = if (isLocalGroup) {
        val label = stringResource(R.string.local_group_label)
        val suffix = stringResource(R.string.group_node_count_suffix, subscription.nodeCount)
        "$label · $suffix"
    } else {
        null
    }

    Card(
        onClick = onOpen,
        modifier = Modifier
            .fillMaxWidth()
            .graphicsLayer {
                translationY = draggingOffsetY
                shadowElevation = if (isDragging) 24f else 0f
            }
            .scale(if (isDragging) 1.01f else 1f)
            .zIndex(if (isDragging) 1f else 0f)
            .animateContentSize(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = containerColor
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = subscription.name,
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f, fill = false)
                    )
                    Spacer(Modifier.width(8.dp))
                    if (!isLocalGroup) {
                        Text(
                            text = buildRelativeTimeText(context, subscription.updateTime),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.outline
                        )
                    }
                }

                if (localGroupSubtitle != null || trafficText != null || expiryText != null) {
                    Spacer(Modifier.height(6.dp))
                }

                localGroupSubtitle?.let { infoText ->
                    Text(
                        text = infoText,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }

                trafficText?.let { infoText ->
                    Text(
                        text = infoText,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }

                expiryText?.let { infoText ->
                    Text(
                        text = infoText,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }

            Spacer(Modifier.width(8.dp))

            Text(
                text = "⋮⋮",
                style = MaterialTheme.typography.titleMedium,
                color = if (isDragging) {
                    MaterialTheme.colorScheme.primary
                } else {
                    MaterialTheme.colorScheme.outline
                },
                modifier = Modifier
                    .padding(horizontal = 4.dp)
                    .pointerInput(subscription.id, isLoading) {
                        if (!isLoading) {
                            detectDragGesturesAfterLongPress(
                                onDragStart = {
                                    onDragStart()
                                },
                                onDragEnd = {
                                    onDragEnd()
                                },
                                onDragCancel = {
                                    onDragCancel()
                                },
                                onDrag = { change, dragAmount ->
                                    change.consume()
                                    onMove(dragAmount.y)
                                }
                            )
                        }
                    }
            )

            Spacer(Modifier.width(4.dp))

            if (!isLocalGroup) {
                IconButton(onClick = onUpdate, enabled = !isLoading) {
                    Icon(
                        Icons.Filled.Refresh,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary
                    )
                }
            }
            IconButton(onClick = onEdit, enabled = !isLoading) {
                Icon(
                    Icons.Filled.Edit,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            IconButton(onClick = onDelete) {
                Icon(
                    Icons.Filled.Delete,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.error
                )
            }
        }
    }
}

@Composable
private fun UngroupedCard(
    nodeCount: Int,
    onClick: () -> Unit
) {
    Card(
        onClick = onClick,
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainerLow
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = stringResource(R.string.group_ungrouped),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Spacer(Modifier.height(6.dp))
                Text(
                    text = stringResource(R.string.group_node_count_suffix, nodeCount),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

private fun formatSubscriptionDate(timestampMs: Long): String {
    return SimpleDateFormat("yyyy-MM-dd", Locale.getDefault()).format(Date(timestampMs))
}

private fun buildRelativeTimeText(context: android.content.Context, timestampMs: Long): String {
    if (timestampMs <= 0L) return context.getString(R.string.never_updated)
    val diff = System.currentTimeMillis() - timestampMs
    val seconds = diff / 1000
    if (seconds < 60) return context.getString(R.string.just_updated)
    val minutes = seconds / 60
    if (minutes < 60) return context.getString(R.string.minutes_ago_format, minutes.toInt())
    val hours = minutes / 60
    if (hours < 24) return context.getString(R.string.hours_ago_format, hours.toInt())
    val days = hours / 24
    return context.getString(R.string.days_ago_format, days.toInt())
}

@Composable
private fun SubscriptionEditorDialog(
    title: String,
    confirmText: String,
    cancelText: String,
    groupNameLabel: String,
    subscriptionNameLabel: String,
    subscriptionUrlLabel: String,
    autoUpdateText: String,
    updateIntervalLabel: String,
    updateIntervalHint: String,
    invalidIntervalText: String,
    isLocalGroup: Boolean = false,
    initialName: String = "",
    initialUrl: String = "",
    initialAutoUpdate: Boolean = true,
    initialUpdateInterval: Long = DEFAULT_INTERVAL_MINUTES * 60_000L,
    onDismiss: () -> Unit,
    onConfirm: (name: String, url: String, autoUpdate: Boolean, updateInterval: Long) -> Unit
) {
    var name by remember(initialName) { mutableStateOf(initialName) }
    var url by remember(initialUrl) { mutableStateOf(initialUrl) }
    var autoUpdate by remember(initialAutoUpdate) { mutableStateOf(initialAutoUpdate) }
    var updateIntervalMinutes by remember(initialUpdateInterval) {
        mutableStateOf((initialUpdateInterval / 60_000L).coerceAtLeast(MIN_INTERVAL_MINUTES).toString())
    }

    val intervalMinutes = updateIntervalMinutes.toLongOrNull()
    val intervalValid = isLocalGroup || !autoUpdate ||
        (intervalMinutes != null && intervalMinutes >= MIN_INTERVAL_MINUTES)
    val urlValid = isLocalGroup || url.isNotBlank()

    ProvideAppLocale {
        AlertDialog(
            onDismissRequest = onDismiss,
            title = { Text(title) },
            text = {
                Column {
                    OutlinedTextField(
                        value = name,
                        onValueChange = { name = it },
                        label = {
                            Text(
                                if (isLocalGroup) groupNameLabel else subscriptionNameLabel
                            )
                        },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                    if (!isLocalGroup) {
                        Spacer(Modifier.height(8.dp))
                        OutlinedTextField(
                            value = url,
                            onValueChange = { url = it },
                            label = { Text(subscriptionUrlLabel) },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth()
                        )
                        Spacer(Modifier.height(12.dp))
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = autoUpdateText,
                                style = MaterialTheme.typography.bodyLarge
                            )
                            Switch(
                                checked = autoUpdate,
                                onCheckedChange = { autoUpdate = it }
                            )
                        }
                        if (autoUpdate) {
                            Spacer(Modifier.height(8.dp))
                            OutlinedTextField(
                                value = updateIntervalMinutes,
                                onValueChange = { input ->
                                    updateIntervalMinutes = input.filter { it.isDigit() }
                                },
                                label = { Text(updateIntervalLabel) },
                                supportingText = {
                                    Text(
                                        text = if (intervalValid) {
                                            updateIntervalHint
                                        } else {
                                            invalidIntervalText
                                        }
                                    )
                                },
                                isError = !intervalValid,
                                singleLine = true,
                                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                                modifier = Modifier.fillMaxWidth()
                            )
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        val minutes = if (autoUpdate && !isLocalGroup) {
                            (intervalMinutes ?: DEFAULT_INTERVAL_MINUTES).coerceAtLeast(MIN_INTERVAL_MINUTES)
                        } else {
                            DEFAULT_INTERVAL_MINUTES
                        }
                        onConfirm(
                            name.trim(),
                            if (isLocalGroup) "" else url.trim(),
                            if (isLocalGroup) false else autoUpdate,
                            minutes * 60_000L
                        )
                    },
                    enabled = name.isNotBlank() && urlValid && intervalValid
                ) {
                    Text(confirmText)
                }
            },
            dismissButton = {
                TextButton(onClick = onDismiss) {
                    Text(cancelText)
                }
            }
        )
    }
}

private const val MIN_INTERVAL_MINUTES = 15L
private const val DEFAULT_INTERVAL_MINUTES = 24L * 60L
