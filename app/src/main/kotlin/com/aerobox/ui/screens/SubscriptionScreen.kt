package com.aerobox.ui.screens

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.clickable
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
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.zIndex
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.aerobox.AeroBoxApplication
import com.aerobox.R
import com.aerobox.data.model.Subscription
import com.aerobox.data.model.SubscriptionInfo
import com.aerobox.data.model.info
import com.aerobox.utils.NetworkUtils
import com.aerobox.viewmodel.SubscriptionViewModel
import kotlinx.coroutines.flow.collectLatest
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SubscriptionScreen(
    onNavigateBack: () -> Unit,
    viewModel: SubscriptionViewModel = viewModel()
) {
    val subscriptions by viewModel.subscriptions.collectAsStateWithLifecycle()
    val isLoading by viewModel.isLoading.collectAsStateWithLifecycle()
    var showAddDialog by remember { mutableStateOf(false) }
    var editTarget by remember { mutableStateOf<Subscription?>(null) }
    var deleteTarget by remember { mutableStateOf<Subscription?>(null) }
    val snackbarHostState = remember { SnackbarHostState() }
    val listState = rememberLazyListState()
    var orderedSubscriptions by remember { mutableStateOf(subscriptions) }
    var draggingSubscriptionId by remember { mutableStateOf<Long?>(null) }
    var draggingOffsetY by remember { mutableFloatStateOf(0f) }

    LaunchedEffect(viewModel) {
        viewModel.uiMessage.collectLatest { message ->
            snackbarHostState.showSnackbar(message)
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
                        Icon(Icons.Filled.ArrowBack, contentDescription = null)
                    }
                },
                actions = {
                    if (isLoading) {
                        CircularProgressIndicator(
                            modifier = Modifier
                                .size(24.dp)
                                .padding(end = 8.dp),
                            strokeWidth = 2.dp
                        )
                    }
                    IconButton(
                        onClick = { viewModel.updateAllSubscriptions() },
                        enabled = !isLoading
                    ) {
                        Icon(Icons.Filled.Refresh, contentDescription = stringResource(R.string.refresh))
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface
                )
            )
        },
        snackbarHost = { SnackbarHost(hostState = snackbarHostState) },
        floatingActionButton = {
            FloatingActionButton(onClick = { showAddDialog = true }) {
                Icon(Icons.Filled.Add, contentDescription = stringResource(R.string.add_subscription))
            }
        }
    ) { innerPadding ->
        if (subscriptions.isEmpty() && !isLoading) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding),
                contentAlignment = Alignment.Center
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
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
        } else {
            LazyColumn(
                state = listState,
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding),
                contentPadding = PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                items(orderedSubscriptions, key = { it.id }) { subscription ->
                    SubscriptionItem(
                        subscription = subscription,
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
    if (showAddDialog) {
        SubscriptionEditorDialog(
            title = stringResource(R.string.add_subscription),
            confirmText = stringResource(R.string.add),
            onDismiss = { showAddDialog = false },
            onConfirm = { name, url, autoUpdate, updateInterval ->
                viewModel.addSubscription(
                    name = name,
                    url = url,
                    autoUpdate = autoUpdate,
                    updateInterval = updateInterval
                )
                showAddDialog = false
            }
        )
    }

    editTarget?.let { subscription ->
        SubscriptionEditorDialog(
            title = stringResource(R.string.edit_subscription),
            confirmText = stringResource(R.string.save),
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
        AlertDialog(
            onDismissRequest = { deleteTarget = null },
            title = { Text(stringResource(R.string.delete_subscription)) },
            text = { Text("确定要删除「${subscription.name}」及其所有节点吗？") },
            confirmButton = {
                TextButton(onClick = {
                    viewModel.deleteSubscription(subscription)
                    deleteTarget = null
                }) {
                    Text(stringResource(R.string.delete), color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = {
                TextButton(onClick = { deleteTarget = null }) {
                    Text(stringResource(R.string.cancel))
                }
            }
        )
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun SubscriptionItem(
    subscription: Subscription,
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
    val containerColor by animateColorAsState(
        targetValue = if (isDragging) {
            MaterialTheme.colorScheme.surfaceContainerHigh
        } else {
            MaterialTheme.colorScheme.surfaceContainerLow
        },
        label = "subscription_drag_color"
    )

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .graphicsLayer {
                translationY = draggingOffsetY
                shadowElevation = if (isDragging) 24f else 0f
            }
            .scale(if (isDragging) 1.01f else 1f)
            .zIndex(if (isDragging) 1f else 0f)
            .animateContentSize()
            .clickable(onClick = onEdit),
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
                    Text(
                        text = buildRelativeTimeText(subscription.updateTime),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.outline
                    )
                }
                buildTrafficInfoText(subscription.info)?.let { trafficText ->
                    Spacer(Modifier.height(6.dp))
                    Text(
                        text = trafficText,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.primary
                    )
                    Spacer(Modifier.height(6.dp))
                    LinearProgressIndicator(
                        progress = { subscription.info.progress },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(6.dp),
                        color = MaterialTheme.colorScheme.primary,
                        trackColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.16f)
                    )
                }
                buildRemainingInfoText(subscription.info)?.let { remainingText ->
                    Spacer(Modifier.height(4.dp))
                    Text(
                        text = remainingText,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                buildExpiryInfoText(subscription.info)?.let { expiryText ->
                    Spacer(Modifier.height(2.dp))
                    Text(
                        text = expiryText,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.outline
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

            IconButton(onClick = onUpdate, enabled = !isLoading) {
                Icon(
                    Icons.Filled.Refresh,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary
                )
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
private fun buildRelativeTimeText(timestampMs: Long): String {
    if (timestampMs <= 0L) return "从未更新"
    val diff = System.currentTimeMillis() - timestampMs
    val seconds = diff / 1000
    if (seconds < 60) return "刚刚更新"
    val minutes = seconds / 60
    if (minutes < 60) return "${minutes}分钟前"
    val hours = minutes / 60
    if (hours < 24) return "${hours}小时前"
    val days = hours / 24
    return "${days}天前"
}

private fun buildTrafficInfoText(info: SubscriptionInfo): String? {
    if (!info.hasTrafficQuota) return null
    return "${NetworkUtils.formatBytesCompact(info.usedBytes)} / ${NetworkUtils.formatBytesCompact(info.totalBytes)}"
}

private fun buildRemainingInfoText(info: SubscriptionInfo): String? {
    if (!info.hasTrafficQuota) return null
    return AeroBoxApplication.appInstance.getString(
        R.string.subscription_traffic_remaining,
        NetworkUtils.formatBytesCompact(info.remainingBytes)
    )
}

private fun buildExpiryInfoText(info: SubscriptionInfo): String? {
    return when {
        info.hasExpiry -> formatExpiry(info.expireTimestamp)
        buildTrafficInfoText(info) != null -> AeroBoxApplication.appInstance.getString(R.string.subscription_no_expiry)
        else -> null
    }
}

private fun formatExpiry(expireTimestamp: Long): String {
    val timestampMillis = if (expireTimestamp < 10_000_000_000L) expireTimestamp * 1000 else expireTimestamp
    val remainMs = timestampMillis - System.currentTimeMillis()
    if (remainMs <= 0L) return "已过期"

    val days = remainMs / (24 * 60 * 60 * 1000)
    val hours = (remainMs / (60 * 60 * 1000)) % 24
    return when {
        days > 0 -> "${days}天${hours}小时"
        hours > 0 -> "${hours}小时"
        else -> "不足1小时"
    }
}

@Composable
private fun SubscriptionEditorDialog(
    title: String,
    confirmText: String,
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
    val intervalValid = !autoUpdate || (intervalMinutes != null && intervalMinutes >= MIN_INTERVAL_MINUTES)

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            Column {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text(stringResource(R.string.subscription_name)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = url,
                    onValueChange = { url = it },
                    label = { Text(stringResource(R.string.subscription_url)) },
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
                        text = stringResource(R.string.subscription_auto_update),
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
                        label = { Text(stringResource(R.string.subscription_update_interval_minutes)) },
                        supportingText = {
                            Text(
                                text = if (intervalValid) {
                                    stringResource(R.string.subscription_update_interval_hint)
                                } else {
                                    stringResource(R.string.subscription_auto_update_invalid_interval)
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
        },
        confirmButton = {
            TextButton(
                onClick = {
                    val minutes = if (autoUpdate) {
                        (intervalMinutes ?: DEFAULT_INTERVAL_MINUTES).coerceAtLeast(MIN_INTERVAL_MINUTES)
                    } else {
                        DEFAULT_INTERVAL_MINUTES
                    }
                    onConfirm(
                        name.trim(),
                        url.trim(),
                        autoUpdate,
                        minutes * 60_000L
                    )
                },
                enabled = name.isNotBlank() && url.isNotBlank() && intervalValid
            ) {
                Text(confirmText)
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.cancel))
            }
        }
    )
}

private const val MIN_INTERVAL_MINUTES = 15L
private const val DEFAULT_INTERVAL_MINUTES = 24L * 60L
