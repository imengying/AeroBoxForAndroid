package com.aerobox.ui.screens

import android.os.Build
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.clickable
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Share
import com.aerobox.ui.icons.AppIcons
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.foundation.layout.Row
import androidx.compose.material3.FilterChip
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Icon
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.aerobox.AeroBoxApplication
import com.aerobox.R
import com.aerobox.core.geo.GeoAssetManager
import com.aerobox.data.model.RoutingMode
import com.aerobox.utils.ImportExportUtils
import com.aerobox.viewmodel.SettingsViewModel
import android.content.Intent
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    onNavigateToSubscriptions: () -> Unit = {},
    onNavigateToPerAppProxy: () -> Unit = {},
    onNavigateToLog: () -> Unit = {},
    viewModel: SettingsViewModel = viewModel()
) {
    val darkMode by viewModel.darkMode.collectAsStateWithLifecycle()
    val dynamicColor by viewModel.dynamicColor.collectAsStateWithLifecycle()
    val autoConnect by viewModel.autoConnect.collectAsStateWithLifecycle()
    val autoUpdateSubscription by viewModel.autoUpdateSubscription.collectAsStateWithLifecycle()
    val showNotification by viewModel.showNotification.collectAsStateWithLifecycle()
    val routingMode by viewModel.routingMode.collectAsStateWithLifecycle()
    val remoteDns by viewModel.remoteDns.collectAsStateWithLifecycle()
    val localDns by viewModel.localDns.collectAsStateWithLifecycle()
    val enableDoh by viewModel.enableDoh.collectAsStateWithLifecycle()
    val perAppProxyEnabled by viewModel.perAppProxyEnabled.collectAsStateWithLifecycle()
    val enableSocksInbound by viewModel.enableSocksInbound.collectAsStateWithLifecycle()
    val enableHttpInbound by viewModel.enableHttpInbound.collectAsStateWithLifecycle()
    val enableIPv6 by viewModel.enableIPv6.collectAsStateWithLifecycle()
    val autoReconnect by viewModel.autoReconnect.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()

    var showDnsDialog by remember { mutableStateOf(false) }
    var showRoutingDialog by remember { mutableStateOf(false) }
    var geoUpdating by remember { mutableStateOf(false) }
    val context = LocalContext.current

    // SAF file picker for import
    val filePickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri ->
        if (uri != null) {
            scope.launch {
                val nodes = ImportExportUtils.importFromFile(context, uri)
                if (nodes.isNotEmpty()) {
                    val db = AeroBoxApplication.database
                    db.proxyNodeDao().insertAll(nodes)
                    Toast.makeText(context, "导入 ${nodes.size} 个节点", Toast.LENGTH_SHORT).show()
                } else {
                    Toast.makeText(context, "未找到可导入的节点", Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        // ── Subscription ──
        item { SectionHeader(title = "订阅管理") }
        item {
            SettingItem(
                modifier = Modifier.clickable { onNavigateToSubscriptions() },
                icon = { Icon(Icons.Filled.Refresh, contentDescription = null) },
                title = "订阅管理",
                supporting = "添加、更新和管理代理订阅",
                trailing = { Icon(Icons.Filled.KeyboardArrowRight, contentDescription = null) }
            )
        }

        // ── DNS ──
        item { SectionHeader(title = "DNS 设置") }
        item {
            SettingItem(
                modifier = Modifier.clickable { showDnsDialog = true },
                icon = { Icon(AppIcons.Security, contentDescription = null) },
                title = "DNS 服务器",
                supporting = "远程: $remoteDns · 本地: $localDns",
                trailing = { Icon(Icons.Filled.KeyboardArrowRight, contentDescription = null) }
            )
        }
        item {
            SettingItem(
                icon = { Icon(AppIcons.Security, contentDescription = null) },
                title = "加密 DNS",
                supporting = "使用 DNS over TLS/HTTPS",
                trailing = {
                    Switch(checked = enableDoh, onCheckedChange = { scope.launch { viewModel.setEnableDoh(it) } })
                }
            )
        }

        // ── Per-App Proxy ──
        item { SectionHeader(title = "分应用代理") }
        item {
            SettingItem(
                icon = { Icon(AppIcons.Speed, contentDescription = null) },
                title = "启用分应用代理",
                supporting = if (perAppProxyEnabled) "已启用" else "未启用",
                trailing = {
                    Switch(
                        checked = perAppProxyEnabled,
                        onCheckedChange = { scope.launch { viewModel.setPerAppProxyEnabled(it) } }
                    )
                }
            )
        }
        if (perAppProxyEnabled) {
            item {
                SettingItem(
                    modifier = Modifier.clickable { onNavigateToPerAppProxy() },
                    icon = { Icon(AppIcons.Speed, contentDescription = null) },
                    title = "配置应用列表",
                    supporting = "选择哪些应用走代理/绕过代理",
                    trailing = { Icon(Icons.Filled.KeyboardArrowRight, contentDescription = null) }
                )
            }
        }

        // ── Import/Export ──
        item { SectionHeader(title = "导入 / 导出") }
        item {
            SettingItem(
                modifier = Modifier.clickable {
                    scope.launch {
                        val nodes = ImportExportUtils.importFromClipboard(context)
                        if (nodes.isNotEmpty()) {
                            val db = AeroBoxApplication.database
                            db.proxyNodeDao().insertAll(nodes)
                            Toast.makeText(context, "从剪贴板导入 ${nodes.size} 个节点", Toast.LENGTH_SHORT).show()
                        } else {
                            Toast.makeText(context, "剪贴板中未找到可导入的节点", Toast.LENGTH_SHORT).show()
                        }
                    }
                },
                icon = { Icon(AppIcons.Speed, contentDescription = null) },
                title = "从剪贴板导入",
                supporting = "导入 URI / JSON / Clash YAML 格式节点",
                trailing = {}
            )
        }
        item {
            SettingItem(
                modifier = Modifier.clickable { filePickerLauncher.launch("*/*") },
                icon = { Icon(AppIcons.Speed, contentDescription = null) },
                title = "从文件导入",
                supporting = "选择本地配置文件导入",
                trailing = { Icon(Icons.Filled.KeyboardArrowRight, contentDescription = null) }
            )
        }
        item {
            SettingItem(
                modifier = Modifier.clickable {
                    scope.launch {
                        val db = AeroBoxApplication.database
                        val allNodes = db.proxyNodeDao().getAllNodes()
                        val nodes = allNodes.first()
                        if (nodes.isNotEmpty()) {
                            val uris = nodes.mapNotNull { ImportExportUtils.exportNodeAsUri(it) }
                                .joinToString("\n")
                            val intent = ImportExportUtils.createShareIntent(uris)
                            context.startActivity(Intent.createChooser(intent, "分享节点"))
                        } else {
                            Toast.makeText(context, "暂无节点可导出", Toast.LENGTH_SHORT).show()
                        }
                    }
                },
                icon = { Icon(Icons.Filled.Share, contentDescription = null) },
                title = "导出并分享",
                supporting = "将所有节点以 URI 格式分享",
                trailing = {}
            )
        }

        // ── Geo Assets ──
        item { SectionHeader(title = "GeoIP / GeoSite 资源") }
        item {
            val hasFiles = GeoAssetManager.hasLocalFiles(context)
            val geoIpSize = GeoAssetManager.getGeoIpSize(context)
            val geoSiteSize = GeoAssetManager.getGeoSiteSize(context)
            SettingItem(
                modifier = Modifier.clickable {
                    if (!geoUpdating) {
                        geoUpdating = true
                        scope.launch {
                            val ok = GeoAssetManager.updateAll(context)
                            geoUpdating = false
                            Toast.makeText(
                                context,
                                if (ok) "资源更新完成" else "更新失败，请检查网络",
                                Toast.LENGTH_SHORT
                            ).show()
                        }
                    }
                },
                icon = { Icon(AppIcons.Security, contentDescription = null) },
                title = if (hasFiles) "更新规则数据库" else "下载规则数据库",
                supporting = if (hasFiles) "GeoIP: $geoIpSize · GeoSite: $geoSiteSize" else "规则分流需要此资源",
                trailing = {
                    if (geoUpdating) {
                        CircularProgressIndicator(
                            modifier = Modifier.padding(4.dp),
                            strokeWidth = 2.dp
                        )
                    } else {
                        Icon(Icons.Filled.Refresh, contentDescription = null)
                    }
                }
            )
        }

        // ── Inbound Proxy ──
        item { SectionHeader(title = "入站代理") }
        item {
            SettingItem(
                icon = { Icon(AppIcons.Speed, contentDescription = null) },
                title = "SOCKS5 入站",
                supporting = "端口 2080",
                trailing = {
                    Switch(
                        checked = enableSocksInbound,
                        onCheckedChange = { scope.launch { viewModel.setEnableSocksInbound(it) } }
                    )
                }
            )
        }
        item {
            SettingItem(
                icon = { Icon(AppIcons.Speed, contentDescription = null) },
                title = "HTTP 入站",
                supporting = "端口 2081",
                trailing = {
                    Switch(
                        checked = enableHttpInbound,
                        onCheckedChange = { scope.launch { viewModel.setEnableHttpInbound(it) } }
                    )
                }
            )
        }

        // ── Appearance ──
        item { SectionHeader(title = stringResource(R.string.appearance)) }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            item {
                SettingItem(
                    icon = { Icon(AppIcons.ColorLens, contentDescription = null) },
                    title = stringResource(R.string.dynamic_color),
                    supporting = stringResource(R.string.android_12_plus),
                    trailing = {
                        Switch(checked = dynamicColor, onCheckedChange = { scope.launch { viewModel.setDynamicColor(it) } })
                    }
                )
            }
        }
        item {
            SettingItem(
                icon = { Icon(AppIcons.DarkMode, contentDescription = null) },
                title = stringResource(R.string.dark_mode),
                supporting = when (darkMode) {
                    "on" -> "始终开启"
                    "off" -> "始终关闭"
                    else -> "跟随系统"
                },
                trailing = {
                    Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                        FilterChip(
                            selected = darkMode == "system",
                            onClick = { scope.launch { viewModel.setDarkMode("system") } },
                            label = { Text("系统") }
                        )
                        FilterChip(
                            selected = darkMode == "on",
                            onClick = { scope.launch { viewModel.setDarkMode("on") } },
                            label = { Text("开") }
                        )
                        FilterChip(
                            selected = darkMode == "off",
                            onClick = { scope.launch { viewModel.setDarkMode("off") } },
                            label = { Text("关") }
                        )
                    }
                }
            )
        }

        // ── Connection settings ──
        item { SectionHeader(title = stringResource(R.string.connection_settings)) }
        item {
            SettingItem(
                icon = { Icon(AppIcons.Power, contentDescription = null) },
                title = stringResource(R.string.auto_connect),
                supporting = "开机后自动连接",
                trailing = {
                    Switch(checked = autoConnect, onCheckedChange = { scope.launch { viewModel.setAutoConnect(it) } })
                }
            )
        }
        item {
            SettingItem(
                icon = { Icon(Icons.Filled.Refresh, contentDescription = null) },
                title = stringResource(R.string.auto_update_subscription),
                supporting = "连接时自动更新订阅",
                trailing = {
                    Switch(
                        checked = autoUpdateSubscription,
                        onCheckedChange = { scope.launch { viewModel.setAutoUpdateSubscription(it) } }
                    )
                }
            )
        }
        item {
            SettingItem(
                icon = { Icon(Icons.Filled.Notifications, contentDescription = null) },
                title = stringResource(R.string.show_notification),
                supporting = "连接时在通知栏显示状态",
                trailing = {
                    Switch(checked = showNotification, onCheckedChange = { scope.launch { viewModel.setShowNotification(it) } })
                }
            )
        }
        item {
            SettingItem(
                icon = { Icon(AppIcons.Speed, contentDescription = null) },
                title = stringResource(R.string.enable_ipv6),
                supporting = "启用 IPv6 网络支持",
                trailing = {
                    Switch(checked = enableIPv6, onCheckedChange = { scope.launch { viewModel.setEnableIPv6(it) } })
                }
            )
        }
        item {
            SettingItem(
                icon = { Icon(AppIcons.Power, contentDescription = null) },
                title = "断线自动重连",
                supporting = "VPN 意外断开时自动重新连接",
                trailing = {
                    Switch(checked = autoReconnect, onCheckedChange = { scope.launch { viewModel.setAutoReconnect(it) } })
                }
            )
        }

        // ── About ──
        item { SectionHeader(title = stringResource(R.string.about)) }
        item {
            SettingItem(
                modifier = Modifier.clickable { onNavigateToLog() },
                icon = { Icon(Icons.Filled.Info, contentDescription = null) },
                title = "运行日志",
                supporting = "查看 sing-box 运行日志",
                trailing = { Icon(Icons.Filled.KeyboardArrowRight, contentDescription = null) }
            )
        }
        item {
            SettingItem(
                icon = { Icon(Icons.Filled.Info, contentDescription = null) },
                title = stringResource(R.string.version),
                supporting = "${com.aerobox.BuildConfig.VERSION_NAME} (sing-box ${com.aerobox.core.native.SingBoxNative.getVersion()})",
                trailing = {}
            )
        }
        item {
            SettingItem(
                icon = { Icon(AppIcons.Security, contentDescription = null) },
                title = stringResource(R.string.open_source_licenses),
                supporting = stringResource(R.string.about),
                trailing = { Icon(Icons.Filled.KeyboardArrowRight, contentDescription = null) }
            )
        }
    }

    // DNS dialog
    if (showDnsDialog) {
        DnsSettingsDialog(
            remoteDns = remoteDns,
            localDns = localDns,
            onDismiss = { showDnsDialog = false },
            onConfirm = { remote, local ->
                scope.launch {
                    viewModel.setRemoteDns(remote)
                    viewModel.setLocalDns(local)
                }
                showDnsDialog = false
            }
        )
    }

    // Routing mode dialog
    if (showRoutingDialog) {
        RoutingModeDialog(
            currentMode = routingMode,
            onDismiss = { showRoutingDialog = false },
            onModeSelected = { mode ->
                scope.launch { viewModel.setRoutingMode(mode) }
            }
        )
    }
}

@Composable
private fun RoutingModeDialog(
    currentMode: RoutingMode,
    onDismiss: () -> Unit,
    onModeSelected: (RoutingMode) -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("路由模式") },
        text = {
            Column {
                RoutingMode.entries.forEach { mode ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable {
                                onModeSelected(mode)
                                onDismiss()
                            }
                            .padding(vertical = 4.dp),
                        verticalAlignment = androidx.compose.ui.Alignment.CenterVertically
                    ) {
                        RadioButton(
                            selected = mode == currentMode,
                            onClick = {
                                onModeSelected(mode)
                                onDismiss()
                            }
                        )
                        Text(
                            text = mode.displayName,
                            style = MaterialTheme.typography.bodyLarge,
                            modifier = Modifier.padding(start = 8.dp)
                        )
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) }
        }
    )
}

@Composable
private fun DnsSettingsDialog(
    remoteDns: String,
    localDns: String,
    onDismiss: () -> Unit,
    onConfirm: (remote: String, local: String) -> Unit
) {
    var remote by remember { mutableStateOf(remoteDns) }
    var local by remember { mutableStateOf(localDns) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("DNS 设置") },
        text = {
            Column {
                OutlinedTextField(
                    value = remote,
                    onValueChange = { remote = it },
                    label = { Text("远程 DNS") },
                    supportingText = { Text("示例: tls://8.8.8.8, https://1.1.1.1/dns-query") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = local,
                    onValueChange = { local = it },
                    label = { Text("本地 DNS") },
                    supportingText = { Text("用于解析中国域名: 223.5.5.5, 119.29.29.29") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = { onConfirm(remote.trim(), local.trim()) },
                enabled = remote.isNotBlank() && local.isNotBlank()
            ) { Text(stringResource(R.string.confirm)) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) }
        }
    )
}

@Composable
private fun SectionHeader(title: String) {
    Text(
        text = title,
        style = MaterialTheme.typography.titleMedium,
        color = MaterialTheme.colorScheme.primary,
        fontWeight = FontWeight.Black,
        modifier = Modifier.padding(start = 4.dp, top = 16.dp, bottom = 8.dp)
    )
}

@Composable
private fun SettingItem(
    icon: @Composable () -> Unit,
    title: String,
    supporting: String,
    trailing: @Composable () -> Unit,
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier.fillMaxWidth(),
        shape = androidx.compose.foundation.shape.RoundedCornerShape(16.dp),
        colors = androidx.compose.material3.CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainerLow
        )
    ) {
        ListItem(
            leadingContent = icon,
            headlineContent = { 
                Text(
                    text = title,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold
                ) 
            },
            supportingContent = { 
                Text(
                    text = supporting,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                ) 
            },
            trailingContent = trailing,
            colors = androidx.compose.material3.ListItemDefaults.colors(
                containerColor = androidx.compose.ui.graphics.Color.Transparent
            )
        )
    }
}
