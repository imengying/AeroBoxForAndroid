package com.aerobox.ui.screens

import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.Refresh
import com.aerobox.ui.icons.AppIcons
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.foundation.layout.Row
import androidx.compose.material3.FilterChip
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
import com.aerobox.R
import com.aerobox.data.model.IPv6Mode
import com.aerobox.viewmodel.SettingsViewModel
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    onNavigateToSubscriptions: () -> Unit = {},
    onNavigateToPerAppProxy: () -> Unit = {},
    onNavigateToRouting: () -> Unit = {},
    onNavigateToLog: () -> Unit = {},
    onNavigateToLicense: () -> Unit = {},
    viewModel: SettingsViewModel = viewModel()
) {
    val context = LocalContext.current
    val darkMode by viewModel.darkMode.collectAsStateWithLifecycle()
    val dynamicColor by viewModel.dynamicColor.collectAsStateWithLifecycle()
    val autoConnect by viewModel.autoConnect.collectAsStateWithLifecycle()
    val routingMode by viewModel.routingMode.collectAsStateWithLifecycle()
    val remoteDns by viewModel.remoteDns.collectAsStateWithLifecycle()
    val localDns by viewModel.localDns.collectAsStateWithLifecycle()
    val enableDoh by viewModel.enableDoh.collectAsStateWithLifecycle()
    val perAppProxyEnabled by viewModel.perAppProxyEnabled.collectAsStateWithLifecycle()
    val enableSocksInbound by viewModel.enableSocksInbound.collectAsStateWithLifecycle()
    val enableHttpInbound by viewModel.enableHttpInbound.collectAsStateWithLifecycle()
    val ipv6Mode by viewModel.ipv6Mode.collectAsStateWithLifecycle()
    val autoReconnect by viewModel.autoReconnect.collectAsStateWithLifecycle()
    val enableGeoRules by viewModel.enableGeoRules.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()

    var showDnsDialog by remember { mutableStateOf(false) }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        // ── Subscription ──
        item { SectionHeader(title = "订阅管理") }
        item {
            SettingItem(
                onClick = onNavigateToSubscriptions,
                icon = { Icon(Icons.Filled.Refresh, contentDescription = null) },
                title = "订阅管理",
                supporting = "添加、更新和管理订阅",
                trailing = { Icon(Icons.Filled.KeyboardArrowRight, contentDescription = null) }
            )
        }

        // ── Routing ──
        item { SectionHeader(title = "路由") }
        item {
            SettingItem(
                onClick = onNavigateToRouting,
                icon = { Icon(AppIcons.Security, contentDescription = null) },
                title = "路由",
                supporting = "当前模式 · ${routingMode.displayName}",
                trailing = { Icon(Icons.Filled.KeyboardArrowRight, contentDescription = null) }
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
                    onClick = onNavigateToPerAppProxy,
                    icon = { Icon(AppIcons.Speed, contentDescription = null) },
                    title = "配置应用列表",
                    supporting = "选择哪些应用走代理/绕过代理",
                    trailing = { Icon(Icons.Filled.KeyboardArrowRight, contentDescription = null) }
                )
            }
        }

        // ── Appearance ──
        item { SectionHeader(title = stringResource(R.string.appearance)) }
        item {
            SettingItem(
                icon = { Icon(AppIcons.ColorLens, contentDescription = null) },
                title = stringResource(R.string.dynamic_color),
                supporting = "使用系统动态取色",
                trailing = {
                    Switch(checked = dynamicColor, onCheckedChange = { scope.launch { viewModel.setDynamicColor(it) } })
                }
            )
        }
        item {
            SettingItem(
                icon = { Icon(AppIcons.DarkMode, contentDescription = null) },
                title = stringResource(R.string.dark_mode),
                supporting = when (darkMode) {
                    "on" -> "深色"
                    "off" -> "浅色"
                    else -> "系统"
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
                            label = { Text("深色") }
                        )
                        FilterChip(
                            selected = darkMode == "off",
                            onClick = { scope.launch { viewModel.setDarkMode("off") } },
                            label = { Text("浅色") }
                        )
                    }
                }
            )
        }

        // ── DNS ──
        item { SectionHeader(title = "DNS 设置") }
        item {
            SettingItem(
                onClick = { showDnsDialog = true },
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

        // ── Inbound ──
        item { SectionHeader(title = "入站设置") }
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
                icon = { Icon(AppIcons.Speed, contentDescription = null) },
                title = stringResource(R.string.enable_ipv6),
                supporting = "启用 IPv6 网络支持",
                trailing = {
                    Switch(
                        checked = ipv6Mode == IPv6Mode.ENABLE,
                        onCheckedChange = { enabled ->
                            scope.launch {
                                viewModel.setIPv6Mode(if (enabled) IPv6Mode.ENABLE else IPv6Mode.DISABLE)
                            }
                        }
                    )
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
                onClick = onNavigateToLog,
                icon = { Icon(Icons.Filled.Info, contentDescription = null) },
                title = "运行日志",
                supporting = "查看 sing-box 运行日志",
                trailing = { Icon(Icons.Filled.KeyboardArrowRight, contentDescription = null) }
            )
        }
        item {
            SettingItem(
                onClick = {
                    context.startActivity(
                        Intent(
                            Intent.ACTION_VIEW,
                            Uri.parse("https://github.com/imengying/AeroBoxForAndroid")
                        )
                    )
                },
                icon = { Icon(Icons.Filled.Info, contentDescription = null) },
                title = stringResource(R.string.version),
                supporting = "${com.aerobox.BuildConfig.VERSION_NAME} (sing-box ${com.aerobox.core.native.SingBoxNative.getVersion()})",
                trailing = {}
            )
        }
        item {
            SettingItem(
                onClick = onNavigateToLicense,
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
                    supportingText = { Text("示例: tls://1.1.1.1, https://cloudflare-dns.com/dns-query") },
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
    onClick: (() -> Unit)? = null,
    enabled: Boolean = true,
    modifier: Modifier = Modifier
) {
    val shape = androidx.compose.foundation.shape.RoundedCornerShape(16.dp)
    val colors = androidx.compose.material3.CardDefaults.cardColors(
        containerColor = MaterialTheme.colorScheme.surfaceContainerLow
    )

    if (onClick != null) {
        Card(
            onClick = onClick,
            enabled = enabled,
            modifier = modifier.fillMaxWidth(),
            shape = shape,
            colors = colors
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
    } else {
        Card(
            modifier = modifier.fillMaxWidth(),
            shape = shape,
            colors = colors
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
}
