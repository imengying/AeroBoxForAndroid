package com.aerobox.ui.screens

import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Refresh
import com.aerobox.ui.icons.AppIcons
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.aerobox.R
import com.aerobox.data.model.IPv6Mode
import com.aerobox.ui.components.AppSnackbarHost
import com.aerobox.ui.components.SectionHeader
import com.aerobox.ui.components.SettingItem
import com.aerobox.utils.AppLocaleManager
import com.aerobox.utils.findComponentActivity
import com.aerobox.viewmodel.SettingsViewModel
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch

@Composable
fun SettingsScreen(
    onNavigateToSubscriptions: () -> Unit = {},
    onNavigateToPerAppProxy: () -> Unit = {},
    onNavigateToRouting: () -> Unit = {},
    onNavigateToLog: () -> Unit = {},
    onNavigateToLicense: () -> Unit = {},
    viewModel: SettingsViewModel = viewModel(
        viewModelStoreOwner = requireNotNull(LocalView.current.context.findComponentActivity()) {
            "SettingsScreen requires a ComponentActivity"
        }
    )
) {
    val context = LocalContext.current
    val activity = requireNotNull(LocalView.current.context.findComponentActivity()) {
        "SettingsScreen requires a ComponentActivity"
    }
    val languageTag by viewModel.languageTag.collectAsStateWithLifecycle()
    val dynamicColor by viewModel.dynamicColor.collectAsStateWithLifecycle()
    val autoConnect by viewModel.autoConnect.collectAsStateWithLifecycle()
    val routingMode by viewModel.routingMode.collectAsStateWithLifecycle()
    val remoteDns by viewModel.remoteDns.collectAsStateWithLifecycle()
    val directDns by viewModel.directDns.collectAsStateWithLifecycle()
    val perAppProxyEnabled by viewModel.perAppProxyEnabled.collectAsStateWithLifecycle()
    val enableSocksInbound by viewModel.enableSocksInbound.collectAsStateWithLifecycle()
    val enableHttpInbound by viewModel.enableHttpInbound.collectAsStateWithLifecycle()
    val ipv6Mode by viewModel.ipv6Mode.collectAsStateWithLifecycle()
    val autoReconnect by viewModel.autoReconnect.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()
    val snackbarHostState = remember { SnackbarHostState() }

    var showDnsDialog by remember { mutableStateOf(false) }
    var showLanguageDialog by remember { mutableStateOf(false) }
    val effectiveLanguageTag = AppLocaleManager.currentLanguageTag(activity, languageTag)

    LaunchedEffect(viewModel) {
        viewModel.uiMessage.collectLatest { message ->
            snackbarHostState.showSnackbar(message)
        }
    }

    Box(modifier = Modifier.fillMaxSize()) {
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
        // ── Subscription ──
            item { SectionHeader(title = stringResource(R.string.settings_section_subscription)) }
            item {
                SettingItem(
                    onClick = onNavigateToSubscriptions,
                    icon = { Icon(Icons.Filled.Refresh, contentDescription = null) },
                    title = stringResource(R.string.subscription_management),
                    supporting = stringResource(R.string.settings_subscription_summary),
                    trailing = { Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, contentDescription = null) }
                )
            }

        // ── Routing ──
        item { SectionHeader(title = stringResource(R.string.settings_section_routing)) }
        item {
            SettingItem(
                onClick = onNavigateToRouting,
                icon = { Icon(AppIcons.Route, contentDescription = null) },
                title = stringResource(R.string.settings_routing_title),
                supporting = stringResource(
                    R.string.settings_routing_summary_format,
                    stringResource(routingMode.labelResId)
                ),
                trailing = { Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, contentDescription = null) }
            )
        }

        // ── Per-App Proxy ──
        item { SectionHeader(title = stringResource(R.string.settings_section_per_app)) }
        item {
            SettingItem(
                icon = { Icon(AppIcons.Apps, contentDescription = null) },
                title = stringResource(R.string.settings_per_app_enable),
                supporting = stringResource(
                    if (perAppProxyEnabled) R.string.settings_per_app_enabled
                    else R.string.settings_per_app_disabled
                ),
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
                    icon = { Icon(AppIcons.Apps, contentDescription = null) },
                    title = stringResource(R.string.settings_per_app_config_title),
                    supporting = stringResource(R.string.settings_per_app_config_summary),
                    trailing = { Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, contentDescription = null) }
                )
            }
        }

        // ── Appearance ──
        item { SectionHeader(title = stringResource(R.string.appearance)) }
        item {
            SettingItem(
                icon = { Icon(AppIcons.ColorLens, contentDescription = null) },
                title = stringResource(R.string.dynamic_color),
                supporting = stringResource(R.string.settings_dynamic_color_summary),
                trailing = {
                    Switch(checked = dynamicColor, onCheckedChange = { scope.launch { viewModel.setDynamicColor(it) } })
                }
            )
        }
        item {
            var expanded by remember { mutableStateOf(false) }
            val themeSystemText = context.getString(R.string.settings_theme_system)
            val themeDarkText = context.getString(R.string.settings_theme_dark)
            val themeLightText = context.getString(R.string.settings_theme_light)
            SettingItem(
                onClick = { expanded = true },
                icon = { Icon(AppIcons.DarkMode, contentDescription = null) },
                title = stringResource(R.string.dark_mode),
                trailing = {
                    Box {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.KeyboardArrowRight,
                            contentDescription = null,
                            tint = androidx.compose.material3.MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        androidx.compose.material3.DropdownMenu(
                            expanded = expanded,
                            onDismissRequest = { expanded = false }
                        ) {
                            androidx.compose.material3.DropdownMenuItem(
                                text = { Text(themeSystemText) },
                                onClick = { scope.launch { viewModel.setDarkMode("system") }; expanded = false }
                            )
                            androidx.compose.material3.DropdownMenuItem(
                                text = { Text(themeDarkText) },
                                onClick = { scope.launch { viewModel.setDarkMode("on") }; expanded = false }
                            )
                            androidx.compose.material3.DropdownMenuItem(
                                text = { Text(themeLightText) },
                                onClick = { scope.launch { viewModel.setDarkMode("off") }; expanded = false }
                            )
                        }
                    }
                }
            )
        }
        item {
            val currentLanguageLabel = AppLocaleManager.supportedLanguages
                .firstOrNull { it.tag == effectiveLanguageTag }
                ?.labelResId
                ?: R.string.settings_language_system
            SettingItem(
                onClick = { showLanguageDialog = true },
                icon = { Icon(AppIcons.Translate, contentDescription = null) },
                title = stringResource(R.string.settings_language),
                supporting = stringResource(currentLanguageLabel),
                trailing = { Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, contentDescription = null) }
            )
        }

        // ── DNS ──
        item { SectionHeader(title = stringResource(R.string.settings_section_dns)) }
        item {
            SettingItem(
                onClick = { showDnsDialog = true },
                icon = { Icon(AppIcons.Dns, contentDescription = null) },
                title = stringResource(R.string.settings_dns_server),
                supporting = stringResource(R.string.settings_dns_summary),
                trailing = { Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, contentDescription = null) }
            )
        }

        // ── Inbound ──
        item { SectionHeader(title = stringResource(R.string.settings_section_inbound)) }
        item {
            SettingItem(
                icon = { Icon(AppIcons.Input, contentDescription = null) },
                title = stringResource(R.string.settings_inbound_socks5),
                supporting = stringResource(R.string.settings_inbound_port_format, 2080),
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
                icon = { Icon(AppIcons.Input, contentDescription = null) },
                title = stringResource(R.string.settings_inbound_http),
                supporting = stringResource(R.string.settings_inbound_port_format, 2081),
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
                supporting = stringResource(R.string.settings_auto_connect_summary),
                trailing = {
                    Switch(checked = autoConnect, onCheckedChange = { scope.launch { viewModel.setAutoConnect(it) } })
                }
            )
        }
        item {
            SettingItem(
                icon = { Icon(AppIcons.Public, contentDescription = null) },
                title = stringResource(R.string.enable_ipv6),
                supporting = stringResource(R.string.settings_ipv6_summary),
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
                icon = { Icon(AppIcons.Autorenew, contentDescription = null) },
                title = stringResource(R.string.settings_auto_reconnect),
                supporting = stringResource(R.string.settings_auto_reconnect_summary),
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
                icon = { Icon(AppIcons.Description, contentDescription = null) },
                title = stringResource(R.string.settings_log),
                supporting = stringResource(R.string.settings_log_summary),
                trailing = { Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, contentDescription = null) }
            )
        }
        item {
            SettingItem(
                onClick = {
                    activity.startActivity(
                        Intent(
                            Intent.ACTION_VIEW,
                            Uri.parse("https://github.com/imengying/AeroBoxForAndroid/releases/latest")
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
                    icon = { Icon(AppIcons.Description, contentDescription = null) },
                    title = stringResource(R.string.open_source_licenses),
                    supporting = stringResource(R.string.settings_about_supporting),
                    trailing = { Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, contentDescription = null) }
                )
            }
        }

        AppSnackbarHost(
            hostState = snackbarHostState,
            modifier = Modifier.align(Alignment.BottomCenter)
        )
    }

    // DNS dialog
    if (showDnsDialog) {
        DnsSettingsDialog(
            remoteDns = remoteDns,
            directDns = directDns,
            titleText = context.getString(R.string.dns_dialog_title),
            remoteLabelText = context.getString(R.string.dns_label_remote),
            remoteExampleText = context.getString(R.string.dns_dialog_remote_example),
            directLabelText = context.getString(R.string.dns_label_direct),
            directExampleText = context.getString(R.string.dns_dialog_direct_example),
            confirmText = context.getString(R.string.confirm),
            cancelText = context.getString(R.string.cancel),
            resetText = context.getString(R.string.dns_dialog_reset),
            onDismiss = { showDnsDialog = false },
            onReset = {
                scope.launch {
                    viewModel.resetDnsServers()
                }
                showDnsDialog = false
            },
            onConfirm = { remote, direct ->
                scope.launch {
                    viewModel.setDnsServers(remote, direct)
                }
                showDnsDialog = false
            }
        )
    }

    if (showLanguageDialog) {
        LanguageSettingsDialog(
            selectedLanguageTag = effectiveLanguageTag,
            titleText = context.getString(R.string.settings_language),
            confirmText = context.getString(R.string.confirm),
            cancelText = context.getString(R.string.cancel),
            languageOptions = AppLocaleManager.supportedLanguages.map { language ->
                language.tag to context.getString(language.labelResId)
            },
            onDismiss = { showLanguageDialog = false },
            onConfirm = { selectedTag ->
                scope.launch {
                    val normalized = AppLocaleManager.normalize(selectedTag)
                    val applied = AppLocaleManager.apply(activity, normalized)
                    viewModel.setLanguageTag(
                        if (applied || android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.TIRAMISU) {
                            normalized
                        } else {
                            AppLocaleManager.SYSTEM_LANGUAGE_TAG
                        }
                    )
                    showLanguageDialog = false
                }
            }
        )
    }



}

@OptIn(androidx.compose.foundation.layout.ExperimentalLayoutApi::class)
@Composable
private fun LanguageSettingsDialog(
    selectedLanguageTag: String,
    titleText: String,
    confirmText: String,
    cancelText: String,
    languageOptions: List<Pair<String, String>>,
    onDismiss: () -> Unit,
    onConfirm: (String) -> Unit
) {
    var selected by remember(selectedLanguageTag) {
        mutableStateOf(AppLocaleManager.normalize(selectedLanguageTag))
    }

    AlertDialog(
        modifier = Modifier.width(320.dp),
        onDismissRequest = onDismiss,
        title = { Text(titleText) },
        text = {
            androidx.compose.foundation.layout.FlowRow(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                languageOptions.forEach { (tag, label) ->
                    FilterChip(
                        selected = selected == tag,
                        onClick = { selected = tag },
                        label = { Text(label) }
                    )
                }
            }
        },
        confirmButton = {
            TextButton(onClick = { onConfirm(selected) }) {
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

@Composable
private fun DnsSettingsDialog(
    remoteDns: String,
    directDns: String,
    titleText: String,
    remoteLabelText: String,
    remoteExampleText: String,
    directLabelText: String,
    directExampleText: String,
    confirmText: String,
    cancelText: String,
    resetText: String,
    onDismiss: () -> Unit,
    onReset: () -> Unit,
    onConfirm: (remote: String, direct: String) -> Unit
) {
    var remote by remember { mutableStateOf(remoteDns) }
    var direct by remember { mutableStateOf(directDns) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(titleText) },
        text = {
            Column {
                OutlinedTextField(
                    value = remote,
                    onValueChange = { remote = it },
                    label = { Text(remoteLabelText) },
                    supportingText = { Text(remoteExampleText) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = direct,
                    onValueChange = { direct = it },
                    label = { Text(directLabelText) },
                    supportingText = { Text(directExampleText) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = { onConfirm(remote.trim(), direct.trim()) },
                enabled = remote.isNotBlank() && direct.isNotBlank()
            ) { Text(confirmText) }
        },
        dismissButton = {
            Row {
                TextButton(onClick = onReset) { Text(resetText) }
                TextButton(onClick = onDismiss) { Text(cancelText) }
            }
        }
    )
}
