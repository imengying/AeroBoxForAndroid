package com.aerobox.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.aerobox.R
import com.aerobox.core.geo.GeoAssetManager
import com.aerobox.data.model.CustomRuleSet
import com.aerobox.data.model.RuleSetAction
import com.aerobox.data.model.RuleSetFormat
import com.aerobox.ui.components.AppSnackbarHost
import com.aerobox.ui.components.SectionHeader
import com.aerobox.ui.components.SettingItem
import com.aerobox.ui.icons.AppIcons
import com.aerobox.utils.findComponentActivity
import com.aerobox.viewmodel.SettingsViewModel
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RoutingSettingsScreen(
    onNavigateBack: () -> Unit,
    viewModel: SettingsViewModel = viewModel(
        viewModelStoreOwner = requireNotNull(LocalView.current.context.findComponentActivity()) {
            "RoutingSettingsScreen requires a ComponentActivity"
        }
    )
) {
    val enableGeoRules by viewModel.enableGeoRules.collectAsStateWithLifecycle()
    val enableGeoCnDomainRule by viewModel.enableGeoCnDomainRule.collectAsStateWithLifecycle()
    val enableGeoCnIpRule by viewModel.enableGeoCnIpRule.collectAsStateWithLifecycle()
    val enableGeoAdsBlock by viewModel.enableGeoAdsBlock.collectAsStateWithLifecycle()
    val enableGeoBlockQuic by viewModel.enableGeoBlockQuic.collectAsStateWithLifecycle()
    val customRuleSets by viewModel.customRuleSets.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    var geoUpdating by remember { mutableStateOf(false) }
    var editingRuleSet by remember { mutableStateOf<CustomRuleSet?>(null) }
    var showRuleDialog by remember { mutableStateOf(false) }
    val snackbarHostState = remember { SnackbarHostState() }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.routing_screen_title)) },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = null)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface
                )
            )
        },
        snackbarHost = { AppSnackbarHost(hostState = snackbarHostState) }
    ) { innerPadding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            item { SectionHeader(title = stringResource(R.string.routing_section_rules)) }
            item {
                SettingItem(
                    icon = { Icon(AppIcons.Security, contentDescription = null) },
                    title = stringResource(R.string.routing_rules_master),
                    supporting = stringResource(
                        if (enableGeoRules) R.string.routing_rules_master_on
                        else R.string.routing_rules_master_off
                    ),
                    trailing = {
                        Switch(
                            checked = enableGeoRules,
                            onCheckedChange = { scope.launch { viewModel.setEnableGeoRules(it) } }
                        )
                    }
                )
            }
            if (enableGeoRules) {
                item {
                    SettingItem(
                        icon = { Icon(AppIcons.Security, contentDescription = null) },
                        title = stringResource(R.string.routing_block_quic),
                        supporting = "network: udp + port: 443",
                        trailing = {
                            Switch(
                                checked = enableGeoBlockQuic,
                                onCheckedChange = { scope.launch { viewModel.setEnableGeoBlockQuic(it) } }
                            )
                        }
                    )
                }
                item {
                    SettingItem(
                        icon = { Icon(AppIcons.Security, contentDescription = null) },
                        title = stringResource(R.string.routing_cn_domain),
                        supporting = "rule_set: geosite-cn",
                        trailing = {
                            Switch(
                                checked = enableGeoCnDomainRule,
                                onCheckedChange = { scope.launch { viewModel.setEnableGeoCnDomainRule(it) } }
                            )
                        }
                    )
                }
                item {
                    SettingItem(
                        icon = { Icon(AppIcons.Security, contentDescription = null) },
                        title = stringResource(R.string.routing_cn_ip),
                        supporting = "rule_set: geoip-cn",
                        trailing = {
                            Switch(
                                checked = enableGeoCnIpRule,
                                onCheckedChange = { scope.launch { viewModel.setEnableGeoCnIpRule(it) } }
                            )
                        }
                    )
                }
                item {
                    SettingItem(
                        icon = { Icon(AppIcons.Security, contentDescription = null) },
                        title = stringResource(R.string.routing_block_ads),
                        supporting = "rule_set: geosite-category-ads-all",
                        trailing = {
                            Switch(
                                checked = enableGeoAdsBlock,
                                onCheckedChange = { scope.launch { viewModel.setEnableGeoAdsBlock(it) } }
                            )
                        }
                    )
                }
            }

            item { SectionHeader(title = stringResource(R.string.routing_section_custom_rules)) }
            item {
                SettingItem(
                    onClick = {
                        editingRuleSet = null
                        showRuleDialog = true
                    },
                    icon = { Icon(AppIcons.Security, contentDescription = null) },
                    title = stringResource(R.string.routing_custom_rule_add),
                    supporting = stringResource(R.string.routing_custom_rule_summary),
                    trailing = {
                        Icon(AppIcons.Add, contentDescription = null)
                    }
                )
            }
            items(customRuleSets.size, key = { customRuleSets[it].id }) { index ->
                val ruleSet = customRuleSets[index]
                val actionText = when (ruleSet.action) {
                    RuleSetAction.DIRECT -> stringResource(R.string.routing_custom_rule_action_direct)
                    RuleSetAction.PROXY -> stringResource(R.string.routing_custom_rule_action_proxy)
                    RuleSetAction.REJECT -> stringResource(R.string.routing_custom_rule_action_reject)
                }
                val formatText = when (ruleSet.format) {
                    RuleSetFormat.BINARY -> stringResource(R.string.routing_custom_rule_format_binary)
                    RuleSetFormat.SOURCE -> stringResource(R.string.routing_custom_rule_format_source)
                }
                SettingItem(
                    onClick = {
                        editingRuleSet = ruleSet
                        showRuleDialog = true
                    },
                    icon = { Icon(AppIcons.Security, contentDescription = null) },
                    title = ruleSet.name,
                    supporting = "$actionText · $formatText · ${ruleSet.url}",
                    trailing = {
                        Switch(
                            checked = ruleSet.enabled,
                            onCheckedChange = { enabled ->
                                scope.launch { viewModel.setCustomRuleSetEnabled(ruleSet, enabled) }
                            }
                        )
                    }
                )
            }

            item { SectionHeader(title = stringResource(R.string.routing_section_resources)) }
            item {
                val hasFiles = GeoAssetManager.hasLocalFiles(context)
                val geoIpSize = GeoAssetManager.getGeoIpSize(context)
                val geoSiteSize = GeoAssetManager.getGeoSiteSize(context)
                val geoAdsSize = GeoAssetManager.getGeoAdsSize(context)
                val routingAssetsUpdatedMessage = stringResource(R.string.routing_assets_updated)
                val routingAssetsFailedFormat = stringResource(R.string.routing_assets_failed_format)
                val routingAssetsNoEnabledMessage = stringResource(R.string.routing_assets_no_enabled_rules)
                SettingItem(
                    onClick = {
                        if (!geoUpdating) {
                            val targets = GeoAssetManager.GeoUpdateTargets(
                                geoIpCn = enableGeoRules && enableGeoCnIpRule,
                                geoSiteCn = enableGeoRules && enableGeoCnDomainRule,
                                geoAds = enableGeoRules && enableGeoAdsBlock
                            )
                            if (!targets.hasAny) {
                                scope.launch {
                                    snackbarHostState.showSnackbar(routingAssetsNoEnabledMessage)
                                }
                                return@SettingItem
                            }
                            geoUpdating = true
                            scope.launch {
                                val result = GeoAssetManager.updateAll(context, targets)
                                geoUpdating = false
                                val message = if (result.allOk) {
                                    routingAssetsUpdatedMessage
                                } else {
                                    val failed = buildList {
                                        if (targets.geoIpCn && !result.geoIpOk) add("GeoIP")
                                        if (targets.geoSiteCn && !result.geoSiteCnOk) add("GeoSite-CN")
                                        if (targets.geoAds && !result.geoAdsOk) add("GeoAds")
                                    }
                                    routingAssetsFailedFormat.format(failed.joinToString(", "))
                                }
                                snackbarHostState.showSnackbar(message)
                            }
                        }
                    },
                    icon = { Icon(AppIcons.Security, contentDescription = null) },
                    title = stringResource(
                        if (hasFiles) R.string.routing_assets_update
                        else R.string.routing_assets_download
                    ),
                    supporting = if (hasFiles) {
                        stringResource(
                            R.string.routing_assets_summary_format,
                            geoIpSize,
                            geoSiteSize,
                            geoAdsSize
                        )
                    } else {
                        stringResource(R.string.routing_assets_official_only)
                    },
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
        }
    }

    if (showRuleDialog) {
        CustomRuleSetDialog(
            ruleSet = editingRuleSet,
            onDismiss = { showRuleDialog = false },
            onDelete = { ruleSet ->
                scope.launch {
                    viewModel.deleteCustomRuleSet(ruleSet)
                    showRuleDialog = false
                }
            },
            onConfirm = { name, url, format, action, enabled ->
                scope.launch {
                    val saved = viewModel.saveCustomRuleSet(
                        existingId = editingRuleSet?.id,
                        name = name,
                        url = url,
                        format = format,
                        action = action,
                        enabled = enabled
                    )
                    if (saved) {
                        showRuleDialog = false
                    }
                }
            }
        )
    }
}

@OptIn(androidx.compose.foundation.layout.ExperimentalLayoutApi::class)
@Composable
private fun CustomRuleSetDialog(
    ruleSet: CustomRuleSet?,
    onDismiss: () -> Unit,
    onDelete: (CustomRuleSet) -> Unit,
    onConfirm: (name: String, url: String, format: RuleSetFormat, action: RuleSetAction, enabled: Boolean) -> Unit
) {
    var name by remember(ruleSet) { mutableStateOf(ruleSet?.name.orEmpty()) }
    var url by remember(ruleSet) { mutableStateOf(ruleSet?.url.orEmpty()) }
    var format by remember(ruleSet) { mutableStateOf(ruleSet?.format ?: RuleSetFormat.BINARY) }
    var action by remember(ruleSet) { mutableStateOf(ruleSet?.action ?: RuleSetAction.DIRECT) }
    var enabled by remember(ruleSet) { mutableStateOf(ruleSet?.enabled ?: true) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                stringResource(
                    if (ruleSet == null) R.string.routing_custom_rule_add
                    else R.string.routing_custom_rule_edit
                )
            )
        },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text(stringResource(R.string.routing_custom_rule_name)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(
                    value = url,
                    onValueChange = { url = it },
                    label = { Text(stringResource(R.string.routing_custom_rule_url)) },
                    supportingText = { Text(stringResource(R.string.routing_custom_rule_url_hint)) },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                Text(
                    text = stringResource(R.string.routing_custom_rule_action),
                    style = MaterialTheme.typography.labelLarge
                )
                androidx.compose.foundation.layout.FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    RuleSetAction.entries.forEach { option ->
                        FilterChip(
                            selected = action == option,
                            onClick = { action = option },
                            label = { Text(option.label()) }
                        )
                    }
                }
                Text(
                    text = stringResource(R.string.routing_custom_rule_format),
                    style = MaterialTheme.typography.labelLarge
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    RuleSetFormat.entries.forEach { option ->
                        FilterChip(
                            selected = format == option,
                            onClick = { format = option },
                            label = { Text(option.label()) }
                        )
                    }
                }
                SettingItem(
                    icon = { Icon(AppIcons.Security, contentDescription = null) },
                    title = stringResource(R.string.routing_custom_rule_enabled),
                    trailing = {
                        Switch(
                            checked = enabled,
                            onCheckedChange = { enabled = it }
                        )
                    }
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = { onConfirm(name, url, format, action, enabled) },
                enabled = name.isNotBlank() && url.isNotBlank()
            ) {
                Text(stringResource(R.string.save))
            }
        },
        dismissButton = {
            Row {
                if (ruleSet != null) {
                    TextButton(onClick = { onDelete(ruleSet) }) {
                        Text(stringResource(R.string.delete))
                    }
                }
                TextButton(onClick = onDismiss) {
                    Text(stringResource(R.string.cancel))
                }
            }
        }
    )
}

@Composable
private fun RuleSetAction.label(): String {
    return when (this) {
        RuleSetAction.DIRECT -> stringResource(R.string.routing_custom_rule_action_direct)
        RuleSetAction.PROXY -> stringResource(R.string.routing_custom_rule_action_proxy)
        RuleSetAction.REJECT -> stringResource(R.string.routing_custom_rule_action_reject)
    }
}

@Composable
private fun RuleSetFormat.label(): String {
    return when (this) {
        RuleSetFormat.BINARY -> stringResource(R.string.routing_custom_rule_format_binary)
        RuleSetFormat.SOURCE -> stringResource(R.string.routing_custom_rule_format_source)
    }
}
