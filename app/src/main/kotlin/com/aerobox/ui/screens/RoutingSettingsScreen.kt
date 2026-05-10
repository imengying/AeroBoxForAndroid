package com.aerobox.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
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
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.aerobox.R
import com.aerobox.core.geo.GeoAssetManager
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
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    var geoUpdating by remember { mutableStateOf(false) }
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

            item { SectionHeader(title = stringResource(R.string.routing_section_resources)) }
            item {
                val hasFiles = GeoAssetManager.hasLocalFiles(context)
                val geoIpSize = GeoAssetManager.getGeoIpSize(context)
                val geoSiteSize = GeoAssetManager.getGeoSiteSize(context)
                val geoAdsSize = GeoAssetManager.getGeoAdsSize(context)
                val routingAssetsUpdatedMessage = stringResource(R.string.routing_assets_updated)
                val routingAssetsFailedFormat = stringResource(R.string.routing_assets_failed_format)
                SettingItem(
                    onClick = {
                        if (!geoUpdating) {
                            geoUpdating = true
                            scope.launch {
                                val result = GeoAssetManager.updateAll(context)
                                geoUpdating = false
                                val message = if (result.allOk) {
                                    routingAssetsUpdatedMessage
                                } else {
                                    val failed = buildList {
                                        if (!result.geoIpOk) add("GeoIP")
                                        if (!result.geoSiteCnOk) add("GeoSite-CN")
                                        if (!result.geoAdsOk) add("GeoAds")
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
}
