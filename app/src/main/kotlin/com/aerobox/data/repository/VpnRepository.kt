package com.aerobox.data.repository

import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat
import com.aerobox.core.config.ConfigGenerator
import com.aerobox.core.geo.GeoAssetManager
import com.aerobox.core.logging.RuntimeLogBuffer
import com.aerobox.core.native.SingBoxNative
import com.aerobox.data.model.ProxyNode
import com.aerobox.service.AeroBoxVpnService
import com.aerobox.utils.PreferenceManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext

class VpnRepository(private val context: Context) {
    val isRunning: StateFlow<Boolean> = AeroBoxVpnService.isRunning

    fun startVpn(config: String, nodeId: Long? = null) {
        val intent = Intent(context, AeroBoxVpnService::class.java).apply {
            action = AeroBoxVpnService.ACTION_START
            putExtra(AeroBoxVpnService.EXTRA_CONFIG, config)
            if (nodeId != null && nodeId > 0L) {
                putExtra(AeroBoxVpnService.EXTRA_NODE_ID, nodeId)
            }
        }
        ContextCompat.startForegroundService(context, intent)
    }

    fun stopVpn() {
        val intent = Intent(context, AeroBoxVpnService::class.java).apply {
            action = AeroBoxVpnService.ACTION_STOP
        }
        context.startService(intent)
    }

    /**
     * Validate config via libbox. Returns null if valid, error message otherwise.
     */
    fun checkConfig(config: String): String? {
        val error = SingBoxNative.checkConfig(config)
        if (error != null) {
            RuntimeLogBuffer.append("error", "Config check failed: $error")
        }
        return error
    }

    /**
     * Build a sing-box config JSON string for the given node,
     * reading all user preferences (routing, DNS, IPv6, geo paths, etc.).
     */
    suspend fun buildConfig(node: ProxyNode): String {
        RuntimeLogBuffer.append(
            "info",
            "Generating config for ${node.name.ifBlank { "unnamed node" }}"
        )
        withContext(Dispatchers.IO) {
            GeoAssetManager.ensureBundledAssets(context)
        }

        val routingMode = PreferenceManager.routingModeFlow(context).first()
        val remoteDns = PreferenceManager.remoteDnsFlow(context).first()
        val localDns = PreferenceManager.localDnsFlow(context).first()
        val enableDoh = PreferenceManager.enableDohFlow(context).first()
        val enableSocksInbound = PreferenceManager.enableSocksInboundFlow(context).first()
        val enableHttpInbound = PreferenceManager.enableHttpInboundFlow(context).first()
        val enableIPv6 = PreferenceManager.enableIPv6Flow(context).first()
        val enableGeoRules = PreferenceManager.enableGeoRulesFlow(context).first()
        val enableGeoCnDomainRule = PreferenceManager.enableGeoCnDomainRuleFlow(context).first()
        val enableGeoCnIpRule = PreferenceManager.enableGeoCnIpRuleFlow(context).first()
        val enableGeoAdsBlock = PreferenceManager.enableGeoAdsBlockFlow(context).first()
        val enableGeoBlockQuic = PreferenceManager.enableGeoBlockQuicFlow(context).first()

        val geoIpCnRuleSetPath = if (enableGeoRules) {
            GeoAssetManager
                .getGeoIpFile(context)
                .takeIf { it.exists() && it.length() > 0L }
                ?.absolutePath
        } else {
            null
        }
        val geoSiteCnRuleSetPath = if (enableGeoRules) {
            GeoAssetManager
                .getGeoSiteFile(context)
                .takeIf { it.exists() && it.length() > 0L }
                ?.absolutePath
        } else {
            null
        }
        val geoSiteAdsRuleSetPath = if (enableGeoRules) {
            GeoAssetManager
                .getGeoAdsFile(context)
                .takeIf { it.exists() && it.length() > 0L }
                ?.absolutePath
        } else {
            null
        }

        return ConfigGenerator.generateSingBoxConfig(
            node = node,
            routingMode = routingMode,
            remoteDns = remoteDns,
            localDns = localDns,
            enableDoh = enableDoh,
            enableSocksInbound = enableSocksInbound,
            enableHttpInbound = enableHttpInbound,
            enableIPv6 = enableIPv6,
            enableGeoCnDomainRule = enableGeoRules && enableGeoCnDomainRule,
            enableGeoCnIpRule = enableGeoRules && enableGeoCnIpRule,
            enableGeoAdsBlock = enableGeoRules && enableGeoAdsBlock,
            enableGeoBlockQuic = enableGeoRules && enableGeoBlockQuic,
            geoIpCnRuleSetPath = geoIpCnRuleSetPath,
            geoSiteCnRuleSetPath = geoSiteCnRuleSetPath,
            geoSiteAdsRuleSetPath = geoSiteAdsRuleSetPath
        )
    }
}
