package com.aerobox.data.repository

import android.content.Context
import com.aerobox.AeroBoxApplication
import com.aerobox.core.config.ConfigGenerator
import com.aerobox.core.geo.GeoAssetManager
import com.aerobox.core.logging.RuntimeLogBuffer
import com.aerobox.core.native.SingBoxNative
import com.aerobox.data.model.ProxyNode
import com.aerobox.utils.PreferenceManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext

class VpnConfigResolver(private val context: Context) {
    private val nodeDao = AeroBoxApplication.database.proxyNodeDao()
    private val subscriptionRepository by lazy(LazyThreadSafetyMode.NONE) {
        SubscriptionRepository(context)
    }

    suspend fun resolveSelectedNode(): ProxyNode? {
        val selectedId = PreferenceManager.lastSelectedNodeIdFlow(context).first()
        val allNodes = nodeDao.getAllNodes().first()
        val node = allNodes.firstOrNull { it.id == selectedId } ?: allNodes.firstOrNull() ?: return null
        if (node.id != selectedId && node.id > 0L) {
            PreferenceManager.setLastSelectedNodeId(context, node.id)
        }
        return node
    }

    suspend fun resolveNodeForAction(
        node: ProxyNode,
        allowSelectedFallback: Boolean
    ): ProxyNode? {
        subscriptionRepository.resolveNode(node)?.let { return it }
        nodeDao.getNodeById(node.id)?.let { return it }

        if (allowSelectedFallback) {
            return resolveSelectedNode()
        }

        return node.takeIf { it.subscriptionId == 0L }
    }

    suspend fun resolveNodeById(
        nodeId: Long?,
        fallbackToSelected: Boolean = true
    ): ProxyNode? {
        if (nodeId != null && nodeId > 0L) {
            nodeDao.getNodeById(nodeId)?.let { return it }
        }
        return if (fallbackToSelected) resolveSelectedNode() else null
    }

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
        val ipv6Mode = PreferenceManager.ipv6ModeFlow(context).first()
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
            ipv6Mode = ipv6Mode,
            enableGeoCnDomainRule = enableGeoRules && enableGeoCnDomainRule,
            enableGeoCnIpRule = enableGeoRules && enableGeoCnIpRule,
            enableGeoAdsBlock = enableGeoRules && enableGeoAdsBlock,
            enableGeoBlockQuic = enableGeoRules && enableGeoBlockQuic,
            geoIpCnRuleSetPath = geoIpCnRuleSetPath,
            geoSiteCnRuleSetPath = geoSiteCnRuleSetPath,
            geoSiteAdsRuleSetPath = geoSiteAdsRuleSetPath
        )
    }

    fun validateConfig(config: String): String? {
        val error = SingBoxNative.checkConfig(config)
        if (error != null) {
            RuntimeLogBuffer.append("error", "Config check failed: $error")
        }
        return error
    }
}
