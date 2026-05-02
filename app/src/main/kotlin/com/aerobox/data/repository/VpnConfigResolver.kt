package com.aerobox.data.repository

import android.content.Context
import android.util.Log
import com.aerobox.AeroBoxApplication
import com.aerobox.R
import com.aerobox.core.config.ConfigGenerator
import com.aerobox.core.errors.LocalizedException
import com.aerobox.core.geo.GeoAssetManager
import com.aerobox.core.logging.RuntimeLogBuffer
import com.aerobox.core.network.NodeAddressFamilyResolver
import com.aerobox.core.native.SingBoxNative
import com.aerobox.data.model.ProxyNode
import com.aerobox.utils.PreferenceManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext

class VpnConfigResolver(private val context: Context) {
    companion object {
        private const val TAG = "VpnConfigResolver"
    }

    private val nodeDao = AeroBoxApplication.database.proxyNodeDao()
    private val subscriptionRepository get() = AeroBoxApplication.subscriptionRepository

    suspend fun resolveSelectedNode(): ProxyNode? {
        val selectedId = PreferenceManager.lastSelectedNodeIdFlow(context).first()
        val allNodes = nodeDao.getAllNodes().first()
        allNodes.firstOrNull { it.id == selectedId }?.let { return it }
        if (selectedId > 0L) {
            return null
        }
        val fallbackNode = allNodes.firstOrNull() ?: return null
        if (fallbackNode.id > 0L) {
            PreferenceManager.setLastSelectedNodeId(context, fallbackNode.id)
        }
        return fallbackNode
    }

    suspend fun resolveNodeForAction(node: ProxyNode): ProxyNode? {
        subscriptionRepository.resolveNode(node)?.let { return it }
        nodeDao.getNodeById(node.id)?.let { return it }
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

    suspend fun buildConfig(
        node: ProxyNode,
        preferencesOverride: PreferenceManager.VpnConfigPreferences? = null
    ): String {
        val nodeName = node.name.ifBlank { "unnamed node" }
        Log.i(TAG, "Generating config for $nodeName [${node.type.name}]")
        RuntimeLogBuffer.append("info", "Generating config for $nodeName [${node.type.name}]")
        val prefs = preferencesOverride ?: PreferenceManager.readVpnConfigPreferences(context)
        if (prefs.enableGeoRules) {
            if (!GeoAssetManager.ensureRuleSetAssets(context)) {
                val msg = context.getString(R.string.error_rule_set_unavailable)
                Log.e(TAG, msg)
                RuntimeLogBuffer.append("error", msg)
                throw LocalizedException.of(R.string.error_rule_set_unavailable)
            }
        } else {
            withContext(Dispatchers.IO) {
                GeoAssetManager.ensureBundledAssets(context)
            }
        }
        val geoIpCnRuleSetPath = if (prefs.enableGeoRules) {
            GeoAssetManager
                .getGeoIpFile(context)
                .takeIf { it.exists() && it.length() > 0L }
                ?.absolutePath
        } else {
            null
        }
        val geoSiteCnRuleSetPath = if (prefs.enableGeoRules) {
            GeoAssetManager
                .getGeoSiteFile(context)
                .takeIf { it.exists() && it.length() > 0L }
                ?.absolutePath
        } else {
            null
        }
        val geoSiteAdsRuleSetPath = if (prefs.enableGeoRules) {
            GeoAssetManager
                .getGeoAdsFile(context)
                .takeIf { it.exists() && it.length() > 0L }
                ?.absolutePath
        } else {
            null
        }
        val nodeIsIpv6Only = NodeAddressFamilyResolver.isIpv6Only(node)

        val config = ConfigGenerator.generateSingBoxConfig(
            node = node,
            routingMode = prefs.routingMode,
            remoteDns = prefs.remoteDns,
            directDns = prefs.directDns,
            enableSocksInbound = prefs.enableSocksInbound,
            enableHttpInbound = prefs.enableHttpInbound,
            ipv6Mode = prefs.ipv6Mode,
            enableGeoCnDomainRule = prefs.enableGeoRules && prefs.enableGeoCnDomainRule,
            enableGeoCnIpRule = prefs.enableGeoRules && prefs.enableGeoCnIpRule,
            enableGeoAdsBlock = prefs.enableGeoRules && prefs.enableGeoAdsBlock,
            enableGeoBlockQuic = prefs.enableGeoRules && prefs.enableGeoBlockQuic,
            geoIpCnRuleSetPath = geoIpCnRuleSetPath,
            geoSiteCnRuleSetPath = geoSiteCnRuleSetPath,
            geoSiteAdsRuleSetPath = geoSiteAdsRuleSetPath,
            nodeIsIpv6OnlyOverride = nodeIsIpv6Only
        )
        return config
    }

    fun validateConfig(config: String): String? {
        val error = SingBoxNative.checkConfig(config)
        if (error != null) {
            Log.e(TAG, "Config check failed: $error")
            RuntimeLogBuffer.append("error", "Config check failed: $error")
        }
        return error
    }
}
