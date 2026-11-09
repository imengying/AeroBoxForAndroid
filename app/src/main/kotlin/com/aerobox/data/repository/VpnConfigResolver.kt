package com.aerobox.data.repository

import android.content.Context
import android.util.Log
import com.aerobox.data.database.ProxyNodeDao
import com.aerobox.R
import com.aerobox.core.config.ConfigGenerator
import com.aerobox.core.errors.LocalizedException
import com.aerobox.core.geo.GeoAssetManager
import com.aerobox.core.logging.RuntimeLogBuffer
import com.aerobox.core.native.SingBoxNative
import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.RoutingMode
import com.aerobox.utils.PreferenceManager
import kotlinx.coroutines.flow.first

class VpnConfigResolver(
    private val context: Context,
    private val nodeDao: ProxyNodeDao
) {
    companion object {
        private const val TAG = "VpnConfigResolver"
    }

    suspend fun resolveSelectedNode(): ProxyNode? {
        val selectedId = PreferenceManager.lastSelectedNodeIdFlow(context).first()
        if (selectedId > 0L) nodeDao.getNodeById(selectedId)?.let { return it }
        val fallbackNode = nodeDao.getFirstNode() ?: return null
        if (fallbackNode.id > 0L) {
            PreferenceManager.setLastSelectedNodeId(context, fallbackNode.id)
        }
        return fallbackNode
    }

    suspend fun resolveNodeById(nodeId: Long?): ProxyNode? {
        if (nodeId != null && nodeId > 0L) {
            nodeDao.getNodeById(nodeId)?.let { return it }
        }
        return resolveSelectedNode()
    }

    suspend fun buildConfig(node: ProxyNode): String {
        val nodeName = node.name.ifBlank { "unnamed node" }
        Log.i(TAG, "Generating config for $nodeName [${node.type.name}]")
        val prefs = PreferenceManager.readVpnConfigPreferences(context)
        val useGeo = prefs.enableGeoRules && prefs.routingMode == RoutingMode.RULE_BASED
        val targets = GeoAssetManager.GeoUpdateTargets(
            geoIpCn = useGeo && prefs.enableGeoCnIpRule,
            geoSiteCn = useGeo && prefs.enableGeoCnDomainRule,
            geoAds = useGeo && prefs.enableGeoAdsBlock
        )
        if (targets.hasAny) {
            if (!GeoAssetManager.ensureRuleSetAssets(context, targets)) {
                val msg = context.getString(R.string.error_rule_set_unavailable)
                Log.e(TAG, msg)
                RuntimeLogBuffer.appendError(msg)
                throw LocalizedException.of(R.string.error_rule_set_unavailable)
            }
        }
        val geoIpCnRuleSetPath = if (targets.geoIpCn) {
            GeoAssetManager
                .getGeoIpFile(context)
                .takeIf { it.exists() && it.length() > 0L }
                ?.absolutePath
        } else {
            null
        }
        val geoSiteCnRuleSetPath = if (targets.geoSiteCn) {
            GeoAssetManager
                .getGeoSiteFile(context)
                .takeIf { it.exists() && it.length() > 0L }
                ?.absolutePath
        } else {
            null
        }
        val geoSiteAdsRuleSetPath = if (targets.geoAds) {
            GeoAssetManager
                .getGeoAdsFile(context)
                .takeIf { it.exists() && it.length() > 0L }
                ?.absolutePath
        } else {
            null
        }

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
            customRuleSets = prefs.customRuleSets,
            enableFakeDns = prefs.enableFakeDns
        )
        return config
    }

    suspend fun validateConfig(config: String): String? {
        val error = SingBoxNative.checkConfig(config)
        if (error != null) {
            Log.e(TAG, "Config check failed: $error")
            RuntimeLogBuffer.appendError("Config check failed: $error")
        }
        return error
    }
}
