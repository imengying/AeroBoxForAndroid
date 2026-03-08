package com.aerobox.data.repository

import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat
import com.aerobox.AeroBoxApplication
import com.aerobox.core.config.ConfigGenerator
import com.aerobox.core.geo.GeoAssetManager
import com.aerobox.core.logging.RuntimeLogBuffer
import com.aerobox.core.native.SingBoxNative
import com.aerobox.data.model.ProxyNode
import com.aerobox.service.AeroBoxVpnService
import com.aerobox.utils.PreferenceManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext

sealed interface VpnConnectionResult {
    data class Success(val node: ProxyNode) : VpnConnectionResult
    data object NoNodeAvailable : VpnConnectionResult
    data class InvalidConfig(val error: String) : VpnConnectionResult
    data class Failure(val throwable: Throwable) : VpnConnectionResult
}

class VpnRepository(private val context: Context) {
    private val nodeDao = AeroBoxApplication.database.proxyNodeDao()
    private val subscriptionRepository by lazy(LazyThreadSafetyMode.NONE) {
        SubscriptionRepository(context)
    }

    suspend fun connectSelectedNode(refreshDueSubscriptions: Boolean = false): VpnConnectionResult {
        val selectedId = PreferenceManager.lastSelectedNodeIdFlow(context).first()
        val allNodes = nodeDao.getAllNodes().first()
        val node = allNodes.firstOrNull { it.id == selectedId } ?: allNodes.firstOrNull()
            ?: return VpnConnectionResult.NoNodeAvailable
        return connectNode(node, refreshDueSubscriptions)
    }

    suspend fun connectNode(
        node: ProxyNode,
        refreshDueSubscriptions: Boolean = false
    ): VpnConnectionResult {
        return launchNodeAction(node, refreshDueSubscriptions) { config ->
            startVpn(config, node.id)
        }
    }

    suspend fun switchToNode(node: ProxyNode): VpnConnectionResult {
        return launchNodeAction(node) { config ->
            switchNode(config, node.id)
        }
    }

    fun startVpn(config: String, nodeId: Long? = null) {
        startServiceWithAction(AeroBoxVpnService.ACTION_START, config, nodeId)
    }

    fun switchNode(config: String, nodeId: Long? = null) {
        startServiceWithAction(AeroBoxVpnService.ACTION_SWITCH, config, nodeId)
    }

    private suspend fun launchNodeAction(
        node: ProxyNode,
        refreshDueSubscriptions: Boolean = false,
        action: (String) -> Unit
    ): VpnConnectionResult {
        return runCatching {
            if (refreshDueSubscriptions) {
                val subscriptions = subscriptionRepository.getAllSubscriptions().first()
                subscriptionRepository.refreshDueSubscriptions(subscriptions)
            }

            val config = buildConfig(node)
            val configError = checkConfig(config)
            if (configError != null) {
                VpnConnectionResult.InvalidConfig(configError)
            } else {
                action(config)
                VpnConnectionResult.Success(node)
            }
        }.getOrElse { error ->
            VpnConnectionResult.Failure(error)
        }
    }

    private fun startServiceWithAction(action: String, config: String, nodeId: Long? = null) {
        val intent = Intent(context, AeroBoxVpnService::class.java).apply {
            this.action = action
            putExtra(AeroBoxVpnService.EXTRA_CONFIG, config)
            if (nodeId != null && nodeId > 0L) {
                putExtra(AeroBoxVpnService.EXTRA_NODE_ID, nodeId)
            }
        }
        ContextCompat.startForegroundService(context, intent)
    }

    fun stopVpn() {
        RuntimeLogBuffer.append("info", "Sending ACTION_STOP to VPN service")
        val intent = Intent(context, AeroBoxVpnService::class.java).apply {
            action = AeroBoxVpnService.ACTION_STOP
        }
        context.startService(intent)
    }

    fun checkConfig(config: String): String? {
        val error = SingBoxNative.checkConfig(config)
        if (error != null) {
            RuntimeLogBuffer.append("error", "Config check failed: $error")
        }
        return error
    }

    suspend fun urlTestNode(
        node: ProxyNode,
        testUrl: String = "https://www.gstatic.com/generate_204",
        timeoutMs: Int = 3000
    ): Int {
        return withContext(Dispatchers.IO) {
            val versionBefore = SingBoxNative.getVersion()
            if (versionBefore == "unknown") {
                SingBoxNative.setup(context)
                RuntimeLogBuffer.append("debug", "SingBoxNative.setup() retried in urlTestNode")
            }
            RuntimeLogBuffer.append("debug", "SingBoxNative.version=${SingBoxNative.getVersion()}")
            val localDns = PreferenceManager.localDnsFlow(context).first()
            val config = ConfigGenerator.generateUrlTestConfig(
                node = node,
                localDns = localDns
            )
            RuntimeLogBuffer.append(
                "debug",
                "urlTest start: node=${node.name.ifBlank { "unnamed node" }}, timeout=${timeoutMs}ms"
            )
            val result = SingBoxNative.urlTestOutbound(
                configContent = config,
                outboundTag = "proxy",
                testUrl = testUrl,
                timeoutMs = timeoutMs
            )
            RuntimeLogBuffer.append(
                if (result > 0) "debug" else "warn",
                "urlTest result: node=${node.name.ifBlank { "unnamed node" }}, latency=$result"
            )
            result
        }
    }

    suspend fun buildConfig(node: ProxyNode): String {
        RuntimeLogBuffer.append(
            "info",
            "Generating config for ${node.name.ifBlank { "unnamed node" }}"
        )
        RuntimeLogBuffer.append(
            "debug",
            buildString {
                append("Node summary: ")
                append("type=").append(node.type.name)
                node.network?.takeIf { it.isNotBlank() }?.let { append(", network=").append(it) }
                append(", tls=").append(node.tls)
                node.security?.takeIf { it.isNotBlank() }?.let { append(", security=").append(it) }
                node.flow?.takeIf { it.isNotBlank() }?.let { append(", flow=").append(it) }
                node.packetEncoding?.takeIf { it.isNotBlank() }?.let { append(", packetEncoding=").append(it) }
                if (!node.publicKey.isNullOrBlank()) append(", reality=true")
                if (node.allowInsecure) append(", insecure=true")
            }
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
        val effectiveEnableIPv6 = enableIPv6 && isPureIpv6Node(node)
        val enableGeoRules = PreferenceManager.enableGeoRulesFlow(context).first()
        val enableGeoCnDomainRule = PreferenceManager.enableGeoCnDomainRuleFlow(context).first()
        val enableGeoCnIpRule = PreferenceManager.enableGeoCnIpRuleFlow(context).first()
        val enableGeoAdsBlock = PreferenceManager.enableGeoAdsBlockFlow(context).first()
        val enableGeoBlockQuic = PreferenceManager.enableGeoBlockQuicFlow(context).first()
        RuntimeLogBuffer.append(
            "debug",
            "Config options: mode=$routingMode, doh=$enableDoh, socksIn=$enableSocksInbound, " +
                "httpIn=$enableHttpInbound, ipv6Setting=$enableIPv6, ipv6Effective=$effectiveEnableIPv6, " +
                "geoRules=$enableGeoRules, cnDomain=$enableGeoCnDomainRule, cnIp=$enableGeoCnIpRule, " +
                "ads=$enableGeoAdsBlock, blockQuic=$enableGeoBlockQuic"
        )

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
            enableIPv6 = effectiveEnableIPv6,
            enableGeoCnDomainRule = enableGeoRules && enableGeoCnDomainRule,
            enableGeoCnIpRule = enableGeoRules && enableGeoCnIpRule,
            enableGeoAdsBlock = enableGeoRules && enableGeoAdsBlock,
            enableGeoBlockQuic = enableGeoRules && enableGeoBlockQuic,
            geoIpCnRuleSetPath = geoIpCnRuleSetPath,
            geoSiteCnRuleSetPath = geoSiteCnRuleSetPath,
            geoSiteAdsRuleSetPath = geoSiteAdsRuleSetPath
        )
    }

    private fun isPureIpv6Node(node: ProxyNode): Boolean {
        val host = node.server
            .trim()
            .removePrefix("[")
            .removeSuffix("]")
            .substringBefore('%')
        if (!host.contains(':')) return false
        return host.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' || it == ':' || it == '.' }
    }
}
