package com.aerobox.data.repository

import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat
import com.aerobox.core.config.ConfigGenerator
import com.aerobox.core.logging.RuntimeLogBuffer
import com.aerobox.core.native.SingBoxNative
import com.aerobox.data.model.IPv6Mode
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
    private val configResolver = VpnConfigResolver(context)
    private val subscriptionRepository by lazy(LazyThreadSafetyMode.NONE) {
        SubscriptionRepository(context)
    }

    suspend fun connectSelectedNode(refreshDueSubscriptions: Boolean = false): VpnConnectionResult {
        val node = configResolver.resolveSelectedNode() ?: return VpnConnectionResult.NoNodeAvailable
        return connectNode(node, refreshDueSubscriptions)
    }

    suspend fun connectNode(
        node: ProxyNode,
        refreshDueSubscriptions: Boolean = false
    ): VpnConnectionResult {
        return launchNodeAction(node, refreshDueSubscriptions) { config, resolvedNode ->
            startVpn(config, resolvedNode.id)
        }
    }

    suspend fun switchToNode(node: ProxyNode): VpnConnectionResult {
        return launchNodeAction(node) { config, resolvedNode ->
            switchNode(config, resolvedNode.id)
        }
    }

    suspend fun reloadActiveConnection(node: ProxyNode): VpnConnectionResult {
        return launchNodeAction(node) { config, resolvedNode ->
            startServiceWithAction(AeroBoxVpnService.ACTION_RELOAD, config, resolvedNode.id)
        }
    }

    private fun startVpn(config: String, nodeId: Long? = null) {
        startServiceWithAction(AeroBoxVpnService.ACTION_START, config, nodeId)
    }

    private fun switchNode(config: String, nodeId: Long? = null) {
        startServiceWithAction(AeroBoxVpnService.ACTION_SWITCH, config, nodeId)
    }

    private suspend fun launchNodeAction(
        node: ProxyNode,
        refreshDueSubscriptions: Boolean = false,
        action: (String, ProxyNode) -> Unit
    ): VpnConnectionResult {
        return runCatching {
            if (refreshDueSubscriptions) {
                val subscriptions = subscriptionRepository.getAllSubscriptions().first()
                subscriptionRepository.refreshDueSubscriptions(subscriptions)
            }

            val resolvedNode = configResolver.resolveNodeForAction(
                node = node,
                allowSelectedFallback = refreshDueSubscriptions
            ) ?: return@runCatching VpnConnectionResult.NoNodeAvailable

            val config = configResolver.buildConfig(resolvedNode)
            val configError = configResolver.validateConfig(config)
            if (configError != null) {
                VpnConnectionResult.InvalidConfig(configError)
            } else {
                action(config, resolvedNode)
                VpnConnectionResult.Success(resolvedNode)
            }
        }.getOrElse { error ->
            VpnConnectionResult.Failure(error)
        }
    }

    private fun startServiceWithAction(action: String, config: String? = null, nodeId: Long? = null) {
        val intent = Intent(context, AeroBoxVpnService::class.java).apply {
            this.action = action
            config?.takeIf { it.isNotBlank() }?.let {
                putExtra(AeroBoxVpnService.EXTRA_CONFIG, it)
            }
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

    suspend fun urlTestNode(
        node: ProxyNode,
        testUrl: String = "http://cp.cloudflare.com/",
        timeoutMs: Int = 5000,
        localDns: String? = null,
        ipv6Mode: IPv6Mode? = null
    ): Int {
        return withContext(Dispatchers.IO) {
            val resolvedLocalDns = localDns ?: PreferenceManager.localDnsFlow(context).first()
            val resolvedIpv6Mode = ipv6Mode ?: PreferenceManager.ipv6ModeFlow(context).first()
            val safeLocalDns = if (resolvedLocalDns.contains("[")) "223.5.5.5" else resolvedLocalDns
            val config = ConfigGenerator.generateUrlTestConfig(
                node = node,
                localDns = safeLocalDns,
                ipv6Mode = resolvedIpv6Mode
            )
            val parseError = configResolver.validateConfig(config)
            if (parseError != null) {
                RuntimeLogBuffer.append("error", "urlTest parsing aborted: $parseError")
                return@withContext -1
            }

            val result = SingBoxNative.urlTestOutbound(
                configContent = config,
                outboundTag = "proxy",
                testUrl = testUrl,
                timeoutMs = timeoutMs
            )
            result
        }
    }
}
