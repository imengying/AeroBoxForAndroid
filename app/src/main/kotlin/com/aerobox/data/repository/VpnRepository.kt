package com.aerobox.data.repository

import android.content.Context
import android.content.Intent
import com.aerobox.AeroBoxApplication
import com.aerobox.core.config.ConfigGenerator
import com.aerobox.core.errors.LocalizedException
import com.aerobox.core.logging.RuntimeLogBuffer
import com.aerobox.core.network.NodeAddressFamilyResolver
import com.aerobox.core.native.SingBoxNative
import com.aerobox.data.model.IPv6Mode
import com.aerobox.data.model.ProxyNode
import com.aerobox.service.AeroBoxVpnService
import com.aerobox.service.VpnStateManager
import com.aerobox.utils.PreferenceManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.util.concurrent.atomic.AtomicBoolean

sealed interface VpnConnectionResult {
    data class Success(val node: ProxyNode) : VpnConnectionResult
    data object NoNodeAvailable : VpnConnectionResult
    data class InvalidConfig(val error: String) : VpnConnectionResult
    data class Failure(val throwable: Throwable) : VpnConnectionResult
}

class VpnRepository(private val context: Context) {
    companion object {
        private val backgroundRefreshScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        private val dueRefreshRunning = AtomicBoolean(false)
    }

    private val configResolver = VpnConfigResolver(context)
    private val subscriptionRepository get() = AeroBoxApplication.subscriptionRepository

    suspend fun connectSelectedNode(): VpnConnectionResult {
        val node = configResolver.resolveSelectedNode() ?: return VpnConnectionResult.NoNodeAvailable
        return connectNode(node)
    }

    suspend fun connectNode(node: ProxyNode): VpnConnectionResult {
        val result = launchNodeAction(node) { config, resolvedNode ->
            startVpn(config, resolvedNode.id)
        }
        val triggerNode = (result as? VpnConnectionResult.Success)?.node ?: node
        refreshDueSubscriptionsInBackground(triggerNode)
        return result
    }

    suspend fun switchToNode(node: ProxyNode): VpnConnectionResult {
        val currentNode = VpnStateManager.vpnState.value.currentNode
        if (currentNode != null) {
            val currentIsIpv6Only = NodeAddressFamilyResolver.isIpv6Only(currentNode)
            val targetIsIpv6Only = NodeAddressFamilyResolver.isIpv6Only(node)
            if (currentIsIpv6Only != targetIsIpv6Only) {
                RuntimeLogBuffer.append(
                    "info",
                    "Switching across FakeIP mode boundary, performing full VPN restart"
                )
                stopVpn()
                waitForServiceStop()
                return launchNodeAction(node) { config, resolvedNode ->
                    startVpn(config, resolvedNode.id)
                }
            }
        }

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

    private fun refreshDueSubscriptionsInBackground(triggerNode: ProxyNode) {
        if (!dueRefreshRunning.compareAndSet(false, true)) return

        backgroundRefreshScope.launch {
            try {
                val subscriptions = subscriptionRepository.getAllSubscriptions().first()
                val results = subscriptionRepository.refreshDueSubscriptions(subscriptions)
                val updatedSubscriptionIds = results.mapNotNull { it.getOrNull()?.subscriptionId }.toSet()
                val triggerSubscriptionId = triggerNode.subscriptionId.takeIf { it > 0L } ?: return@launch
                if (triggerSubscriptionId !in updatedSubscriptionIds) return@launch
                if (!VpnStateManager.serviceActive.value) return@launch

                RuntimeLogBuffer.append(
                    "info",
                    "Due subscription refreshed in background, reloading active connection"
                )

                when (val reloadResult = reloadActiveConnection(triggerNode)) {
                    is VpnConnectionResult.Success -> Unit
                    VpnConnectionResult.NoNodeAvailable -> {
                        RuntimeLogBuffer.append(
                            "warn",
                            "Background subscription refresh finished but no replacement node was available"
                        )
                    }
                    is VpnConnectionResult.InvalidConfig -> {
                        RuntimeLogBuffer.append(
                            "warn",
                            "Background subscription refresh reload failed: ${reloadResult.error}"
                        )
                    }
                    is VpnConnectionResult.Failure -> {
                        RuntimeLogBuffer.append(
                            "warn",
                            "Background subscription refresh reload failed: ${reloadResult.throwable.message ?: reloadResult.throwable}"
                        )
                    }
                }
            } catch (error: Throwable) {
                RuntimeLogBuffer.append(
                    "warn",
                    "Background subscription refresh failed: ${error.message ?: error}"
                )
            } finally {
                dueRefreshRunning.set(false)
            }
        }
    }

    private suspend fun launchNodeAction(
        node: ProxyNode,
        action: (String, ProxyNode) -> Unit
    ): VpnConnectionResult {
        return runCatching {
            val resolvedNode = configResolver.resolveNodeForAction(node)
                ?: return@runCatching VpnConnectionResult.NoNodeAvailable

            val config = configResolver.buildConfig(resolvedNode)
            val configError = configResolver.validateConfig(config)
            if (configError != null) {
                VpnConnectionResult.InvalidConfig(configError)
            } else {
                action(config, resolvedNode)
                VpnConnectionResult.Success(resolvedNode)
            }
        }.getOrElse { error ->
            if (error is LocalizedException) {
                VpnConnectionResult.InvalidConfig(error.resolveMessage(context))
            } else {
                VpnConnectionResult.Failure(error)
            }
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
        context.startForegroundService(intent)
    }

    fun stopVpn() {
        RuntimeLogBuffer.append("info", "Sending ACTION_STOP to VPN service")
        val intent = Intent(context, AeroBoxVpnService::class.java).apply {
            action = AeroBoxVpnService.ACTION_STOP
        }
        context.startForegroundService(intent)
    }

    private suspend fun waitForServiceStop(timeoutMs: Long = 5_000L) {
        withTimeoutOrNull(timeoutMs) {
            while (VpnStateManager.serviceActive.value) {
                delay(100)
            }
        } ?: RuntimeLogBuffer.append(
            "warn",
            "Timed out waiting for VPN service to stop before restart"
        )
    }

    suspend fun urlTestNode(
        node: ProxyNode,
        testUrl: String = "http://cp.cloudflare.com/",
        timeoutMs: Int = 5000,
        directDns: String? = null,
        ipv6Mode: IPv6Mode? = null
    ): Int {
        return withContext(Dispatchers.IO) {
            val preferences = if (directDns != null && ipv6Mode != null) {
                null
            } else {
                PreferenceManager.readVpnConfigPreferences(context)
            }
            val resolvedDirectDns = directDns ?: preferences?.directDns ?: PreferenceManager.DEFAULT_DIRECT_DNS
            val resolvedIpv6Mode = ipv6Mode ?: preferences?.ipv6Mode ?: IPv6Mode.DISABLE
            val safeDirectDns = if (resolvedDirectDns.contains("[")) {
                PreferenceManager.DEFAULT_DIRECT_DNS
            } else {
                resolvedDirectDns
            }
            val nodeIsIpv6Only = NodeAddressFamilyResolver.isIpv6Only(node)
            val config = ConfigGenerator.generateUrlTestConfig(
                node = node,
                directDns = safeDirectDns,
                ipv6Mode = resolvedIpv6Mode,
                nodeIsIpv6OnlyOverride = nodeIsIpv6Only
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
