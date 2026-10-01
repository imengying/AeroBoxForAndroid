package com.aerobox.data.repository

import android.content.Context
import android.content.Intent
import android.util.Log
import com.aerobox.AeroBoxApplication
import com.aerobox.core.config.ConfigGenerator
import com.aerobox.core.errors.LocalizedException
import com.aerobox.core.network.NodeAddressFamilyResolver
import com.aerobox.core.native.SingBoxNative
import com.aerobox.data.model.IPv6Mode
import com.aerobox.data.model.ProxyNode
import com.aerobox.service.AeroBoxVpnService
import com.aerobox.service.VpnStateManager
import com.aerobox.utils.PreferenceManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
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
        private const val TAG = "VpnRepository"
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
            startServiceWithAction(AeroBoxVpnService.ACTION_START, config, resolvedNode.id)
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
                stopVpn()
                waitForServiceStop()
                return launchNodeAction(node) { config, resolvedNode ->
                    startServiceWithAction(AeroBoxVpnService.ACTION_START, config, resolvedNode.id)
                }
            }
        }

        return launchNodeAction(node) { config, resolvedNode ->
            startServiceWithAction(AeroBoxVpnService.ACTION_SWITCH, config, resolvedNode.id)
        }
    }

    suspend fun reloadActiveConnection(node: ProxyNode): VpnConnectionResult {
        val operation = VpnStateManager.registerServiceOperation()
        try {
            val launchResult = launchNodeAction(node) { config, resolvedNode ->
                startServiceWithAction(AeroBoxVpnService.ACTION_RELOAD, config, resolvedNode.id, operation.id)
            }
            if (launchResult !is VpnConnectionResult.Success) return launchResult

            val result = withTimeoutOrNull(30_000L) { operation.result.await() }
                ?: return VpnConnectionResult.Failure(
                    IllegalStateException("Timed out waiting for VPN reload")
                )
            val connectedNode = result.node
            return if (result.success && connectedNode != null) {
                VpnConnectionResult.Success(connectedNode)
            } else if (result.cancelled) {
                VpnConnectionResult.Failure(CancellationException(result.error ?: "VPN reload cancelled"))
            } else {
                VpnConnectionResult.Failure(IllegalStateException(result.error ?: "VPN reload failed"))
            }
        } finally {
            VpnStateManager.forgetServiceOperation(operation.id)
        }
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
                val activeNode = VpnStateManager.vpnState.value.currentNode
                if (activeNode?.id != triggerNode.id) return@launch

                reloadActiveConnection(triggerNode)
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                Log.w(TAG, "Background subscription refresh failed", error)
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
            if (error is CancellationException) throw error
            if (error is LocalizedException) {
                VpnConnectionResult.InvalidConfig(error.resolveMessage(context))
            } else {
                VpnConnectionResult.Failure(error)
            }
        }
    }

    private fun startServiceWithAction(action: String, config: String, nodeId: Long, operationId: Long = 0L) {
        val intent = Intent(context, AeroBoxVpnService::class.java).apply {
            this.action = action
            putExtra(AeroBoxVpnService.EXTRA_CONFIG, config)
            putExtra(AeroBoxVpnService.EXTRA_NODE_ID, nodeId)
            putExtra(AeroBoxVpnService.EXTRA_OPERATION_ID, operationId)
        }
        context.startForegroundService(intent)
    }

    fun stopVpn() {
        val intent = Intent(context, AeroBoxVpnService::class.java).apply {
            action = AeroBoxVpnService.ACTION_STOP
        }
        context.startForegroundService(intent)
    }

    private suspend fun waitForServiceStop(timeoutMs: Long = 5_000L) {
        withTimeoutOrNull(timeoutMs) {
            VpnStateManager.serviceActive.first { !it }
        } ?: Log.w(
            TAG,
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
            SingBoxNative.urlTestOutbound(
                configContent = config,
                outboundTag = "proxy",
                testUrl = testUrl,
                timeoutMs = timeoutMs,
                platformInterface = AeroBoxVpnService.activePlatformInterface()
            )
        }
    }
}
