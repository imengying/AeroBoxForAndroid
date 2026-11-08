package com.aerobox.data.repository

import android.content.Context
import android.content.Intent
import android.util.Log
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
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.concurrent.atomic.AtomicBoolean

sealed interface VpnConnectionResult {
    data class Success(val node: ProxyNode) : VpnConnectionResult
    data object NoNodeAvailable : VpnConnectionResult
    data class InvalidConfig(val error: String) : VpnConnectionResult
    data class Failure(val throwable: Throwable) : VpnConnectionResult
}

class VpnRepository(
    private val context: Context,
    private val configResolver: VpnConfigResolver,
    private val subscriptionRepository: SubscriptionRepository
) {
    companion object {
        private const val TAG = "VpnRepository"
        private val backgroundRefreshScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        private val dueRefreshRunning = AtomicBoolean(false)
    }

    val runtimeSettingsMutex = Mutex()
    val runtimeSettings = RuntimeSettingsCoordinator(
        mutex = runtimeSettingsMutex,
        state = { VpnStateManager.vpnState.value },
        stopRevision = { VpnStateManager.stopRevision.get() },
        reload = ::reloadActiveConnection,
        reportRestoreFailure = { result ->
            val details = when (result) {
                is VpnConnectionResult.InvalidConfig -> result.error
                is VpnConnectionResult.Failure -> result.throwable.message
                VpnConnectionResult.NoNodeAvailable -> "current node unavailable"
                is VpnConnectionResult.Success -> null
            }
            RuntimeLogBuffer.appendError("Failed to restore VPN after rolling back settings: $details")
        }
    )

    suspend fun connectSelectedNode(): VpnConnectionResult {
        val node = configResolver.resolveSelectedNode() ?: return VpnConnectionResult.NoNodeAvailable
        return connectNode(node)
    }

    suspend fun connectNode(node: ProxyNode): VpnConnectionResult {
        val stopRevision = VpnStateManager.stopRevision.get()
        val preparation = VpnStateManager.tryBeginStart()
            ?: throw CancellationException("VPN start already in progress")
        var delivered = false
        try {
            val result = runtimeSettingsMutex.withLock {
                if (VpnStateManager.stopRevision.get() != stopRevision) {
                    throw CancellationException("VPN start cancelled")
                }
                launchNodeAction(node) { config, resolvedNode ->
                    if (VpnStateManager.stopRevision.get() != stopRevision) {
                        throw CancellationException("VPN start cancelled")
                    }
                    startServiceWithAction(AeroBoxVpnService.ACTION_START, config, resolvedNode.id, stopRevision = stopRevision)
                    delivered = true
                }
            }
            val triggerNode = (result as? VpnConnectionResult.Success)?.node ?: node
            refreshDueSubscriptionsInBackground(triggerNode)
            return result
        } finally {
            // A later service start/stop owns a newer generation and must stay intact.
            if (!delivered) VpnStateManager.stopped(preparation)
        }
    }

    suspend fun switchToNode(node: ProxyNode): VpnConnectionResult {
        val stopRevision = VpnStateManager.stopRevision.get()
        return runtimeSettingsMutex.withLock {
            if (VpnStateManager.stopRevision.get() != stopRevision) {
                VpnConnectionResult.Failure(CancellationException("VPN switch cancelled"))
            } else {
                reloadActiveConnection(node, stopRevision)
            }
        }
    }

    suspend fun reloadActiveConnection(
        node: ProxyNode,
        stopRevision: Long = VpnStateManager.stopRevision.get()
    ): VpnConnectionResult {
        val operation = VpnStateManager.registerServiceOperation()
        try {
            val launchResult = launchNodeAction(node) { config, resolvedNode ->
                check(VpnStateManager.stopRevision.get() == stopRevision) { "VPN operation cancelled" }
                startServiceWithAction(AeroBoxVpnService.ACTION_RELOAD, config, resolvedNode.id, operation.id, stopRevision)
            }
            if (launchResult !is VpnConnectionResult.Success) return launchResult

            val result = operation.awaitResult(30_000L)
            if (result == null) {
                AeroBoxVpnService.cancelStartOperation(operation.id)
                withTimeoutOrNull(5_000L) { VpnStateManager.vpnState.first { !it.serviceActive } }
                return VpnConnectionResult.Failure(
                    IllegalStateException("Timed out waiting for VPN reload")
                )
            }
            val connectedNode = result.node
            return if (result.success && connectedNode != null) {
                VpnConnectionResult.Success(connectedNode)
            } else if (result.cancelled) {
                VpnConnectionResult.Failure(CancellationException(result.error ?: "VPN reload cancelled"))
            } else {
                VpnConnectionResult.Failure(IllegalStateException(result.error ?: "VPN reload failed"))
            }
        } catch (error: CancellationException) {
            withContext(NonCancellable) { AeroBoxVpnService.cancelStartOperation(operation.id) }
            throw error
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
                if (!VpnStateManager.vpnState.value.serviceActive) return@launch
                val activeNode = VpnStateManager.vpnState.value.currentNode
                if (activeNode?.id != triggerNode.id) return@launch

                runtimeSettingsMutex.withLock {
                    if (VpnStateManager.vpnState.value.currentNode?.id == triggerNode.id) reloadActiveConnection(triggerNode)
                }
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
                RuntimeLogBuffer.appendError("VPN configuration rejected: $configError")
                VpnConnectionResult.InvalidConfig(configError)
            } else {
                action(config, resolvedNode)
                VpnConnectionResult.Success(resolvedNode)
            }
        }.getOrElse { error ->
            if (error is CancellationException) throw error
            val details = if (error is LocalizedException) error.resolveMessage(context) else error.message.orEmpty()
            RuntimeLogBuffer.appendError("Unable to prepare or launch VPN: ${error.javaClass.simpleName}: $details")
            if (error is LocalizedException) {
                VpnConnectionResult.InvalidConfig(details)
            } else {
                VpnConnectionResult.Failure(error)
            }
        }
    }

    private fun startServiceWithAction(
        action: String, config: String, nodeId: Long,
        operationId: Long = 0L, stopRevision: Long
    ) {
        val intent = Intent(context, AeroBoxVpnService::class.java).apply {
            this.action = action
            putExtra(AeroBoxVpnService.EXTRA_CONFIG, config)
            putExtra(AeroBoxVpnService.EXTRA_NODE_ID, nodeId)
            putExtra(AeroBoxVpnService.EXTRA_OPERATION_ID, operationId)
            putExtra(AeroBoxVpnService.EXTRA_STOP_REVISION, stopRevision)
        }
        try {
            context.startForegroundService(intent)
        } catch (error: Exception) {
            VpnStateManager.updateLastError(error.message ?: error.javaClass.simpleName)
            throw error
        }
    }

    fun stopVpn() {
        val stopRevision = VpnStateManager.stopRevision.incrementAndGet()
        val intent = Intent(context, AeroBoxVpnService::class.java).apply {
            action = AeroBoxVpnService.ACTION_STOP
            putExtra(AeroBoxVpnService.EXTRA_STOP_REVISION, stopRevision)
        }
        context.startForegroundService(intent)
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
            val nodeIsIpv6Only = NodeAddressFamilyResolver.isIpv6Only(node)
            val config = ConfigGenerator.generateUrlTestConfig(
                node = node,
                directDns = resolvedDirectDns,
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
