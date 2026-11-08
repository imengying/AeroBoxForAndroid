package com.aerobox.service

import com.aerobox.AeroBoxApplication
import com.aerobox.data.model.ProxyNode
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.withTimeoutOrNull
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

object VpnStateManager {
    data class ServiceOperationResult(
        val success: Boolean,
        val node: ProxyNode? = null,
        val cancelled: Boolean = false,
        val error: String? = null
    )

    data class ServiceOperation(
        val id: Long,
        val result: Deferred<ServiceOperationResult>
    ) {
        suspend fun awaitResult(timeoutMillis: Long): ServiceOperationResult? =
            withTimeoutOrNull(timeoutMillis) { result.await() }
                ?: if (result.isCompleted) result.await() else null
    }

    private val store = VpnStateStore()
    val vpnState = store.state
    private val nextOperationId = AtomicLong()
    val stopRevision = AtomicLong()
    private val pendingOperations = ConcurrentHashMap<Long, CompletableDeferred<ServiceOperationResult>>()

    fun tryBeginStart(): Long? = store.tryBeginStart().also { if (it != null) refreshTile() }
    fun beginStart(): Long = store.beginStart().also { refreshTile() }
    fun beginStop(): Long = store.beginStop().also { refreshTile() }
    fun connected(generation: Long, node: ProxyNode): Boolean =
        store.connected(generation, node).also { refreshTile() }
    fun disconnected(generation: Long, error: String?, retrying: Boolean = false) {
        store.disconnected(generation, error, retrying)
        refreshTile()
    }
    fun stopped(generation: Long) { store.stopped(generation); refreshTile() }
    fun updateCurrentNode(node: ProxyNode?) { store.updateNode(node); refreshTile() }
    fun updateLastError(error: String?) { store.updateError(error) }
    fun clearLastError() { store.updateError(null) }

    private fun refreshTile() {
        runCatching { AeroBoxTileService.requestTileRefresh(AeroBoxApplication.appInstance) }
    }

    fun registerServiceOperation(): ServiceOperation {
        val id = nextOperationId.incrementAndGet()
        val result = CompletableDeferred<ServiceOperationResult>()
        pendingOperations[id] = result
        return ServiceOperation(id, result)
    }

    fun forgetServiceOperation(id: Long) {
        pendingOperations.remove(id)?.cancel()
    }

    fun reportServiceOperation(
        id: Long,
        success: Boolean,
        node: ProxyNode? = null,
        cancelled: Boolean = false,
        error: String? = null
    ) {
        pendingOperations.remove(id)?.complete(
            ServiceOperationResult(
                success = success,
                node = node,
                cancelled = cancelled,
                error = error?.takeIf { it.isNotBlank() }
            )
        )
    }

    fun updateTrafficStats(uploadSpeed: Long, downloadSpeed: Long, uploadDelta: Long, downloadDelta: Long) {
        store.updateTraffic(uploadSpeed, downloadSpeed, uploadDelta, downloadDelta)
    }

    fun resetTrafficSession() { store.resetTraffic() }
}
