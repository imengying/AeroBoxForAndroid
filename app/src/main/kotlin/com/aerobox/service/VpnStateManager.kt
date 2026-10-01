package com.aerobox.service

import com.aerobox.AeroBoxApplication
import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.TrafficStats
import com.aerobox.data.model.VpnState
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
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
    )

    private val _vpnState = MutableStateFlow(VpnState())
    val vpnState: StateFlow<VpnState> = _vpnState.asStateFlow()
    private val _serviceActive = MutableStateFlow(false)
    val serviceActive: StateFlow<Boolean> = _serviceActive.asStateFlow()
    private val _lastError = MutableStateFlow<String?>(null)
    val lastError: StateFlow<String?> = _lastError.asStateFlow()
    private val nextOperationId = AtomicLong()
    private val pendingOperations = ConcurrentHashMap<Long, CompletableDeferred<ServiceOperationResult>>()

    fun updateServiceActive(active: Boolean) {
        _serviceActive.value = active
        runCatching { AeroBoxTileService.requestTileRefresh(AeroBoxApplication.appInstance) }
    }

    fun updateConnectionState(isConnected: Boolean, node: ProxyNode?) {
        _vpnState.update { current ->
            current.copy(
                isConnected = isConnected,
                currentNode = if (isConnected) node else null,
                connectionTime = if (isConnected) System.currentTimeMillis() else 0L
            )
        }
        if (isConnected) {
            _lastError.value = null
        }
        runCatching { AeroBoxTileService.requestTileRefresh(AeroBoxApplication.appInstance) }
    }

    fun updateCurrentNode(node: ProxyNode?) {
        _vpnState.update { current ->
            if (!current.isConnected) current
            else current.copy(currentNode = node)
        }
        runCatching { AeroBoxTileService.requestTileRefresh(AeroBoxApplication.appInstance) }
    }

    fun updateLastError(error: String?) {
        _lastError.value = error?.takeIf { it.isNotBlank() }
    }

    fun clearLastError() {
        _lastError.value = null
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

    fun updateTrafficStats(
        uploadSpeed: Long,
        downloadSpeed: Long,
        uploadDelta: Long,
        downloadDelta: Long
    ) {
        _vpnState.update { current ->
            current.copy(
                traffic = TrafficStats(
                    uploadSpeed = uploadSpeed,
                    downloadSpeed = downloadSpeed,
                    totalUpload = (current.totalUpload + uploadDelta).coerceAtLeast(0L),
                    totalDownload = (current.totalDownload + downloadDelta).coerceAtLeast(0L)
                )
            )
        }
    }

    fun resetTrafficSession() {
        _vpnState.update { current ->
            current.copy(traffic = TrafficStats())
        }
    }
}
