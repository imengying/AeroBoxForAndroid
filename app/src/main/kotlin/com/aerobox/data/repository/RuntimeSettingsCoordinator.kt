package com.aerobox.data.repository

import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.VpnState
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

data class RuntimeSettingsResult(
    val applied: Boolean,
    val reloaded: Boolean = false,
    val failure: VpnConnectionResult? = null
)

/** Owns the save/reload/compensate transaction shared by all settings entry points. */
class RuntimeSettingsCoordinator(
    private val mutex: Mutex,
    private val state: () -> VpnState,
    private val stopRevision: () -> Long,
    private val reload: suspend (ProxyNode, Long) -> VpnConnectionResult,
    private val reportRestoreFailure: (VpnConnectionResult) -> Unit
) {
    suspend fun <T> update(
        readCurrent: suspend () -> T,
        persist: suspend (T) -> Unit,
        transform: suspend (T) -> T
    ): RuntimeSettingsResult = mutex.withLock {
        val revision = stopRevision()
        val activeNode = state().takeIf { it.isConnected }?.currentNode
        val previous = readCurrent()
        val updated = transform(previous)
        if (previous == updated) return@withLock RuntimeSettingsResult(applied = true)

        var compensationStarted = false
        suspend fun compensate() = withContext(NonCancellable) {
            if (compensationStarted) return@withContext
            compensationStarted = true
            // A user stop keeps the new preference for the next connection.
            if (stopRevision() != revision) return@withContext
            persist(previous)
            if (activeNode != null && !state().isConnected && stopRevision() == revision) {
                val restored = try {
                    reload(activeNode, revision)
                } catch (error: Exception) {
                    VpnConnectionResult.Failure(error)
                }
                if (restored !is VpnConnectionResult.Success) reportRestoreFailure(restored)
            }
        }

        try {
            persist(updated)
            if (activeNode == null || stopRevision() != revision) {
                return@withLock RuntimeSettingsResult(applied = true)
            }
            val result = reload(activeNode, revision)
            when {
                stopRevision() != revision ||
                    (result is VpnConnectionResult.Failure && result.throwable is CancellationException) ->
                    RuntimeSettingsResult(applied = true)
                result is VpnConnectionResult.Success -> RuntimeSettingsResult(applied = true, reloaded = true)
                else -> {
                    compensate()
                    RuntimeSettingsResult(applied = false, failure = result)
                }
            }
        } catch (error: Exception) {
            try {
                compensate()
            } catch (rollbackError: Exception) {
                error.addSuppressed(rollbackError)
            }
            throw error
        }
    }
}
