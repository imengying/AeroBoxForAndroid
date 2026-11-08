package com.aerobox.service

import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.TrafficStats
import com.aerobox.data.model.VpnPhase
import com.aerobox.data.model.VpnState
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.flow.updateAndGet

/** One atomic snapshot; late native results cannot overwrite a newer start or stop. */
internal class VpnStateStore(private val now: () -> Long = System::currentTimeMillis) {
    private val mutable = MutableStateFlow(VpnState())
    val state = mutable.asStateFlow()

    /** Reserve the preparation phase before configuration work can suspend. */
    fun tryBeginStart(): Long? {
        while (true) {
            val previous = mutable.value
            if (previous.serviceActive || previous.phase == VpnPhase.STOPPING) return null
            val starting = previous.copy(phase = VpnPhase.STARTING, serviceActive = true,
                lastError = null, generation = previous.generation + 1,
                currentNode = null, connectionTime = 0)
            if (mutable.compareAndSet(previous, starting)) return starting.generation
        }
    }

    fun beginStart(): Long = mutable.updateAndGet {
        it.copy(phase = VpnPhase.STARTING, serviceActive = true, lastError = null,
            generation = it.generation + 1, currentNode = null, connectionTime = 0)
    }.generation

    fun beginStop(): Long = mutable.updateAndGet {
        it.copy(phase = VpnPhase.STOPPING, generation = it.generation + 1,
            currentNode = null, connectionTime = 0)
    }.generation

    fun connected(generation: Long, node: ProxyNode): Boolean {
        val timestamp = now()
        val updated = mutable.updateAndGet {
            if (it.generation != generation || it.phase != VpnPhase.STARTING) it else
                it.copy(phase = VpnPhase.CONNECTED, serviceActive = true, currentNode = node,
                    connectionTime = timestamp, lastError = null)
        }
        return updated.generation == generation && updated.isConnected
    }

    fun disconnected(generation: Long, error: String? = null, retrying: Boolean = false) {
        mutable.update {
            if (it.generation != generation) it else it.copy(
                phase = if (retrying) VpnPhase.STARTING else VpnPhase.FAILED,
                currentNode = null, connectionTime = 0, lastError = if (retrying) null else error,
                traffic = TrafficStats()
            )
        }
    }

    fun stopped(generation: Long) {
        mutable.update {
            if (it.generation != generation) it else it.copy(
                phase = if (it.lastError == null) VpnPhase.IDLE else VpnPhase.FAILED,
                serviceActive = false, currentNode = null, connectionTime = 0, traffic = TrafficStats()
            )
        }
    }

    fun updateError(error: String?) {
        mutable.update {
            val message = error?.takeIf(String::isNotBlank)
            it.copy(lastError = message, phase = if (!it.serviceActive) {
                if (message == null) VpnPhase.IDLE else VpnPhase.FAILED
            } else it.phase)
        }
    }

    fun updateNode(node: ProxyNode?) {
        mutable.update { if (it.isConnected) it.copy(currentNode = node) else it }
    }

    fun updateTraffic(uploadSpeed: Long, downloadSpeed: Long, uploadDelta: Long, downloadDelta: Long) {
        mutable.update { if (!it.isConnected) it else it.copy(traffic = TrafficStats(uploadSpeed, downloadSpeed,
            (it.traffic.totalUpload + uploadDelta).coerceAtLeast(0L), (it.traffic.totalDownload + downloadDelta).coerceAtLeast(0L))) }
    }

    fun resetTraffic() { mutable.update { it.copy(traffic = TrafficStats()) } }
}
