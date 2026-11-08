package com.aerobox.data.model

data class TrafficStats(
    val uploadSpeed: Long = 0,
    val downloadSpeed: Long = 0,
    val totalUpload: Long = 0,
    val totalDownload: Long = 0
)

enum class VpnPhase { IDLE, STARTING, CONNECTED, STOPPING, FAILED }

data class VpnState(
    val phase: VpnPhase = VpnPhase.IDLE,
    val serviceActive: Boolean = false,
    val lastError: String? = null,
    val generation: Long = 0L,
    val currentNode: ProxyNode? = null,
    val connectionTime: Long = 0,
    val traffic: TrafficStats = TrafficStats()
) {
    val isConnected: Boolean get() = phase == VpnPhase.CONNECTED
}
