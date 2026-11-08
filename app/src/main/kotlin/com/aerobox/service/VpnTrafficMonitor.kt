package com.aerobox.service

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull

internal data class TrafficCounters(val upload: Long, val download: Long)
internal data class TrafficSample(
    val uploadSpeed: Long,
    val downloadSpeed: Long,
    val uploadDelta: Long,
    val downloadDelta: Long
)

/** Polls the native traffic API; lifecycle decisions and UI updates belong to its caller. */
internal class VpnTrafficMonitor(
    private val query: (logErrors: Boolean) -> TrafficCounters?,
    private val closeQuery: () -> Unit,
    private val clock: () -> Long,
    private val isInteractive: () -> Boolean
) {
    private var job: Job? = null
    private val screenChanges = Channel<Unit>(Channel.CONFLATED)

    fun screenChanged() { screenChanges.trySend(Unit) }

    suspend fun stop() {
        val previous = job
        job = null
        previous?.cancel()
        // A JNI query must be interrupted before joining its coroutine.
        closeQuery()
        previous?.join()
    }

    fun start(
        scope: CoroutineScope,
        serviceActive: () -> Boolean,
        onSample: (TrafficSample, interactive: Boolean) -> Unit,
        onUnavailable: () -> Unit
    ) {
        check(job == null) { "Stop the previous traffic monitor before starting another" }
        job = scope.launch {
            var previous = initialCounters() ?: TrafficCounters(0L, 0L)
            var previousTime = clock()
            var failures = 0
            while (isActive && serviceActive()) {
                withTimeoutOrNull(if (isInteractive()) 1_000L else 15_000L) { screenChanges.receive() }
                val current = query(true)
                currentCoroutineContext().ensureActive()
                if (current == null) {
                    if (++failures >= 5) {
                        onUnavailable()
                        return@launch
                    }
                    // Retain both the byte and time baseline across failed samples.
                    onSample(TrafficSample(0, 0, 0, 0), isInteractive())
                    continue
                }
                failures = 0
                val now = clock()
                val elapsed = (now - previousTime).coerceAtLeast(1L)
                val uploaded = (current.upload - previous.upload).coerceAtLeast(0L)
                val downloaded = (current.download - previous.download).coerceAtLeast(0L)
                onSample(
                    TrafficSample(uploaded * 1_000L / elapsed, downloaded * 1_000L / elapsed, uploaded, downloaded),
                    isInteractive()
                )
                previous = current
                previousTime = now
            }
        }
    }

    private suspend fun initialCounters(): TrafficCounters? {
        repeat(6) { attempt ->
            currentCoroutineContext().ensureActive()
            val stats = query(attempt == 5)
            if (stats != null) return stats
            delay(250)
        }
        return null
    }
}
