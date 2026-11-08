package com.aerobox.service

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class VpnTrafficMonitorTest {
    @Test fun missedSampleKeepsTheBaselineAndCounterResetNeverProducesNegativeTraffic() = runTest {
        val counters = ArrayDeque(listOf(TrafficCounters(100, 200), null, TrafficCounters(300, 600), TrafficCounters(10, 20)))
        val samples = mutableListOf<TrafficSample>()
        val monitor = VpnTrafficMonitor({ counters.removeFirst() }, {}, { testScheduler.currentTime }, { true })
        monitor.start(backgroundScope, { true }, { sample, _ -> samples += sample }, { fail("Unexpected health failure") })
        runCurrent()
        repeat(3) { advanceTimeBy(1_000); runCurrent() }
        assertEquals(TrafficSample(0, 0, 0, 0), samples[0])
        assertEquals(TrafficSample(100, 200, 200, 400), samples[1])
        assertEquals(TrafficSample(0, 0, 0, 0), samples[2])
        monitor.stop()
    }

    @Test fun fiveConsecutiveFailuresReportOneHealthFailureAndStopPolling() = runTest {
        var calls = 0
        var failures = 0
        var closes = 0
        val monitor = VpnTrafficMonitor({ if (calls++ == 0) TrafficCounters(0, 0) else null },
            { closes++ }, { testScheduler.currentTime }, { true })
        monitor.start(backgroundScope, { true }, { _, _ -> }, { failures++ })
        runCurrent()
        advanceTimeBy(5_000); runCurrent()
        assertEquals(1, failures)
        assertEquals(6, calls)
        advanceTimeBy(60_000); runCurrent()
        assertEquals(6, calls)
        monitor.stop()
        assertEquals(1, closes)
    }

    @Test fun successfulSamplesResetTheFailureCount() = runTest {
        var calls = 0
        var failures = 0
        val monitor = VpnTrafficMonitor({ if (calls++ % 5 == 0) TrafficCounters(0, 0) else null },
            {}, { testScheduler.currentTime }, { true })
        monitor.start(backgroundScope, { true }, { _, _ -> }, { failures++ })
        runCurrent()
        advanceTimeBy(12_000); runCurrent()
        assertEquals(0, failures)
        monitor.stop()
    }

    @Test fun screenWakeInterruptsSlowPollingAndStopPreventsFurtherSamples() = runTest {
        var interactive = false
        var calls = 0
        var closes = 0
        val samples = mutableListOf<Boolean>()
        val monitor = VpnTrafficMonitor({ calls++; TrafficCounters(0, 0) }, { closes++ },
            { testScheduler.currentTime }, { interactive })
        monitor.start(backgroundScope, { true }, { _, screenOn -> samples += screenOn }, { fail("Unexpected health failure") })
        runCurrent()
        advanceTimeBy(14_000); runCurrent()
        assertEquals(1, calls)
        interactive = true
        monitor.screenChanged()
        runCurrent()
        assertEquals(listOf(true), samples)
        monitor.stop()
        advanceTimeBy(30_000); runCurrent()
        assertEquals(2, calls)
        assertEquals(1, closes)
    }
}
