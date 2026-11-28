package com.aerobox.core.logging

import android.app.ApplicationExitInfo
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test

class DiagnosticsTest {
    @Test fun systemKillsAreRecordedWithoutCallingThemCrashes() {
        assertEquals("process exit [low memory]", describeProcessExit(ApplicationExitInfo.REASON_LOW_MEMORY, 0))
        assertEquals("process exit [signal]", describeProcessExit(ApplicationExitInfo.REASON_SIGNALED, 9))
        assertEquals("process exit [user requested]", describeProcessExit(ApplicationExitInfo.REASON_USER_REQUESTED, 0))
        assertEquals("process exit [permission change]", describeProcessExit(ApplicationExitInfo.REASON_PERMISSION_CHANGE, 0))
        assertNull(describeProcessExit(ApplicationExitInfo.REASON_EXIT_SELF, 0))
        assertEquals("crash [native]", describeProcessExit(ApplicationExitInfo.REASON_CRASH_NATIVE, 11))
    }

    @Test fun runtimeErrorsAreRedactedBeforeEnteringPersistentStorage() = runBlocking {
        RuntimeLogBuffer.clear()
        RuntimeLogBuffer.appendError("Start failed: password=my-secret token=private-token https://user:pass@example.com/private?token=hidden")
        val message = RuntimeLogBuffer.lines.value.single().message
        listOf("my-secret", "private-token", "user:pass", "private?", "hidden").forEach {
            assertFalse("Sensitive value persisted: $it", message.contains(it))
        }
        RuntimeLogBuffer.clear()
    }

    @Test fun quotedCredentialsInValidationErrorsAreAlsoRedacted() = runBlocking {
        RuntimeLogBuffer.clear()
        RuntimeLogBuffer.appendError("""Invalid config: {"password":"secret with spaces", "token":"escaped\"value"}, passwd='another secret'""")
        val message = RuntimeLogBuffer.lines.value.single().message
        listOf("secret with spaces", "escaped", "another secret").forEach {
            assertFalse("Sensitive value persisted: $it", message.contains(it))
        }
        RuntimeLogBuffer.clear()
    }

    @Test fun rustLogEnvelopeKeepsOnlyRedactedErrors() = runBlocking {
        RuntimeLogBuffer.clear()
        RuntimeLogBuffer.appendCore("INFO [2026-11-28T16:00:00.000 INFO shoes::tun] service ready")
        RuntimeLogBuffer.appendCore("WARN [2026-11-28T16:00:00.000 WARN shoes::tun] transient warning")
        RuntimeLogBuffer.appendCore("ERROR [2026-11-28T16:00:00.000 ERROR shoes::tun] tunnel failed password=private-secret")
        val message = RuntimeLogBuffer.lines.value.single().message
        assertTrue(message.contains("ERROR shoes::tun] tunnel failed"))
        assertFalse(message.contains("private-secret"))
        RuntimeLogBuffer.clear()
    }
}
