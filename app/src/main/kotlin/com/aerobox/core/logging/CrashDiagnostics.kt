package com.aerobox.core.logging

import android.app.ActivityManager
import android.app.ApplicationExitInfo
import android.content.Context
import android.os.Build
import android.os.Process
import android.system.OsConstants
import android.util.AtomicFile
import android.util.Log
import com.aerobox.BuildConfig
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.math.abs
import kotlin.system.exitProcess

object CrashDiagnostics {
    private const val TAG = "CrashDiagnostics"
    private const val MAX_REPORTS = 3
    private const val MAX_MESSAGE_CHARS = 4096
    private const val MAX_FILE_BYTES = 64 * 1024
    private val historyMutex = Mutex()
    private val recordingCrash = AtomicBoolean(false)
    private lateinit var context: Context
    private lateinit var historyFile: AtomicFile
    private lateinit var pendingFile: AtomicFile
    private var lastExitTimestamp = 0L
    @Volatile
    private var coreVersion = "unknown"
    private val _entries = MutableStateFlow<List<RuntimeLogEntry>>(emptyList())
    val entries = _entries.asStateFlow()

    private data class Report(val timestamp: Long, val pid: Int, val message: String) {
        fun toJson(): JSONObject = JSONObject()
            .put("timestamp", timestamp)
            .put("pid", pid)
            .put("message", message)
    }

    @Synchronized
    fun install(context: Context, scope: CoroutineScope) {
        if (this::context.isInitialized) return
        this.context = context.applicationContext
        val directory = File(context.applicationInfo.dataDir, "no_backup/crash-diagnostics")
        historyFile = AtomicFile(File(directory, "history.json"))
        pendingFile = AtomicFile(File(directory, "pending-jvm.json"))
        val previousHandler = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, error ->
            try {
                if (recordingCrash.compareAndSet(false, true)) {
                    writeJson(
                        pendingFile,
                        Report(System.currentTimeMillis(), Process.myPid(), summarizeJvmCrash(error)).toJson()
                    )
                }
            } catch (_: Throwable) {
                // Diagnostics must never replace the original crash or prevent process termination.
            } finally {
                if (previousHandler != null) {
                    previousHandler.uncaughtException(thread, error)
                } else {
                    Process.killProcess(Process.myPid())
                    exitProcess(10)
                }
            }
        }
        scope.launch(Dispatchers.IO) {
            historyMutex.withLock {
                runCatching { restoreReports() }.onFailure {
                    Log.w(TAG, "Unable to restore crash summaries", it)
                }
            }
        }
    }

    // Called on IO before and after native initialization. Android attaches this to exit records.
    fun setCoreVersion(version: String) {
        coreVersion = safeVersion(version)
        runCatching {
            checkNotNull(context.getSystemService(ActivityManager::class.java))
                .setProcessStateSummary(versionSummary().toByteArray(Charsets.UTF_8))
        }.onFailure { Log.w(TAG, "Unable to attach crash version metadata", it) }
    }

    suspend fun clear() = withContext(Dispatchers.IO) {
        historyMutex.withLock {
            val clearedAt = maxOf(lastExitTimestamp, System.currentTimeMillis())
            saveHistory(emptyList(), clearedAt)
            pendingFile.delete()
            lastExitTimestamp = clearedAt
            _entries.value = emptyList()
        }
    }

    private fun restoreReports() {
        val saved = readJson(historyFile)
        lastExitTimestamp = saved?.optLong("lastExitTimestamp") ?: 0L
        val savedReports = saved?.optJSONArray("reports") ?: JSONArray()
        val storedReports = (0 until minOf(savedReports.length(), MAX_REPORTS))
            .mapNotNull { readReport(savedReports.optJSONObject(it)) }
        val reports = storedReports.toMutableList()
        val pending = readReport(readJson(pendingFile))
        if (pending != null && pending.timestamp > lastExitTimestamp) reports += pending

        val exits = runCatching {
            checkNotNull(context.getSystemService(ActivityManager::class.java))
                .getHistoricalProcessExitReasons(context.packageName, 0, 8)
        }.getOrElse {
            Log.w(TAG, "Unable to read process exit history", it)
            emptyList()
        }
        for (exit in exits) {
            if (exit.timestamp <= lastExitTimestamp || exit.processName != context.packageName) continue
            val source = when (exit.reason) {
                ApplicationExitInfo.REASON_CRASH -> "JVM"
                ApplicationExitInfo.REASON_CRASH_NATIVE -> "native"
                ApplicationExitInfo.REASON_ANR -> "ANR"
                ApplicationExitInfo.REASON_EXIT_SELF -> if (exit.status != 0) "nonzero process exit" else null
                ApplicationExitInfo.REASON_SIGNALED -> when (exit.status) {
                    OsConstants.SIGABRT, OsConstants.SIGSEGV, OsConstants.SIGBUS,
                    OsConstants.SIGILL, OsConstants.SIGFPE -> "native signal"
                    else -> null
                }
                else -> null
            } ?: continue
            // Prefer our JVM stack summary over the system's duplicate record of the same exit.
            if (reports.any { it.pid == exit.pid && abs(it.timestamp - exit.timestamp) < 60_000L }) continue
            val versions = exit.processStateSummary?.toString(Charsets.UTF_8)?.take(128)
                ?: "Version metadata unavailable"
            reports += Report(
                exit.timestamp, exit.pid,
                "Previous crash [$source]\n$versions\nreason=${exit.reason}, status=${exit.status}"
            )
        }
        val retained = reports.distinctBy { it.timestamp to it.pid }
            .sortedByDescending { it.timestamp }.take(MAX_REPORTS)
        val seen = maxOf(lastExitTimestamp, exits.maxOfOrNull { it.timestamp } ?: 0L)
        if (retained != storedReports || seen != lastExitTimestamp) {
            saveHistory(retained, seen)
        }
        pendingFile.delete()
        lastExitTimestamp = seen
        _entries.value = retained.asReversed().map { RuntimeLogEntry(it.timestamp, it.message) }
    }

    private fun summarizeJvmCrash(error: Throwable): String = buildString {
        append("Previous crash [JVM]\n")
        append(versionSummary())
        var cause: Throwable? = error
        repeat(4) {
            val current = cause ?: return@buildString
            append('\n')
            append(current.javaClass.name.take(256))
            // Only structural stack data: exception messages may contain URLs, passwords or config.
            current.stackTrace.take(10).forEach { frame ->
                append("\n  at ")
                append(frame.toString().take(256))
            }
            cause = current.cause?.takeUnless { it === current }
        }
    }.take(MAX_MESSAGE_CHARS)

    private fun versionSummary(): String =
        "app=${safeVersion(BuildConfig.VERSION_NAME)}, code=${BuildConfig.VERSION_CODE}, " +
            "core=$coreVersion, api=${Build.VERSION.SDK_INT}"

    private fun safeVersion(value: String): String = value.filter {
        it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it in ".+-_"
    }.take(32).ifBlank { "unknown" }

    private fun readReport(json: JSONObject?): Report? {
        json ?: return null
        val timestamp = json.optLong("timestamp")
        val message = json.optString("message").take(MAX_MESSAGE_CHARS)
        if (timestamp <= 0L || message.isBlank()) return null
        return Report(timestamp, json.optInt("pid"), message)
    }

    private fun readJson(file: AtomicFile): JSONObject? = runCatching {
        file.openRead().use { input ->
            if (input.channel.size() > MAX_FILE_BYTES) return@use null
            JSONObject(input.bufferedReader(Charsets.UTF_8).readText())
        }
    }.getOrNull()

    private fun saveHistory(reports: List<Report>, seen: Long) {
        val array = JSONArray()
        reports.forEach { array.put(it.toJson()) }
        writeJson(historyFile, JSONObject().put("lastExitTimestamp", seen).put("reports", array))
    }

    private fun writeJson(file: AtomicFile, json: JSONObject) {
        val bytes = json.toString().toByteArray(Charsets.UTF_8)
        check(bytes.size <= MAX_FILE_BYTES) { "Crash summary exceeds size limit" }
        val output = file.startWrite()
        try {
            output.write(bytes)
            file.finishWrite(output)
        } catch (error: Throwable) {
            file.failWrite(output)
            throw error
        }
    }
}
