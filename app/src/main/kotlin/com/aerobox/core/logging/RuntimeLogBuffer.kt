package com.aerobox.core.logging

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

data class RuntimeLogEntry(
    val timestamp: Long,
    val level: String,
    val message: String
)

object RuntimeLogBuffer {
    private const val MAX_LINES = 500

    private val _lines = MutableStateFlow<List<RuntimeLogEntry>>(emptyList())
    val lines: StateFlow<List<RuntimeLogEntry>> = _lines.asStateFlow()

    fun append(level: String, message: String) {
        val normalizedMessage = message.trim()
        if (normalizedMessage.isEmpty()) return

        val entry = RuntimeLogEntry(
            timestamp = System.currentTimeMillis(),
            level = level.ifBlank { "info" },
            message = normalizedMessage
        )
        _lines.update { current ->
            (current + entry).takeLast(MAX_LINES)
        }
    }

    fun clear() {
        _lines.value = emptyList()
    }
}
