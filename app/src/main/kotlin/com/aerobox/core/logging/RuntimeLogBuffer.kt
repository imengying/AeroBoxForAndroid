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
    private val uuidRegex = Regex(
        """\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"""
    )
    private val urlRegex = Regex("""https?://[^\s]+""")
    private val hostPortRegex = Regex("""\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d{1,5})?\b""")
    private val ipv4PortRegex = Regex("""\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b""")
    private val bracketIpv6Regex = Regex("""\[[0-9A-Fa-f:%.]+\](?::\d{1,5})?""")

    private val _lines = MutableStateFlow<List<RuntimeLogEntry>>(emptyList())
    val lines: StateFlow<List<RuntimeLogEntry>> = _lines.asStateFlow()

    fun append(level: String, message: String) {
        val normalizedMessage = sanitize(message.trim())
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

    private fun sanitize(message: String): String {
        if (message.isBlank()) return message
        return message
            .replace(urlRegex, "[url]")
            .replace(uuidRegex, "[uuid]")
            .replace(bracketIpv6Regex, "[ipv6]")
            .replace(ipv4PortRegex, "[ipv4]")
            .replace(hostPortRegex, "[host]")
    }
}
