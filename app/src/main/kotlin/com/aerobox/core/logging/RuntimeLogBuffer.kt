package com.aerobox.core.logging

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import java.io.File

data class RuntimeLogEntry(
    val timestamp: Long,
    val level: String,
    val message: String
)

object RuntimeLogBuffer {
    private const val MAX_LINES = 500
    private const val LOG_FILE_NAME = "runtime-events.log"
    private val uuidRegex = Regex(
        """\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"""
    )
    private val urlRegex = Regex("""https?://[^\s]+""")
    private val hostPortRegex = Regex("""\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d{1,5})?\b""")
    private val ipv4PortRegex = Regex("""\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b""")
    private val bracketIpv6Regex = Regex("""\[[0-9A-Fa-f:%.]+\](?::\d{1,5})?""")

    private val _lines = MutableStateFlow<List<RuntimeLogEntry>>(emptyList())
    val lines: StateFlow<List<RuntimeLogEntry>> = _lines.asStateFlow()

    fun initialize(context: Context) {
        clearLegacyLogFile(context)
    }

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

    private fun clearLegacyLogFile(context: Context) {
        val candidates = buildList {
            context.getExternalFilesDir("debug")?.let { add(File(it, LOG_FILE_NAME)) }
            context.filesDir?.let { add(File(File(it, "debug"), LOG_FILE_NAME)) }
        }
        candidates.forEach { file ->
            runCatching {
                if (file.exists()) {
                    file.delete()
                }
            }
        }
    }
    private fun sanitize(message: String): String {
        if (message.isBlank()) return message
        return message
            .replace(urlRegex) { maskUrl(it.value) }
            .replace(uuidRegex) { maskUuid(it.value) }
            .replace(bracketIpv6Regex) { maskBracketIpv6(it.value) }
            .replace(ipv4PortRegex) { maskIpv4(it.value) }
            .replace(hostPortRegex) { maskHost(it.value) }
    }

    // Example: https://sub.example.com/path?k=v -> https://sub.exa***.com/[path]
    private fun maskUrl(url: String): String {
        val schemeEnd = url.indexOf("://")
        if (schemeEnd < 0) return "[url]"
        val scheme = url.substring(0, schemeEnd + 3) // "https://"
        val rest = url.substring(schemeEnd + 3)
        val pathStart = rest.indexOf('/')
        val host = if (pathStart >= 0) rest.substring(0, pathStart) else rest
        return "${scheme}${maskHost(host)}/***"
    }

    // Example: 550e8400-e29b-41d4-a716-446655440000 -> 550e****
    private fun maskUuid(uuid: String): String {
        return if (uuid.length >= 4) "${uuid.substring(0, 4)}****" else "****"
    }

    // Example: [2001:db8::1]:443 -> [2001:db8:*]:443
    private fun maskBracketIpv6(raw: String): String {
        val closeBracket = raw.indexOf(']')
        if (closeBracket < 0) return "[ipv6]"
        val addr = raw.substring(1, closeBracket) // strip [ ]
        val port = if (closeBracket + 1 < raw.length) raw.substring(closeBracket + 1) else ""
        val prefix = addr.split(':').take(2).joinToString(":")
        return "[${prefix}:*]$port"
    }

    // Example: 1.2.3.4:443 -> 1.2.*.*:443
    private fun maskIpv4(raw: String): String {
        val colonIdx = raw.indexOf(':')
        val ip = if (colonIdx >= 0) raw.substring(0, colonIdx) else raw
        val port = if (colonIdx >= 0) raw.substring(colonIdx) else ""
        val parts = ip.split('.')
        return if (parts.size == 4) "${parts[0]}.${parts[1]}.*.*$port" else "[ipv4]$port"
    }

    // Example: us-east.server.example.com:443 -> us-east.ser***.com:443
    private fun maskHost(raw: String): String {
        val colonIdx = raw.indexOf(':')
        val host = if (colonIdx >= 0) raw.substring(0, colonIdx) else raw
        val port = if (colonIdx >= 0) raw.substring(colonIdx) else ""
        val labels = host.split('.')
        if (labels.size < 2) return "$host$port"
        val tld = labels.last()
        val sld = labels[labels.size - 2]
        val maskedSld = if (sld.length > 3) "${sld.substring(0, 3)}***" else "${sld}***"
        val prefix = if (labels.size > 2) labels.subList(0, labels.size - 2).joinToString(".") + "." else ""
        return "$prefix$maskedSld.$tld$port"
    }

}
