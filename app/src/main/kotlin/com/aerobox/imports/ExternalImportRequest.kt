package com.aerobox.imports

import android.content.Intent
import androidx.core.net.toUri

data class ExternalImportRequest(
    val id: Long = System.nanoTime(),
    val source: String,
    val suggestedName: String? = null
)

object ExternalImportParser {
    private val directImportSchemes = setOf(
        "https",
        "vmess",
        "vless",
        "ss",
        "trojan",
        "hysteria2",
        "hy2",
        "tuic",
        "naive",
        "naive+https",
        "naive+quic",
        "socks",
        "socks5"
    )
    private val supportedTextPrefixes = listOf("#", "//", ";", "{", "[")

    fun fromIntent(intent: Intent?): ExternalImportRequest? {
        if (intent == null) return null

        val dataString = intent.dataString
        return fromText(dataString)
    }

    fun fromText(raw: String?): ExternalImportRequest? {
        val text = raw?.trim()?.takeIf { it.isNotBlank() } ?: return null
        val parsed = runCatching { text.toUri() }.getOrNull()
        val scheme = parsed?.scheme?.lowercase()

        return when {
            scheme in directImportSchemes -> {
                ExternalImportRequest(
                    source = text,
                    suggestedName = parsed?.fragment?.takeIf { it.isNotBlank() }
                )
            }
            looksLikeRawImportContent(text) -> ExternalImportRequest(source = text)
            else -> null
        }
    }

    private fun looksLikeRawImportContent(text: String): Boolean {
        if ('\n' !in text) return false
        val trimmed = text.trimStart()
        return supportedTextPrefixes.any { trimmed.startsWith(it) } ||
            directImportSchemes.any { scheme -> "$scheme://" in trimmed.lowercase() }
    }
}
