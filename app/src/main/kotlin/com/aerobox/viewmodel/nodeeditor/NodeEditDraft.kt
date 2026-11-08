package com.aerobox.viewmodel.nodeeditor

import com.aerobox.R
import com.aerobox.core.config.ConfigGenerator
import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.ProxyType
import java.util.Base64
import java.util.UUID
import org.json.JSONArray
import org.json.JSONObject

data class NodeEditDraft(
    val original: ProxyNode,
    val edits: Map<String, String> = emptyMap(),
    val sourceFingerprint: String = NodeDraftStore.fingerprint(original)
) {
    fun value(field: NodeEditField): String = edits[field.key] ?: field.read(original)
    fun change(key: String, value: String): NodeEditDraft {
        val field = requireNotNull(NodeEditFields.byKey[key])
        return copy(edits = if (value == field.read(original)) edits - key else edits + (key to value))
    }
    val changed: Boolean get() = edits.isNotEmpty()
    fun node(): ProxyNode = NodeEditFields.all.fold(original) { current, field ->
        edits[field.key]?.let { field.write(current, it) } ?: current
    }

    fun errors(): Map<String, Int> {
        val node = node()
        return buildMap {
            NodeEditFields.all.filter { it.visible(node) }.forEach { field ->
                val raw = value(field)
                val value = raw.trim()
                val required = when (field.key) {
                    "name", "server", "port", "uuid", "method", "alterId" -> true
                    "username" -> node.type == ProxyType.NAIVE
                    "password" -> node.type !in setOf(ProxyType.SOCKS, ProxyType.HTTP)
                    "obfsPassword" -> !node.obfsType.isNullOrBlank()
                    else -> false
                }
                val error = when {
                    required && value.isEmpty() -> R.string.node_edit_required
                    field.key == "port" && (value.toIntOrNull() ?: 0) !in 1..65535 -> R.string.node_edit_invalid_port
                    field.input == EditorInput.NUMBER && value.isNotEmpty() &&
                        (value.toIntOrNull() == null || value.toIntOrNull()!! < 0) -> R.string.node_edit_invalid_number
                    field.key == "server" && (value.any(Char::isWhitespace) || value.any { it in "/?#@" }) -> R.string.node_edit_invalid_server
                    // VMess/VLESS also accept arbitrary IDs, which the core maps to UUIDv5.
                    field.key == "uuid" && node.type == ProxyType.TUIC && value.isNotEmpty() && !validUuid(value) -> R.string.node_edit_invalid_uuid
                    field.key in setOf("transportHeaders", "naiveExtraHeaders") && !validHeaders(value) -> R.string.node_edit_invalid_headers
                    field.key == "publicKey" && value.isNotEmpty() && !validRealityKey(value) -> R.string.node_edit_invalid_public_key
                    field.key == "shortId" && value.isNotEmpty() &&
                        (value.length > 16 || value.length % 2 != 0 || !value.all { it in "0123456789abcdefABCDEF" }) -> R.string.node_edit_invalid_short_id
                    field.key == "sni" && !node.publicKey.isNullOrBlank() && value.isBlank() &&
                        ConfigGenerator.isIpLiteral(node.server.trim()) -> R.string.error_reality_requires_sni
                    field.key == "serverPorts" && !validPorts(value) -> R.string.node_edit_invalid_ports
                    else -> null
                }
                if (error != null) put(field.key, error)
            }
        }
    }

    private fun validUuid(value: String) = runCatching {
        val uuid = value.removePrefix("urn:uuid:").removeSurrounding("{", "}")
        (uuid.length == 32 && uuid.all { it in "0123456789abcdefABCDEF" }) ||
            UUID.fromString(uuid).toString().equals(uuid, ignoreCase = true)
    }.getOrDefault(false)

    private fun validRealityKey(value: String) = runCatching {
        Base64.getUrlDecoder().decode(value).size == 32
    }.getOrDefault(false)

    private fun validHeaders(value: String): Boolean {
        if (value.isEmpty()) return true
        if (value.startsWith("{")) return runCatching {
            val headers = JSONObject(value)
            headers.keys().asSequence().all { key ->
                val v = headers.get(key)
                validHeaderName(key) && (v is String || (v is JSONArray && (0 until v.length()).all { v.get(it) is String }))
            }
        }.getOrDefault(false)
        return value.replace("\r\n", "\n").replace('\r', '\n').split('\n', ';').filter(String::isNotBlank).all { line ->
            val separator = line.indexOfFirst { it == ':' || it == '=' }
            separator > 0 && validHeaderName(line.substring(0, separator).trim()) &&
                line.substring(separator + 1).isNotBlank()
        }
    }

    private fun validHeaderName(value: String) = value.isNotEmpty() && value.all {
        it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it in "!#$%&'*+-.^_`|~"
    }

    private fun validPorts(value: String): Boolean = value.isBlank() || value.split(',').all { part ->
        val ports = part.trim().split(':', '-').map(String::trim)
        ports.size in 1..2 && ports.all { (it.toIntOrNull() ?: 0) in 1..65535 } &&
            (ports.size == 1 || ports[0].toInt() <= ports[1].toInt())
    }
}
