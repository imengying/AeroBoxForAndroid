package com.aerobox.core.subscription

import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.ProxyType

/**
 * Lightweight Clash/ClashMeta YAML proxies parser.
 * Handles the `proxies:` section without requiring a full YAML library.
 *
 * Supports: Shadowsocks, VMess, VLESS, Trojan, Hysteria2, TUIC, WireGuard
 */
object ClashParser {

    fun parseClashYaml(content: String): List<ProxyNode> {
        val proxiesBlock = extractProxiesBlock(content)
        if (proxiesBlock.isBlank()) return emptyList()
        val items = splitProxyItems(proxiesBlock)
        return items.mapNotNull { parseProxyItem(it) }
    }

    /**
     * Detect whether the content looks like a Clash YAML config.
     */
    fun isClashYaml(content: String): Boolean {
        return content.contains("proxies:") &&
                content.contains("- name:") &&
                (content.contains("type:") || content.contains("  server:"))
    }

    // ── Extract the `proxies:` block from the full YAML ──────────────

    private fun extractProxiesBlock(content: String): String {
        val lines = content.lines()
        var inProxies = false
        val result = StringBuilder()

        for (line in lines) {
            val trimmed = line.trimStart()
            if (!inProxies) {
                if (trimmed.startsWith("proxies:")) {
                    inProxies = true
                }
                continue
            }
            // If we hit another top-level key (no leading whitespace), stop
            if (line.isNotBlank() && !line[0].isWhitespace() && !trimmed.startsWith("-") && !trimmed.startsWith("#")) {
                break
            }
            result.appendLine(line)
        }
        return result.toString()
    }

    // ── Split the block into individual proxy item strings ───────────

    private fun splitProxyItems(block: String): List<String> {
        val items = mutableListOf<String>()
        val current = StringBuilder()

        for (line in block.lines()) {
            val trimmed = line.trimStart()
            if (trimmed.startsWith("- ")) {
                if (current.isNotBlank()) {
                    items.add(current.toString())
                }
                current.clear()
                // Remove the leading "- " but keep remaining content
                val indent = line.indexOf('-')
                current.appendLine(" ".repeat(indent + 2) + trimmed.removePrefix("- "))
            } else if (trimmed.isNotBlank() && !trimmed.startsWith("#")) {
                current.appendLine(line)
            }
        }
        if (current.isNotBlank()) items.add(current.toString())
        return items
    }

    // ── Parse a single proxy item into key-value pairs ───────────────

    private fun parseProxyItem(itemYaml: String): ProxyNode? {
        val map = parseSimpleYamlMap(itemYaml)
        if (map.isEmpty()) return null

        val name = map["name"] ?: return null
        val typeStr = (map["type"] ?: return null).lowercase()
        val server = map["server"] ?: return null
        val port = map["port"]?.toIntOrNull() ?: return null

        val type = when (typeStr) {
            "ss", "shadowsocks" -> {
                val method = map["cipher"] ?: map["method"] ?: ""
                if (method.startsWith("2022-")) ProxyType.SHADOWSOCKS_2022 else ProxyType.SHADOWSOCKS
            }
            "vmess" -> ProxyType.VMESS
            "vless" -> ProxyType.VLESS
            "trojan" -> ProxyType.TROJAN
            "hysteria2", "hy2" -> ProxyType.HYSTERIA2
            "tuic" -> ProxyType.TUIC
            "wireguard", "wg" -> ProxyType.WIREGUARD
            "socks", "socks5" -> ProxyType.SOCKS
            "http", "https" -> ProxyType.HTTP
            else -> return null
        }

        val tls = when {
            type == ProxyType.TROJAN || type == ProxyType.HYSTERIA2 || type == ProxyType.TUIC -> true
            map["tls"]?.lowercase() == "true" -> true
            map["security"]?.lowercase() in listOf("tls", "reality") -> true
            else -> false
        }

        val network = map["network"] ?: map["net"] ?: when {
            map.containsKey("ws-opts") || map.containsKey("ws-path") -> "ws"
            map.containsKey("grpc-opts") || map.containsKey("grpc-service-name") -> "grpc"
            map.containsKey("h2-opts") -> "h2"
            else -> null
        }

        return ProxyNode(
            name = name,
            type = type,
            server = server,
            port = port,
            uuid = map["uuid"] ?: map["id"],
            password = map["password"] ?: map["passwd"],
            method = map["cipher"] ?: map["method"],
            flow = map["flow"],
            security = map["security"],
            network = network,
            tls = tls,
            sni = map["sni"] ?: map["servername"],
            alpn = map["alpn"],
            fingerprint = map["fingerprint"] ?: map["client-fingerprint"],
            publicKey = map["public-key"] ?: map["pbk"],
            shortId = map["short-id"] ?: map["sid"],
            username = map["username"],
            privateKey = map["private-key"],
            localAddress = map["ip"] ?: map["local-address"],
            peerPublicKey = map["public-key"] ?: map["peer-public-key"],
            preSharedKey = map["pre-shared-key"] ?: map["preshared-key"],
            reserved = map["reserved"],
            mtu = map["mtu"]?.toIntOrNull()
        )
    }

    // ── Lightweight flat YAML map parser ─────────────────────────────
    // Handles only flat key: value pairs and simple inline lists.
    // Nested maps (ws-opts, grpc-opts) are flattened with their parent key prefix.

    private fun parseSimpleYamlMap(yaml: String): Map<String, String> {
        val map = mutableMapOf<String, String>()
        var currentParentKey: String? = null
        var parentIndent = -1

        for (line in yaml.lines()) {
            val trimmed = line.trimStart()
            if (trimmed.isBlank() || trimmed.startsWith("#")) continue

            val indent = line.length - line.trimStart().length
            val colonIndex = trimmed.indexOf(':')
            if (colonIndex <= 0) continue

            val key = trimmed.substring(0, colonIndex).trim()
            val rawValue = trimmed.substring(colonIndex + 1).trim()

            // Detect nested block start (key with no value, e.g. "ws-opts:")
            if (rawValue.isEmpty()) {
                currentParentKey = key
                parentIndent = indent
                continue
            }

            val cleanValue = rawValue
                .removeSurrounding("\"")
                .removeSurrounding("'")
                .let { if (it.startsWith("[") && it.endsWith("]")) {
                    // Inline YAML array: [a, b] → "a,b"
                    it.removeSurrounding("[", "]").split(",").joinToString(",") { s -> s.trim().removeSurrounding("\"").removeSurrounding("'") }
                } else it }

            if (currentParentKey != null && indent > parentIndent) {
                // This is a child of the nested block → flatten
                map["$currentParentKey-$key"] = cleanValue
            } else {
                currentParentKey = null
                map[key] = cleanValue
            }
        }
        return map
    }
}
