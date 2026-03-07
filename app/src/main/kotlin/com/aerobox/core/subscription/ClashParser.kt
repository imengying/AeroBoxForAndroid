package com.aerobox.core.subscription

import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.ProxyType
import org.yaml.snakeyaml.Yaml

/**
 * Clash/Clash Meta YAML parser.
 * Only reads the `proxies:` list and maps each node into the app's internal model.
 */
object ClashParser {

    fun parseClashYaml(content: String): List<ProxyNode> {
        val root = runCatching { Yaml().load<Any?>(content) }.getOrNull() ?: return emptyList()
        val proxies = value(root, "proxies") as? List<*> ?: return emptyList()
        return proxies.mapNotNull { parseProxyItem(it as? Map<*, *>) }
    }

    fun isClashYaml(content: String): Boolean {
        return content.contains("proxies:") &&
                content.contains("- name:") &&
                (content.contains("type:") || content.contains("server:"))
    }

    private fun parseProxyItem(map: Map<*, *>?): ProxyNode? {
        if (map.isNullOrEmpty()) return null

        val name = stringValue(map, "name") ?: return null
        val typeStr = stringValue(map, "type")?.lowercase() ?: return null
        val server = stringValue(map, "server") ?: return null
        val port = intValue(map, "port") ?: return null

        val type = when (typeStr) {
            "ss", "shadowsocks" -> {
                val method = firstNonBlank(
                    stringValue(map, "cipher"),
                    stringValue(map, "method")
                ).orEmpty()
                if (method.startsWith("2022-")) ProxyType.SHADOWSOCKS_2022 else ProxyType.SHADOWSOCKS
            }
            "vmess" -> ProxyType.VMESS
            "vless" -> ProxyType.VLESS
            "trojan" -> ProxyType.TROJAN
            "hysteria2", "hy2" -> ProxyType.HYSTERIA2
            "tuic" -> ProxyType.TUIC
            "socks", "socks5" -> ProxyType.SOCKS
            "http", "https" -> ProxyType.HTTP
            else -> return null
        }

        val security = firstNonBlank(
            stringValue(map, "security"),
            if (!stringValue(map, "reality-opts", "public-key").isNullOrBlank() ||
                !stringValue(map, "reality-opts", "public_key").isNullOrBlank()) "reality" else null
        )

        val tls = when {
            type == ProxyType.TROJAN || type == ProxyType.HYSTERIA2 || type == ProxyType.TUIC -> true
            booleanValue(map, "tls") == true -> true
            security?.lowercase() in listOf("tls", "reality") -> true
            else -> false
        }

        val network = firstNonBlank(
            stringValue(map, "network"),
            stringValue(map, "net")
        ) ?: when {
            hasValue(map, "ws-opts", "path") || hasValue(map, "ws-opts", "headers", "Host") || hasValue(map, "ws-path") -> "ws"
            hasValue(map, "grpc-opts", "grpc-service-name") || hasValue(map, "grpc-service-name") -> "grpc"
            hasValue(map, "h2-opts", "path") || hasValue(map, "h2-opts", "host") -> "h2"
            hasValue(map, "http-opts", "path") || hasValue(map, "http-opts", "host") || hasValue(map, "http-opts", "headers", "Host") -> "http"
            hasValue(map, "http-upgrade-path") || hasValue(map, "http-upgrade-host") -> "httpupgrade"
            else -> null
        }
        val normalizedNetwork = normalizeNetwork(network)
        val transportPath = firstNonBlank(
            stringValue(map, "ws-opts", "path"),
            stringValue(map, "ws-path"),
            stringValue(map, "h2-opts", "path"),
            stringValue(map, "http-opts", "path"),
            stringValue(map, "http-upgrade-path"),
            stringValue(map, "path")
        )
        val transportHost = firstNonBlank(
            joinedValue(map, "ws-opts", "headers", "Host"),
            joinedValue(map, "ws-opts", "headers", "host"),
            joinedValue(map, "ws-opts", "host"),
            joinedValue(map, "h2-opts", "host"),
            joinedValue(map, "http-opts", "host"),
            joinedValue(map, "http-opts", "headers", "Host"),
            joinedValue(map, "http-opts", "headers", "host"),
            joinedValue(map, "http-upgrade-host"),
            joinedValue(map, "host")
        )
        val transportServiceName = firstNonBlank(
            stringValue(map, "grpc-opts", "grpc-service-name"),
            stringValue(map, "grpc-opts", "service-name"),
            stringValue(map, "grpc-opts", "serviceName"),
            stringValue(map, "grpc-service-name"),
            stringValue(map, "service-name"),
            stringValue(map, "serviceName"),
            if (normalizedNetwork == "grpc") transportPath else null
        )

        val insecure = booleanValue(map, "skip-cert-verify") == true
                || booleanValue(map, "allow-insecure") == true
                || booleanValue(map, "insecure") == true

        val fingerprint = firstNonBlank(
            stringValue(map, "fingerprint"),
            stringValue(map, "client-fingerprint"),
            stringValue(map, "global-client-fingerprint")
        )

        val publicKey = firstNonBlank(
            stringValue(map, "public-key"),
            stringValue(map, "pbk"),
            stringValue(map, "reality-opts", "public-key"),
            stringValue(map, "reality-opts", "public_key")
        )

        val shortId = firstNonBlank(
            stringValue(map, "short-id"),
            stringValue(map, "sid"),
            stringValue(map, "reality-opts", "short-id"),
            stringValue(map, "reality-opts", "short_id"),
            stringValue(map, "reality-opts", "shortid")
        )

        return ProxyNode(
            name = name,
            type = type,
            server = server,
            port = port,
            uuid = firstNonBlank(stringValue(map, "uuid"), stringValue(map, "id")),
            password = firstNonBlank(
                stringValue(map, "password"),
                stringValue(map, "passwd"),
                stringValue(map, "auth"),
                stringValue(map, "token")
            ),
            method = firstNonBlank(stringValue(map, "cipher"), stringValue(map, "method")),
            flow = stringValue(map, "flow"),
            security = security,
            network = normalizedNetwork,
            tls = tls,
            sni = firstNonBlank(
                stringValue(map, "sni"),
                stringValue(map, "servername"),
                stringValue(map, "server-name")
            ),
            transportHost = transportHost,
            transportPath = if (normalizedNetwork == "grpc") null else transportPath,
            transportServiceName = transportServiceName,
            alpn = joinedValue(map, "alpn"),
            fingerprint = fingerprint,
            publicKey = publicKey,
            shortId = shortId,
            packetEncoding = firstNonBlank(
                stringValue(map, "packet-encoding"),
                stringValue(map, "packet_encoding")
            ),
            username = stringValue(map, "username"),
            allowInsecure = insecure
        )
    }

    private fun value(source: Any?, vararg path: String): Any? {
        var current: Any? = source
        for (segment in path) {
            val map = current as? Map<*, *> ?: return null
            current = map.entries.firstOrNull { entry ->
                entry.key?.toString()?.equals(segment, ignoreCase = true) == true
            }?.value
        }
        return current
    }

    private fun hasValue(source: Any?, vararg path: String): Boolean {
        return value(source, *path) != null
    }

    private fun stringValue(source: Any?, vararg path: String): String? {
        return scalarString(value(source, *path))
    }

    private fun joinedValue(source: Any?, vararg path: String): String? {
        val resolved = value(source, *path)
        val parts = when (resolved) {
            is List<*> -> resolved.mapNotNull { scalarString(it) }
            else -> listOfNotNull(scalarString(resolved))
        }
            .map { it.trim() }
            .filter { it.isNotEmpty() }
        return parts.takeIf { it.isNotEmpty() }?.joinToString(",")
    }

    private fun intValue(source: Any?, vararg path: String): Int? {
        val resolved = value(source, *path) ?: return null
        return when (resolved) {
            is Number -> resolved.toInt()
            else -> resolved.toString().trim().toIntOrNull()
        }
    }

    private fun booleanValue(source: Any?, vararg path: String): Boolean? {
        val resolved = value(source, *path) ?: return null
        return when (resolved) {
            is Boolean -> resolved
            is Number -> resolved.toInt() != 0
            is String -> when (resolved.trim().lowercase()) {
                "true", "yes", "on", "1" -> true
                "false", "no", "off", "0" -> false
                else -> null
            }
            else -> null
        }
    }

    private fun scalarString(value: Any?): String? {
        return when (value) {
            null -> null
            is String -> value.trim().takeIf { it.isNotEmpty() }
            is Number, is Boolean -> value.toString()
            else -> null
        }
    }

    private fun normalizeNetwork(value: String?): String? {
        val normalized = value?.trim()?.lowercase()?.takeIf { it.isNotBlank() } ?: return null
        return when (normalized) {
            "websocket" -> "ws"
            "http-upgrade" -> "httpupgrade"
            else -> normalized
        }
    }

    private fun firstNonBlank(vararg values: String?): String? {
        return values.firstOrNull { !it.isNullOrBlank() }?.trim()?.takeIf { it.isNotEmpty() }
    }
}
