package com.aerobox.core.subscription

import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.ProxyType
import org.json.JSONArray
import org.json.JSONObject

/**
 * JSON/SIP008-based proxy node parsers.
 *
 * Extracted from [SubscriptionParser] for maintainability.
 * Delegates to [UriNodeParser] for shared helpers.
 */
internal object JsonNodeParser {

    internal data class NodeParseBatch(
        val nodes: List<ProxyNode>,
        val diagnostics: ParseDiagnostics = ParseDiagnostics()
    )

    internal fun parseJsonContent(content: String): NodeParseBatch {
        return runCatching {
            if (content.trimStart().startsWith("[")) {
                parseJsonArray(JSONArray(content))
            } else {
                val jsonObject = JSONObject(content)
                when {
                    jsonObject.has("servers") -> parseJsonArray(jsonObject.getJSONArray("servers"))
                    jsonObject.has("outbounds") -> parseJsonArray(jsonObject.getJSONArray("outbounds"))
                    else -> parseJsonArray(JSONArray().put(jsonObject))
                }
            }
        }.getOrDefault(
            NodeParseBatch(
                nodes = emptyList(),
                diagnostics = ParseDiagnostics().withIgnored("invalid_json_content")
            )
        )
    }

    internal fun parseJsonArray(array: JSONArray): NodeParseBatch {
        val result = mutableListOf<ProxyNode>()
        var diagnostics = ParseDiagnostics()
        for (index in 0 until array.length()) {
            val obj = array.optJSONObject(index) ?: run {
                diagnostics = diagnostics.withIgnored("invalid_json_item")
                continue
            }
            val transport = obj.optJSONObject("transport")
            val multiplex = obj.optJSONObject("multiplex")
            val tlsObject = obj.optJSONObject("tls")
            val realityObject = tlsObject?.optJSONObject("reality")
            val utlsObject = tlsObject?.optJSONObject("utls")
            val echObject = tlsObject?.optJSONObject("ech") ?: obj.optJSONObject("ech")
            val obfsObject = obj.optJSONObject("obfs")
            val headersObject = obj.optJSONObject("headers")
            val udpOverTcp = UriNodeParser.parseUdpOverTcp(obj.opt("udp_over_tcp"))
            val typeRaw = obj.optString("type", obj.optString("protocol", "")).lowercase()
            val type = when {
                typeRaw.contains("shadow") -> {
                    val method = obj.optString("method")
                    if (method.startsWith("2022-")) ProxyType.SHADOWSOCKS_2022 else ProxyType.SHADOWSOCKS
                }
                typeRaw.contains("vmess") -> ProxyType.VMESS
                typeRaw.contains("vless") -> ProxyType.VLESS
                typeRaw.contains("trojan") -> ProxyType.TROJAN
                typeRaw.contains("hysteria2") || typeRaw == "hy2" -> ProxyType.HYSTERIA2
                typeRaw.contains("tuic") -> ProxyType.TUIC
                typeRaw.contains("naive") -> ProxyType.NAIVE
                typeRaw == "socks" || typeRaw == "socks5" -> ProxyType.SOCKS
                typeRaw == "http" || typeRaw == "https" -> ProxyType.HTTP
                else -> {
                    diagnostics = diagnostics.withIgnored("unsupported_json_type")
                    continue
                }
            }

            val server = obj.optString("server", obj.optString("address", ""))
            val serverPorts = UriNodeParser.firstNonBlank(
                obj.optJSONArray("server_ports")?.toCommaSeparatedString(),
                obj.optString("server_ports", "").ifBlank { null },
                obj.optJSONArray("server-ports")?.toCommaSeparatedString(),
                obj.optString("server-ports", "").ifBlank { null },
                obj.optJSONArray("ports")?.toCommaSeparatedString(),
                obj.optString("ports", "").ifBlank { null },
                obj.optString("mport", "").ifBlank { null }
            )
            val resolvedPort = obj.optInt("server_port", obj.optInt("port", -1)).takeIf { it > 0 }
                ?: (if (type == ProxyType.HYSTERIA2) UriNodeParser.firstPortFromPortList(serverPorts) else null)
                ?: (if (type == ProxyType.NAIVE) 443 else null)
            if (server.isBlank() || resolvedPort == null) {
                diagnostics = diagnostics.withIgnored("missing_json_endpoint")
                continue
            }
            val port: Int = resolvedPort
            val configuredNetwork = UriNodeParser.firstNonBlank(
                obj.optString("network", "").ifBlank { null },
                obj.optString("net", "").ifBlank { null }
            )
            val resolvedTransportType = UriNodeParser.resolveTransportType(
                rawNetwork = UriNodeParser.firstNonBlank(
                    transport?.optString("type", "")?.ifBlank { null },
                    configuredNetwork
                ),
                headerType = UriNodeParser.firstNonBlank(
                    obj.optString("headerType", "").ifBlank { null },
                    obj.optString("header_type", "").ifBlank { null }
                )
            )
            val naiveProtocol = if (type == ProxyType.NAIVE) {
                UriNodeParser.resolveNaiveProtocol(
                    typeRaw,
                    obj.optString("protocol", "").ifBlank { null },
                    obj.optString("proto", "").ifBlank { null },
                    UriNodeParser.parseBooleanOrNull(UriNodeParser.jsonScalarString(obj.opt("quic")))
                )
            } else {
                null
            }
            val transportType = if (type == ProxyType.NAIVE && naiveProtocol == "quic") {
                "quic"
            } else {
                resolvedTransportType
            }
            val enabledNetwork = UriNodeParser.normalizeEnabledNetwork(configuredNetwork)
            if (!configuredNetwork.isNullOrBlank() && transport == null && transportType == null && enabledNetwork == null) {
                diagnostics = diagnostics.withIgnored("unsupported_json_network")
                continue
            }
            if (transport != null &&
                !transport.optString("type", "").isNullOrBlank() &&
                transportType == null
            ) {
                diagnostics = diagnostics.withIgnored("unsupported_json_transport")
                continue
            }

            result += ProxyNode(
                name = obj.optString("name", obj.optString("ps", type.name)),
                type = type,
                server = server,
                port = port,
                bindInterface = UriNodeParser.jsonScalarString(obj.opt("bind_interface")),
                connectTimeout = UriNodeParser.jsonScalarString(obj.opt("connect_timeout")),
                tcpFastOpen = UriNodeParser.optBooleanField(obj, "tcp_fast_open", "tcpFastOpen"),
                udpFragment = UriNodeParser.optBooleanField(obj, "udp_fragment", "udpFragment"),
                disableTcpKeepAlive = UriNodeParser.optBooleanField(
                    obj,
                    "disable_tcp_keep_alive",
                    "disableTcpKeepAlive"
                ),
                tcpKeepAlive = UriNodeParser.jsonScalarString(obj.opt("tcp_keep_alive")),
                tcpKeepAliveInterval = UriNodeParser.jsonScalarString(
                    obj.opt("tcp_keep_alive_interval")
                ),
                uuid = obj.optString("uuid", obj.optString("id", "")).ifBlank { null },
                alterId = UriNodeParser.parseIntField(
                    obj.optString("alter_id", "").ifBlank { null },
                    obj.optString("alterId", "").ifBlank { null },
                    obj.optString("aid", "").ifBlank { null }
                ) ?: 0,
                password = obj.optString("password", "").ifBlank { null },
                method = obj.optString("method", "").ifBlank { null },
                flow = obj.optString("flow", "").ifBlank { null },
                security = if (type == ProxyType.NAIVE) null else obj.optString("security", "").ifBlank { null },
                network = enabledNetwork,
                transportType = transportType,
                tls = type == ProxyType.NAIVE
                        || typeRaw == "https"
                        || obj.optBoolean("tls", false)
                        || tlsObject?.optBoolean("enabled", false) == true
                        || realityObject?.optBoolean("enabled", false) == true,
                sni = UriNodeParser.firstNonBlank(
                    obj.optString("sni", "").ifBlank { null },
                    tlsObject?.optString("server_name", "")?.ifBlank { null },
                    tlsObject?.optString("sni", "")?.ifBlank { null }
                ),
                transportHost = UriNodeParser.firstNonBlank(
                    obj.optString("host", "").ifBlank { null },
                    transport?.optString("host", "")?.ifBlank { null },
                    UriNodeParser.extractHostHeader(headersObject),
                    transport?.optJSONObject("headers")?.optString("Host", "")?.ifBlank { null },
                    transport?.optJSONArray("host")?.toCommaSeparatedString()
                ),
                transportPath = UriNodeParser.firstNonBlank(
                    obj.optString("path", "").ifBlank { null },
                    transport?.optString("path", "")?.ifBlank { null }
                ),
                transportServiceName = UriNodeParser.firstNonBlank(
                    obj.optString("service_name", obj.optString("serviceName", "")).ifBlank { null },
                    transport?.optString("service_name", "")?.ifBlank { null },
                    transport?.optString("serviceName", "")?.ifBlank { null },
                    if (transportType == "grpc") {
                        UriNodeParser.firstNonBlank(
                            obj.optString("path", "").ifBlank { null },
                            transport?.optString("path", "")?.ifBlank { null }
                        )
                    } else {
                        null
                    }
                ),
                wsMaxEarlyData = transport?.optInt("max_early_data", -1)?.takeIf { it >= 0 },
                wsEarlyDataHeaderName = transport?.optString("early_data_header_name", "")?.ifBlank { null },
                alpn = if (type == ProxyType.NAIVE) {
                    null
                } else {
                    UriNodeParser.firstNonBlank(
                        obj.optString("alpn", "").ifBlank { null },
                        tlsObject?.optJSONArray("alpn")?.toCommaSeparatedString(),
                        tlsObject?.optString("alpn", "")?.ifBlank { null }
                    )
                },
                fingerprint = if (type == ProxyType.NAIVE) {
                    null
                } else {
                    UriNodeParser.firstNonBlank(
                        obj.optString("fingerprint", obj.optString("fp", "")).ifBlank { null },
                        utlsObject?.optString("fingerprint", "")?.ifBlank { null }
                    )
                },
                publicKey = if (type == ProxyType.NAIVE) {
                    null
                } else {
                    UriNodeParser.firstNonBlank(
                        obj.optString("public_key", obj.optString("pbk", "")).ifBlank { null },
                        realityObject?.optString("public_key", "")?.ifBlank { null }
                    )
                },
                shortId = if (type == ProxyType.NAIVE) {
                    null
                } else {
                    UriNodeParser.firstNonBlank(
                        obj.optString("short_id", obj.optString("sid", "")).ifBlank { null },
                        realityObject?.optString("short_id", "")?.ifBlank { null }
                    )
                },
                packetEncoding = UriNodeParser.firstNonBlank(
                    obj.optString("packet_encoding", obj.optString("packetEncoding", "")).ifBlank { null },
                    transport?.optString("packet_encoding", "")?.ifBlank { null },
                    transport?.optString("packetEncoding", "")?.ifBlank { null }
                ),
                username = obj.optString("username", "").ifBlank { null },
                socksVersion = UriNodeParser.firstNonBlank(
                    obj.optString("version", "").ifBlank { null },
                    when (typeRaw) {
                        "socks5" -> "5"
                        else -> null
                    }
                ),
                allowInsecure = if (type == ProxyType.NAIVE) {
                    false
                } else {
                    obj.optBoolean("allowInsecure", false)
                        || obj.optBoolean("allow_insecure", false)
                        || tlsObject?.optBoolean("insecure", false) == true
                        || UriNodeParser.parseBooleanField(obj.optString("allowInsecure"))
                },
                plugin = obj.optString("plugin", "").ifBlank { null },
                pluginOpts = UriNodeParser.firstNonBlank(
                    obj.optString("plugin_opts", "").ifBlank { null },
                    obj.optString("plugin-opts", "").ifBlank { null },
                    UriNodeParser.pluginOptionsValue(obj.optJSONObject("plugin_opts")),
                    UriNodeParser.pluginOptionsValue(obj.optJSONObject("plugin-opts"))
                ),
                udpOverTcpEnabled = udpOverTcp.first,
                udpOverTcpVersion = udpOverTcp.second,
                obfsType = UriNodeParser.firstNonBlank(
                    obfsObject?.optString("type", "")?.ifBlank { null },
                    obj.optString("obfs", "").ifBlank { null }
                ),
                obfsPassword = UriNodeParser.firstNonBlank(
                    obfsObject?.optString("password", "")?.ifBlank { null },
                    obj.optString("obfs_password", "").ifBlank { null },
                    obj.optString("obfs-password", "").ifBlank { null }
                ),
                serverPorts = serverPorts,
                hopInterval = UriNodeParser.firstNonBlank(
                    obj.optString("hop_interval", "").ifBlank { null },
                    obj.optString("hop-interval", "").ifBlank { null }
                ),
                upMbps = obj.optInt("up_mbps", -1).takeIf { it > 0 },
                downMbps = obj.optInt("down_mbps", -1).takeIf { it > 0 },
                muxEnabled = UriNodeParser.optBooleanField(multiplex, "enabled"),
                muxProtocol = multiplex?.optString("protocol", "")?.ifBlank { null },
                muxMaxConnections = multiplex?.optInt("max_connections", -1)?.takeIf { it > 0 },
                muxMinStreams = multiplex?.optInt("min_streams", -1)?.takeIf { it > 0 },
                muxMaxStreams = multiplex?.optInt("max_streams", -1)?.takeIf { it > 0 },
                muxPadding = UriNodeParser.optBooleanField(multiplex, "padding"),
                muxBrutalEnabled = UriNodeParser.optBooleanField(
                    multiplex?.optJSONObject("brutal"),
                    "enabled"
                ),
                muxBrutalUpMbps = multiplex?.optJSONObject("brutal")
                    ?.optInt("up_mbps", -1)?.takeIf { it > 0 },
                muxBrutalDownMbps = multiplex?.optJSONObject("brutal")
                    ?.optInt("down_mbps", -1)?.takeIf { it > 0 },
                congestionControl = UriNodeParser.firstNonBlank(
                    obj.optString("congestion_control", "").ifBlank { null },
                    obj.optString("congestion-control", "").ifBlank { null },
                    obj.optString("quic_congestion_control", "").ifBlank { null },
                    obj.optString("quic-congestion-control", "").ifBlank { null }
                ),
                udpRelayMode = UriNodeParser.firstNonBlank(
                    obj.optString("udp_relay_mode", "").ifBlank { null },
                    obj.optString("udp-relay-mode", "").ifBlank { null }
                ),
                udpOverStream = UriNodeParser.optBooleanField(obj, "udp_over_stream", "udp-over-stream"),
                naiveProtocol = naiveProtocol,
                naiveExtraHeaders = UriNodeParser.firstNonBlank(
                    UriNodeParser.jsonObjectString(obj.optJSONObject("extra_headers")),
                    UriNodeParser.jsonObjectString(obj.optJSONObject("extra-headers")),
                    UriNodeParser.jsonScalarString(obj.opt("extra_headers")),
                    UriNodeParser.jsonScalarString(obj.opt("extra-headers"))
                ),
                naiveInsecureConcurrency = obj.optInt("insecure_concurrency", -1).takeIf { it > 0 }
                    ?: obj.optInt("insecure-concurrency", -1).takeIf { it > 0 },
                naiveCertificate = UriNodeParser.firstNonBlank(
                    UriNodeParser.jsonScalarString(tlsObject?.opt("certificate")),
                    UriNodeParser.jsonScalarString(obj.opt("certificate")),
                    UriNodeParser.jsonScalarString(obj.opt("cert"))
                ),
                naiveCertificatePath = UriNodeParser.firstNonBlank(
                    UriNodeParser.jsonScalarString(tlsObject?.opt("certificate_path")),
                    UriNodeParser.jsonScalarString(tlsObject?.opt("certificate-path")),
                    UriNodeParser.jsonScalarString(obj.opt("certificate_path")),
                    UriNodeParser.jsonScalarString(obj.opt("certificate-path"))
                ),
                naiveEchEnabled = UriNodeParser.optBooleanField(echObject, "enabled")
                    ?: UriNodeParser.parseBooleanOrNull(UriNodeParser.jsonScalarString(obj.opt("ech")))
                    ?: UriNodeParser.optBooleanField(obj, "ech_enabled", "ech-enabled"),
                naiveEchConfig = UriNodeParser.firstNonBlank(
                    UriNodeParser.jsonListOrScalarString(echObject?.opt("config")),
                    UriNodeParser.jsonListOrScalarString(obj.opt("ech_config")),
                    UriNodeParser.jsonListOrScalarString(obj.opt("ech-config"))
                ),
                naiveEchConfigPath = UriNodeParser.firstNonBlank(
                    UriNodeParser.jsonScalarString(echObject?.opt("config_path")),
                    UriNodeParser.jsonScalarString(echObject?.opt("config-path")),
                    UriNodeParser.jsonScalarString(obj.opt("ech_config_path")),
                    UriNodeParser.jsonScalarString(obj.opt("ech-config-path"))
                ),
                naiveEchQueryServerName = UriNodeParser.firstNonBlank(
                    UriNodeParser.jsonScalarString(echObject?.opt("query_server_name")),
                    UriNodeParser.jsonScalarString(echObject?.opt("query-server-name")),
                    UriNodeParser.jsonScalarString(obj.opt("ech_query_server_name")),
                    UriNodeParser.jsonScalarString(obj.opt("ech-query-server-name"))
                )
            )
        }
        return NodeParseBatch(nodes = result, diagnostics = diagnostics)
    }

}
