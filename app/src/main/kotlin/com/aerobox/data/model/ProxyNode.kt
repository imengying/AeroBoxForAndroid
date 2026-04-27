package com.aerobox.data.model

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey
import java.util.Locale

enum class ProxyType {
    SHADOWSOCKS,
    SHADOWSOCKS_2022,
    VMESS,
    VLESS,
    TROJAN,
    HYSTERIA2,
    TUIC,
    NAIVE,
    SOCKS,
    HTTP;

    fun displayName(): String {
        return name
            .lowercase(Locale.ROOT)
            .split('_')
            .joinToString(" ") { token ->
                token.replaceFirstChar { ch ->
                    if (ch.isLowerCase()) ch.titlecase(Locale.ROOT) else ch.toString()
                }
            }
    }
}

object NodeLatencyState {
    const val UNTESTED = -1
    const val TESTING = -2
    const val FAILED = -3
}

@Entity(
    tableName = "proxy_nodes",
    indices = [Index(value = ["subscriptionId"])]
)
data class ProxyNode(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val name: String,
    val type: ProxyType,
    val server: String,
    val port: Int,
    val bindInterface: String? = null,
    val connectTimeout: String? = null,
    val tcpFastOpen: Boolean? = null,
    val udpFragment: Boolean? = null,
    val uuid: String? = null,
    val alterId: Int = 0,
    val password: String? = null,
    val method: String? = null,
    val flow: String? = null,
    val security: String? = null,
    val network: String? = null,
    val transportType: String? = null,
    val tls: Boolean = false,
    val sni: String? = null,
    val transportHost: String? = null,
    val transportPath: String? = null,
    val transportServiceName: String? = null,
    val wsMaxEarlyData: Int? = null,
    val wsEarlyDataHeaderName: String? = null,
    val alpn: String? = null,
    val fingerprint: String? = null,
    val publicKey: String? = null,
    val shortId: String? = null,
    val packetEncoding: String? = null,
    val subscriptionId: Long = 0,
    val latency: Int = NodeLatencyState.UNTESTED,
    val createdAt: Long = System.currentTimeMillis(),
    // SOCKS/HTTP auth
    val username: String? = null,
    val socksVersion: String? = null,
    val allowInsecure: Boolean = false,
    // Shadowsocks SIP003
    val plugin: String? = null,
    val pluginOpts: String? = null,
    val udpOverTcpEnabled: Boolean? = null,
    val udpOverTcpVersion: Int? = null,
    // Hysteria2
    val obfsType: String? = null,
    val obfsPassword: String? = null,
    val serverPorts: String? = null,
    val hopInterval: String? = null,
    val upMbps: Int? = null,
    val downMbps: Int? = null,
    // Shared multiplex
    val muxEnabled: Boolean? = null,
    // TUIC-specific
    val congestionControl: String? = null,
    val udpRelayMode: String? = null,
    val udpOverStream: Boolean? = null,
    // Naive-specific
    val naiveProtocol: String? = null,
    val naiveExtraHeaders: String? = null,
    val naiveInsecureConcurrency: Int? = null,
    val naiveCertificate: String? = null,
    val naiveCertificatePath: String? = null,
    val naiveEchEnabled: Boolean? = null,
    val naiveEchConfig: String? = null,
    val naiveEchConfigPath: String? = null,
    val naiveEchQueryServerName: String? = null
)

private val supportedEnabledNetworks = setOf("tcp", "udp")
private val supportedTransportTypes = setOf("ws", "grpc", "http", "h2", "httpupgrade", "quic")

private fun String?.normalizedProxyField(): String? {
    val normalized = this
        ?.trim()
        ?.lowercase(Locale.ROOT)
        ?.takeIf { it.isNotEmpty() }
        ?: return null
    return when (normalized) {
        "websocket" -> "ws"
        "http-upgrade" -> "httpupgrade"
        else -> normalized
    }
}

fun ProxyNode.effectiveEnabledNetwork(): String? {
    return network
        .normalizedProxyField()
        ?.takeIf { it in supportedEnabledNetworks }
}

fun ProxyNode.effectiveTransportType(): String? {
    return transportType
        .normalizedProxyField()
        ?.takeIf { it in supportedTransportTypes }
        ?: network
            .normalizedProxyField()
            ?.takeIf { it in supportedTransportTypes }
}
