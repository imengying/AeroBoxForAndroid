package com.aerobox.data.model

import java.util.Locale

private fun String?.identityValue(): String = this.orEmpty()

private fun String?.normalizedTokenValue(): String = this?.trim()?.lowercase(Locale.ROOT).orEmpty()

private fun String?.normalizedPathValue(): String {
    val value = identityValue()
    if (value.isEmpty()) return ""
    return if (value.startsWith("/")) value else "/$value"
}

private fun String.normalizedServerValue(): String {
    val value = trim()
        .removePrefix("[")
        .removeSuffix("]")
    val zoneSeparator = value.indexOf('%')
    if (zoneSeparator < 0) return value.lowercase(Locale.ROOT)
    val address = value.substring(0, zoneSeparator).lowercase(Locale.ROOT)
    val zone = value.substring(zoneSeparator + 1)
    return "$address%$zone"
}

private fun encodeIdentityParts(parts: List<String>): String {
    return buildString {
        parts.forEach { value ->
            append(value.length)
            append(':')
            append(value)
        }
    }
}

fun ProxyNode.connectionFingerprint(includeName: Boolean = true): String {
    val parts = buildList {
        if (includeName) add(name.identityValue())
        add(type.name)
        add(server.normalizedServerValue())
        add(port.toString())
        add(bindInterface.identityValue())
        add(connectTimeout.identityValue())
        add(tcpFastOpen?.toString().identityValue())
        add(tcpMultiPath?.toString().identityValue())
        add(udpFragment?.toString().identityValue())
        add(networkStrategy.normalizedTokenValue())
        add(networkType.normalizedTokenValue())
        add(fallbackNetworkType.normalizedTokenValue())
        add(fallbackDelay.identityValue())
        add(uuid.normalizedTokenValue())
        add(alterId.toString())
        add(globalPadding?.toString().identityValue())
        add(authenticatedLength?.toString().identityValue())
        add(password.identityValue())
        add(method.normalizedTokenValue())
        add(flow.normalizedTokenValue())
        add(security.normalizedTokenValue())
        add(effectiveEnabledNetwork().normalizedTokenValue())
        add(effectiveTransportType().normalizedTokenValue())
        add(tls.toString())
        add(sni.normalizedTokenValue())
        add(transportHost.normalizedTokenValue())
        add(transportPath.normalizedPathValue())
        add(transportMethod.identityValue())
        add(transportHeaders.identityValue())
        add(transportIdleTimeout.identityValue())
        add(transportPingTimeout.identityValue())
        add(grpcPermitWithoutStream?.toString().identityValue())
        add(transportServiceName.identityValue())
        add(wsMaxEarlyData?.toString().identityValue())
        add(wsEarlyDataHeaderName.normalizedTokenValue())
        add(alpn.identityValue())
        add(tlsDisableSni?.toString().identityValue())
        add(tlsMinVersion.normalizedTokenValue())
        add(tlsMaxVersion.normalizedTokenValue())
        add(tlsCipherSuites.identityValue())
        add(tlsCurvePreferences.identityValue())
        add(tlsCertificatePublicKeySha256.identityValue())
        add(tlsClientCertificate.identityValue())
        add(tlsClientCertificatePath.identityValue())
        add(tlsClientKey.identityValue())
        add(tlsClientKeyPath.identityValue())
        add(tlsFragment?.toString().identityValue())
        add(tlsFragmentFallbackDelay.identityValue())
        add(tlsRecordFragment?.toString().identityValue())
        add(tlsKernelTx?.toString().identityValue())
        add(tlsKernelRx?.toString().identityValue())
        add(fingerprint.normalizedTokenValue())
        add(publicKey.identityValue())
        add(shortId.identityValue())
        add(packetEncoding.normalizedTokenValue())
        add(username.identityValue())
        add(socksVersion.normalizedTokenValue())
        add(allowInsecure.toString())
        add(plugin.identityValue())
        add(pluginOpts.identityValue())
        add(udpOverTcpEnabled?.toString().identityValue())
        add(udpOverTcpVersion?.toString().identityValue())
        add(obfsType.normalizedTokenValue())
        add(obfsPassword.identityValue())
        add(serverPorts.identityValue())
        add(hopInterval.identityValue())
        add(upMbps?.toString().identityValue())
        add(downMbps?.toString().identityValue())
        add(brutalDebug?.toString().identityValue())
        add(muxEnabled?.toString().identityValue())
        add(muxProtocol.normalizedTokenValue())
        add(muxMaxConnections?.toString().identityValue())
        add(muxMinStreams?.toString().identityValue())
        add(muxMaxStreams?.toString().identityValue())
        add(muxPadding?.toString().identityValue())
        add(muxBrutalEnabled?.toString().identityValue())
        add(muxBrutalUpMbps?.toString().identityValue())
        add(muxBrutalDownMbps?.toString().identityValue())
        add(congestionControl.normalizedTokenValue())
        add(udpRelayMode.normalizedTokenValue())
        add(udpOverStream?.toString().identityValue())
        add(zeroRttHandshake?.toString().identityValue())
        add(heartbeat.identityValue())
        add(naiveProtocol.normalizedTokenValue())
        add(naiveExtraHeaders.identityValue())
        add(naiveInsecureConcurrency?.toString().identityValue())
        add(naiveStreamReceiveWindow.identityValue())
        add(naiveQuicSessionReceiveWindow.identityValue())
        add(tlsCertificate.identityValue())
        add(tlsCertificatePath.identityValue())
        add(echEnabled?.toString().identityValue())
        add(echConfig.identityValue())
        add(echConfigPath.identityValue())
        add(echQueryServerName.normalizedTokenValue())
        add(disableTcpKeepAlive?.toString().identityValue())
        add(tcpKeepAlive.identityValue())
        add(tcpKeepAliveInterval.identityValue())
    }
    return encodeIdentityParts(parts)
}

internal class ProxyNodeMatcher(nodes: List<ProxyNode>) {
    private class Candidate(val node: ProxyNode) {
        val name = node.type to node.name.normalizedTokenValue()
        val fingerprint = node.connectionFingerprint(includeName = false)
        val endpoint = Triple(node.type, node.server.normalizedServerValue(), node.port)
    }

    private val candidates = nodes.map(::Candidate)
    private val byName = candidates.groupBy { it.name }.mapValues { it.value.toMutableSet() }
    private val byFingerprint = candidates.groupBy { it.fingerprint }.mapValues { it.value.toMutableSet() }
    private val byEndpoint = candidates.groupBy { it.endpoint }.mapValues { it.value.toMutableSet() }
    private val byNameAndEndpoint = candidates.groupBy { it.name to it.endpoint }
        .mapValues { it.value.toMutableSet() }

    fun takeBestMatch(node: ProxyNode): ProxyNode? {
        val name = node.name.normalizedTokenValue()
        val nameKey = node.type to name
        val endpointKey = Triple(node.type, node.server.normalizedServerValue(), node.port)
        val named = byName[nameKey]?.takeIf { name.isNotEmpty() }
        val exact = byFingerprint[node.connectionFingerprint(includeName = false)]
        val namedEndpoint = byNameAndEndpoint[nameKey to endpointKey]?.takeIf { name.isNotEmpty() }
        val endpoint = byEndpoint[endpointKey]
        // Preserve the original priority and insertion-order tie breaking.
        val matched = named?.singleOrNull()
            ?: exact?.firstOrNull()
            ?: namedEndpoint?.firstOrNull()
            ?: named?.firstOrNull()
            ?: endpoint?.firstOrNull()
            ?: return null

        byName[matched.name]?.remove(matched)
        byFingerprint[matched.fingerprint]?.remove(matched)
        byEndpoint[matched.endpoint]?.remove(matched)
        byNameAndEndpoint[matched.name to matched.endpoint]?.remove(matched)
        return matched.node
    }
}
