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

private fun ProxyNode.normalizedName(): String = name.normalizedTokenValue()

fun ProxyNode.normalizedDisplayName(): String = normalizedName()

private fun ProxyNode.hasSameEndpoint(other: ProxyNode): Boolean {
    return server.normalizedServerValue() == other.server.normalizedServerValue() &&
        port == other.port
}

fun ProxyNode.matchScore(other: ProxyNode): Int {
    if (type != other.type) return Int.MIN_VALUE

    var score = 20
    if (connectionFingerprint(includeName = false) == other.connectionFingerprint(includeName = false)) {
        score += 100
    }
    if (normalizedName().isNotEmpty() && normalizedName() == other.normalizedName()) {
        score += 40
    }
    if (hasSameEndpoint(other)) {
        score += 30
    }
    return score
}
