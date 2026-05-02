package com.aerobox.data.model

import java.util.Locale

private fun String?.normalizedIdentityValue(): String {
    return this
        ?.trim()
        ?.lowercase(Locale.ROOT)
        .orEmpty()
}

private fun String?.normalizedPathValue(): String {
    val value = this?.trim().orEmpty()
    if (value.isEmpty()) return ""
    return if (value.startsWith("/")) value.lowercase(Locale.ROOT) else "/${value.lowercase(Locale.ROOT)}"
}

private fun String.normalizedServerValue(): String {
    return trim()
        .removePrefix("[")
        .removeSuffix("]")
        .substringBefore('%')
        .lowercase(Locale.ROOT)
}

fun ProxyNode.connectionFingerprint(includeName: Boolean = true): String {
    return buildList {
        if (includeName) add(name.normalizedIdentityValue())
        add(type.name)
        add(server.normalizedServerValue())
        add(port.toString())
        add(bindInterface.normalizedIdentityValue())
        add(connectTimeout.normalizedIdentityValue())
        add(tcpFastOpen?.toString().normalizedIdentityValue())
        add(udpFragment?.toString().normalizedIdentityValue())
        add(uuid.normalizedIdentityValue())
        add(alterId.toString())
        add(password.normalizedIdentityValue())
        add(method.normalizedIdentityValue())
        add(flow.normalizedIdentityValue())
        add(security.normalizedIdentityValue())
        add(effectiveEnabledNetwork().normalizedIdentityValue())
        add(effectiveTransportType().normalizedIdentityValue())
        add(tls.toString())
        add(sni.normalizedIdentityValue())
        add(transportHost.normalizedIdentityValue())
        add(transportPath.normalizedPathValue())
        add(transportServiceName.normalizedIdentityValue())
        add(wsMaxEarlyData?.toString().normalizedIdentityValue())
        add(wsEarlyDataHeaderName.normalizedIdentityValue())
        add(alpn.normalizedIdentityValue())
        add(fingerprint.normalizedIdentityValue())
        add(publicKey.normalizedIdentityValue())
        add(shortId.normalizedIdentityValue())
        add(packetEncoding.normalizedIdentityValue())
        add(username.normalizedIdentityValue())
        add(socksVersion.normalizedIdentityValue())
        add(allowInsecure.toString())
        add(plugin.normalizedIdentityValue())
        add(pluginOpts.normalizedIdentityValue())
        add(udpOverTcpEnabled?.toString().normalizedIdentityValue())
        add(udpOverTcpVersion?.toString().normalizedIdentityValue())
        add(obfsType.normalizedIdentityValue())
        add(obfsPassword.normalizedIdentityValue())
        add(serverPorts.normalizedIdentityValue())
        add(hopInterval.normalizedIdentityValue())
        add(upMbps?.toString().normalizedIdentityValue())
        add(downMbps?.toString().normalizedIdentityValue())
        add(muxEnabled?.toString().normalizedIdentityValue())
        add(muxProtocol.normalizedIdentityValue())
        add(muxMaxConnections?.toString().normalizedIdentityValue())
        add(muxMinStreams?.toString().normalizedIdentityValue())
        add(muxMaxStreams?.toString().normalizedIdentityValue())
        add(muxPadding?.toString().normalizedIdentityValue())
        add(muxBrutalEnabled?.toString().normalizedIdentityValue())
        add(muxBrutalUpMbps?.toString().normalizedIdentityValue())
        add(muxBrutalDownMbps?.toString().normalizedIdentityValue())
        add(congestionControl.normalizedIdentityValue())
        add(udpRelayMode.normalizedIdentityValue())
        add(udpOverStream?.toString().normalizedIdentityValue())
        add(naiveProtocol.normalizedIdentityValue())
        add(naiveExtraHeaders.normalizedIdentityValue())
        add(naiveInsecureConcurrency?.toString().normalizedIdentityValue())
        add(naiveCertificate.normalizedIdentityValue())
        add(naiveCertificatePath.normalizedIdentityValue())
        add(naiveEchEnabled?.toString().normalizedIdentityValue())
        add(naiveEchConfig.normalizedIdentityValue())
        add(naiveEchConfigPath.normalizedIdentityValue())
        add(naiveEchQueryServerName.normalizedIdentityValue())
        add(shadowTlsVersion?.toString().normalizedIdentityValue())
        add(shadowTlsPassword.normalizedIdentityValue())
        add(shadowTlsServerName.normalizedIdentityValue())
        add(shadowTlsAlpn.normalizedIdentityValue())
        add(disableTcpKeepAlive?.toString().normalizedIdentityValue())
        add(tcpKeepAlive.normalizedIdentityValue())
        add(tcpKeepAliveInterval.normalizedIdentityValue())
    }.joinToString("|")
}

private fun ProxyNode.normalizedName(): String = name.normalizedIdentityValue()

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
