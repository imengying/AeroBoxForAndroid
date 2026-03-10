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
        add(uuid.normalizedIdentityValue())
        add(password.normalizedIdentityValue())
        add(method.normalizedIdentityValue())
        add(flow.normalizedIdentityValue())
        add(security.normalizedIdentityValue())
        add(network.normalizedIdentityValue())
        add(tls.toString())
        add(sni.normalizedIdentityValue())
        add(transportHost.normalizedIdentityValue())
        add(transportPath.normalizedPathValue())
        add(transportServiceName.normalizedIdentityValue())
        add(alpn.normalizedIdentityValue())
        add(fingerprint.normalizedIdentityValue())
        add(publicKey.normalizedIdentityValue())
        add(shortId.normalizedIdentityValue())
        add(packetEncoding.normalizedIdentityValue())
        add(username.normalizedIdentityValue())
        add(allowInsecure.toString())
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
