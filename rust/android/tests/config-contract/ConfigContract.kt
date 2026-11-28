package com.aerobox.validation

import com.aerobox.core.config.ConfigGenerator
import com.aerobox.core.native.RustCoreNative
import com.aerobox.data.model.*
import org.json.JSONObject
import java.io.File

/** Runs the actual APK's configuration generator against its own JNI library. */
fun main(args: Array<String>) {
    RustCoreNative.initialize(storage = File(args.single()))
    var passed = 0
    fun validate(name: String, raw: String) {
        try {
            RustCoreNative.checkConfig(raw)
            println("PASS $name")
            passed++
        } catch (failure: Exception) {
            throw IllegalStateException("App/Rust contract failed: $name: ${failure.message}", failure)
        }
    }
    fun reject(name: String, raw: String) {
        check(runCatching { RustCoreNative.checkConfig(raw) }.isFailure) {
            "App/Rust contract unexpectedly accepted: $name"
        }
        println("PASS $name rejected")
        passed++
    }
    val uuid = "550e8400-e29b-41d4-a716-446655440000"
    val nodes = ProxyType.entries.map { type ->
        ProxyNode(
            name = type.name, type = type, server = "127.0.0.1", port = 443,
            uuid = uuid, password = if (type == ProxyType.SHADOWSOCKS_2022) "AAAAAAAAAAAAAAAAAAAAAA==" else "fixture-password",
            method = if (type == ProxyType.SHADOWSOCKS_2022) "2022-blake3-aes-128-gcm" else "aes-128-gcm",
            username = "fixture-user", tls = type !in setOf(ProxyType.SHADOWSOCKS, ProxyType.SHADOWSOCKS_2022, ProxyType.SOCKS),
            sni = "proxy.example.invalid"
        )
    }
    for (node in nodes) {
        validate("${node.type} VPN", ConfigGenerator.generateVpnConfig(node))
        validate("${node.type} probe", ConfigGenerator.generateUrlTestConfig(node))
    }
    val rules = File(args.single(), "rules")
    val socks = nodes.single { it.type == ProxyType.SOCKS }
    for ((name, node) in listOf(
        "default" to socks.copy(networkStrategy = "default"),
        "hybrid" to socks.copy(networkStrategy = "hybrid", networkType = "wifi,ethernet"),
        "fallback" to socks.copy(networkStrategy = "fallback", networkType = "wifi", fallbackNetworkType = "cellular", fallbackDelay = "250ms"),
        "network type" to socks.copy(networkType = "wifi"),
        "fallback type" to socks.copy(fallbackNetworkType = "cellular"),
        "fallback delay" to socks.copy(fallbackDelay = "500ms"),
    )) {
        // checkConfig has no platform callback: node editing must work offline.
        validate("physical network $name probe/editor", ConfigGenerator.generateUrlTestConfig(node))
        validate("physical network $name VPN", ConfigGenerator.generateVpnConfig(node))
    }
    validate("bundled SRS rules", ConfigGenerator.generateVpnConfig(socks,
        geoIpCnRuleSetPath = File(rules, "geoip-cn.srs").absolutePath,
        geoSiteCnRuleSetPath = File(rules, "geosite-cn.srs").absolutePath,
        geoSiteAdsRuleSetPath = File(rules, "geosite-category-ads-all.srs").absolutePath))
    for (mode in RoutingMode.entries) {
        validate("routing $mode + FakeIP", ConfigGenerator.generateVpnConfig(socks,
            routingMode = mode, enableFakeDns = true, enableSocksInbound = true, enableHttpInbound = true))
    }
    for (mode in IPv6Mode.entries) {
        validate("IPv6 $mode", ConfigGenerator.generateVpnConfig(socks, ipv6Mode = mode))
    }
    for (dns in listOf("udp://1.1.1.1", "tcp://1.1.1.1", "tls://1.1.1.1", "https://1.1.1.1/dns-query", "quic://1.1.1.1")) {
        validate("DNS $dns", ConfigGenerator.generateVpnConfig(socks, remoteDns = dns))
    }
    validate("remote rules deferred", ConfigGenerator.generateVpnConfig(socks, customRuleSets = listOf(
        CustomRuleSet(1, "test rule", "https://example.invalid/rules.srs", RuleSetFormat.BINARY, RuleSetAction.REJECT, true)
    )))
    val vless = nodes.single { it.type == ProxyType.VLESS }
    for (transport in listOf("grpc", "http")) {
        validate("$transport keepalive", ConfigGenerator.generateVpnConfig(vless.copy(
            transportType = transport, transportHost = if (transport == "http") "first.example.invalid,second.example.invalid" else null, transportIdleTimeout = "15s", transportPingTimeout = "5s",
            grpcPermitWithoutStream = if (transport == "grpc") true else null,
            transportServiceName = if (transport == "grpc") "fixture" else null
        )))
    }
    for (transport in listOf("http", "httpupgrade", "ws")) {
        validate("$transport repeated headers", ConfigGenerator.generateVpnConfig(vless.copy(
            transportType = transport, transportHeaders = """{"X-Fixture":["first","second"]}"""
        )))
    }
    validate("Hysteria2 debug flag", ConfigGenerator.generateVpnConfig(
        nodes.single { it.type == ProxyType.HYSTERIA2 }.copy(brutalDebug = true)))
    for (network in listOf("tcp", "udp")) {
        validate("SOCKS $network-only VPN", ConfigGenerator.generateVpnConfig(socks.copy(network = network)))
        validate("SOCKS $network-only probe", ConfigGenerator.generateUrlTestConfig(socks.copy(network = network)))
    }
    validate("disabled ECH and mux retain editor values", ConfigGenerator.generateVpnConfig(vless.copy(
        echEnabled = false, echConfig = "inactive-config", muxEnabled = false, muxMaxStreams = 8)))
    validate("disabled UoT retains inactive version", ConfigGenerator.generateVpnConfig(socks.copy(
        udpOverTcpEnabled = false, udpOverTcpVersion = 0)))
    validate("Naive HTTPS retains QUIC window", ConfigGenerator.generateVpnConfig(
        nodes.single { it.type == ProxyType.NAIVE }.copy(naiveProtocol = "https", naiveQuicSessionReceiveWindow = "15MiB")))
    validate("HY2 fixed port retains hopping interval", ConfigGenerator.generateVpnConfig(
        nodes.single { it.type == ProxyType.HYSTERIA2 }.copy(hopInterval = "10s")))
    for (type in listOf(ProxyType.HYSTERIA2, ProxyType.TUIC, ProxyType.NAIVE)) {
        validate("$type QUIC retains TCP settings", ConfigGenerator.generateVpnConfig(nodes.single { it.type == type }.copy(
            naiveProtocol = if (type == ProxyType.NAIVE) "quic" else null,
            tcpFastOpen = true, tcpMultiPath = true, tcpKeepAlive = "30s")))
    }
    validate("TLS public-key pin", ConfigGenerator.generateVpnConfig(
        nodes.single { it.type == ProxyType.HTTP }.copy(tlsCertificatePublicKeySha256 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")))
    val https = nodes.single { it.type == ProxyType.HTTP }
    for (version in listOf("1.0", "1.1", "1.2")) {
        validate("ordinary TLS $version without fingerprint", ConfigGenerator.generateVpnConfig(https.copy(
            tlsMinVersion = version, tlsMaxVersion = version,
            tlsCipherSuites = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA")))
    }
    validate("TLS 1.3 with TLS 1.2 cipher selection", ConfigGenerator.generateUrlTestConfig(https.copy(
        tlsMinVersion = "1.3", tlsCipherSuites = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")))
    for (protocol in listOf("https", "quic")) {
        val naive = nodes.single { it.type == ProxyType.NAIVE }.copy(naiveProtocol = protocol)
        validate("Naive $protocol extra headers", ConfigGenerator.generateVpnConfig(naive.copy(
            naiveExtraHeaders = """{"X-Fixture":["first","second"],"User-Agent":"fixture"}""")))
        validate("Naive $protocol without username", ConfigGenerator.generateUrlTestConfig(naive.copy(username = "")))
        validate("Naive $protocol configured concurrency and binary windows", ConfigGenerator.generateVpnConfig(naive.copy(
            naiveInsecureConcurrency = 17, naiveStreamReceiveWindow = "192MB",
            naiveQuicSessionReceiveWindow = if (protocol == "quic") "256MB" else null)))
        for ((name, node) in listOf(
            "insecure" to naive.copy(allowInsecure = true),
            "minimum TLS version" to naive.copy(tlsMinVersion = "1.2"),
            "custom ALPN" to naive.copy(alpn = "h2"),
            "public-key pin" to naive.copy(tlsCertificatePublicKeySha256 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
        )) {
            reject("Naive $protocol $name", ConfigGenerator.generateUrlTestConfig(node))
        }
    }
    val invalid = JSONObject(ConfigGenerator.generateUrlTestConfig(socks))
    invalid.getJSONArray("outbounds").getJSONObject(0).put("unknown_contract_option", true)
    reject("unknown option", invalid.toString())
    println("Config contract: $passed checks passed")
}
