package com.aerobox.core.config

import com.aerobox.data.model.CustomRuleSet
import com.aerobox.data.model.IPv6Mode
import com.aerobox.data.model.RoutingMode
import com.aerobox.data.model.RuleSetAction
import org.json.JSONArray
import org.json.JSONObject

/**
 * Builds the "route" section of a sing-box configuration.
 *
 * Extracted from [ConfigGenerator] for readability — all methods are
 * package-private and called exclusively by the generator.
 */
internal object RouteConfigBuilder {

    fun buildRoute(
        routingMode: RoutingMode,
        ipv6Mode: IPv6Mode,
        nodeIsIpv6Only: Boolean = false,
        geoIpCnRuleSetPath: String? = null,
        geoSiteCnRuleSetPath: String? = null,
        geoSiteAdsRuleSetPath: String? = null,
        enableGeoCnDomainRule: Boolean = true,
        enableGeoCnIpRule: Boolean = true,
        enableGeoAdsBlock: Boolean = true,
        enableGeoBlockQuic: Boolean = true,
        customRuleSets: List<CustomRuleSet> = emptyList()
    ): JSONObject {
        val route = JSONObject()
            .put("auto_detect_interface", true)

        val ruleSets = JSONArray()
        if (!geoIpCnRuleSetPath.isNullOrBlank()) {
            ruleSets.put(buildLocalRuleSet("geoip-cn", geoIpCnRuleSetPath))
        }
        if (!geoSiteCnRuleSetPath.isNullOrBlank()) {
            ruleSets.put(buildLocalRuleSet("geosite-cn", geoSiteCnRuleSetPath))
        }
        if (!geoSiteAdsRuleSetPath.isNullOrBlank()) {
            ruleSets.put(buildLocalRuleSet("geosite-category-ads-all", geoSiteAdsRuleSetPath))
        }
        customRuleSets.forEach { ruleSet ->
            ruleSets.put(buildRemoteRuleSet(ruleSet))
        }
        if (ruleSets.length() > 0) {
            route.put("rule_set", ruleSets)
        }

        when (routingMode) {
            RoutingMode.GLOBAL_PROXY -> {
                route.put("final", "proxy")
                route.put(
                    "rules",
                    buildBaseRouteRules(nodeIsIpv6Only)
                )
            }

            RoutingMode.RULE_BASED -> {
                route.put("final", "proxy")
                val rules = buildBaseRouteRules(nodeIsIpv6Only)

                if (enableGeoBlockQuic) {
                    rules.put(
                        JSONObject()
                            .put("network", JSONArray().put("udp"))
                            .put("port", JSONArray().put(443))
                            .put("action", "reject")
                    )
                }

                if (enableGeoAdsBlock) {
                    rules.put(
                        JSONObject()
                            .put("rule_set", JSONArray().put("geosite-category-ads-all"))
                            .put("action", "reject")
                    )
                }

                customRuleSets.forEach { ruleSet ->
                    rules.put(buildCustomRule(ruleSet))
                }

                if (enableGeoCnDomainRule) {
                    rules.put(
                        JSONObject()
                            .put("rule_set", JSONArray().put("geosite-cn"))
                            .put("action", "route")
                            .put("outbound", "direct")
                    )
                }

                if (enableGeoCnIpRule) {
                    rules.put(
                        JSONObject()
                            .put("rule_set", JSONArray().put("geoip-cn"))
                            .put("action", "route")
                            .put("outbound", "direct")
                    )
                }

                route.put(
                    "rules",
                    rules
                )
            }

            RoutingMode.DIRECT -> {
                route.put("final", "direct")
                route.put(
                    "rules",
                    buildBaseRouteRules(nodeIsIpv6Only)
                )
            }

        }

        return route
    }

    // ── Private helpers ──────────────────────────────────────────────

    private fun buildLocalRuleSet(tag: String, path: String): JSONObject {
        return JSONObject()
            .put("tag", tag)
            .put("type", "local")
            .put("format", "binary")
            .put("path", path)
    }

    private fun buildRemoteRuleSet(ruleSet: CustomRuleSet): JSONObject {
        return JSONObject()
            .put("tag", ruleSet.tag)
            .put("type", "remote")
            .put("format", ruleSet.format.configValue)
            .put("url", ruleSet.url)
            .put("update_interval", "1d")
            .put(
                "http_client",
                JSONObject().put("detour", ConfigGenerator.PROXY_OUTBOUND_TAG)
            )
    }

    private fun buildCustomRule(ruleSet: CustomRuleSet): JSONObject {
        val rule = JSONObject()
            .put("rule_set", JSONArray().put(ruleSet.tag))
        return when (ruleSet.action) {
            RuleSetAction.DIRECT -> rule
                .put("action", "route")
                .put("outbound", "direct")
            RuleSetAction.PROXY -> rule
                .put("action", "route")
                .put("outbound", ConfigGenerator.PROXY_OUTBOUND_TAG)
            RuleSetAction.REJECT -> rule.put("action", "reject")
        }
    }

    private fun buildBaseRouteRules(nodeIsIpv6Only: Boolean): JSONArray {
        return JSONArray().apply {
            put(JSONObject().put("action", "sniff"))

            if (!nodeIsIpv6Only) {
                put(
                    JSONObject()
                        .put("action", "resolve")
                        .put("strategy", "ipv4_only")
                )
            }

            put(
                JSONObject()
                    .put("port", JSONArray().put(53))
                    .put("action", "hijack-dns")
            )
            put(
                JSONObject()
                    .put("protocol", "dns")
                    .put("action", "hijack-dns")
            )
            put(
                JSONObject()
                    .put(
                        "ip_cidr",
                        JSONArray()
                            .put("127.0.0.0/8")
                            .put("10.0.0.0/8")
                            .put("172.16.0.0/12")
                            .put("192.168.0.0/16")
                            .put("169.254.0.0/16")
                            .put("100.64.0.0/10")
                            .put("198.18.0.0/15")
                            .put("::1/128")
                            .put("fc00::/7")
                            .put("fe80::/10")
                    )
                    .put("action", "route")
                    .put("outbound", "direct")
            )
            put(
                JSONObject()
                    .put("ip_cidr", JSONArray().put("224.0.0.0/3").put("ff00::/8"))
                    .put("source_ip_cidr", JSONArray().put("224.0.0.0/3").put("ff00::/8"))
                    .put("action", "reject")
            )
            put(
                JSONObject()
                    .put("ip_cidr", JSONArray()
                        .put("1.1.1.1/32").put("1.0.0.1/32")
                        .put("8.8.8.8/32").put("8.8.4.4/32")
                        .put("9.9.9.9/32").put("149.112.112.112/32")
                        .put("223.5.5.5/32").put("223.6.6.6/32")
                        .put("119.29.29.29/32").put("182.254.116.116/32")
                    )
                    .put("action", "route")
                    .put("outbound", "direct")
            )
        }
    }
}
