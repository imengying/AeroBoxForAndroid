package com.aerobox.utils

import android.content.Context
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.MutablePreferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.core.stringSetPreferencesKey
import com.aerobox.appContainer
import com.aerobox.data.model.CustomRuleSet
import com.aerobox.data.model.CustomRuleSetCodec
import com.aerobox.data.model.IPv6Mode
import com.aerobox.data.model.RoutingMode
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import org.json.JSONArray
import org.json.JSONObject

private val Context.dataStore get() = appContainer.settingsStore

object PreferenceManager {
    const val DEFAULT_REMOTE_DNS = "https://cloudflare-dns.com/dns-query"
    const val DEFAULT_DIRECT_DNS = "udp://223.5.5.5"

    private val DARK_MODE = stringPreferencesKey("dark_mode")
    private val LANGUAGE_TAG = stringPreferencesKey("language_tag")
    private val DYNAMIC_COLOR = booleanPreferencesKey("dynamic_color")
    private val AUTO_CONNECT = booleanPreferencesKey("auto_connect")
    private val LAST_SELECTED_NODE_ID = longPreferencesKey("last_selected_node_id")

    // Routing & Network
    private val ROUTING_MODE = stringPreferencesKey("routing_mode")
    private val REMOTE_DNS = stringPreferencesKey("remote_dns")
    private val DIRECT_DNS = stringPreferencesKey("direct_dns")
    private val PER_APP_PROXY_ENABLED = booleanPreferencesKey("per_app_proxy_enabled")
    private val PER_APP_PROXY_MODE = stringPreferencesKey("per_app_proxy_mode") // "whitelist" or "blacklist"
    private val PER_APP_PROXY_PACKAGES = stringSetPreferencesKey("per_app_proxy_packages")
    private val ENABLE_SOCKS_INBOUND = booleanPreferencesKey("enable_socks_inbound")
    private val ENABLE_HTTP_INBOUND = booleanPreferencesKey("enable_http_inbound")
    private val ENABLE_FAKE_DNS = booleanPreferencesKey("enable_fake_dns")
    private val IPV6_MODE = stringPreferencesKey("ipv6_mode")
    private val AUTO_RECONNECT = booleanPreferencesKey("auto_reconnect")
    private val ENABLE_GEO_RULES = booleanPreferencesKey("enable_geo_rules")
    private val ENABLE_GEO_CN_DOMAIN_RULE = booleanPreferencesKey("enable_geo_cn_domain_rule")
    private val ENABLE_GEO_CN_IP_RULE = booleanPreferencesKey("enable_geo_cn_ip_rule")
    private val ENABLE_GEO_ADS_BLOCK = booleanPreferencesKey("enable_geo_ads_block")
    private val ENABLE_GEO_BLOCK_QUIC = booleanPreferencesKey("enable_geo_block_quic")
    private val CUSTOM_RULE_SETS = stringPreferencesKey("custom_rule_sets")
    private val PER_APP_SHOW_SYSTEM = booleanPreferencesKey("per_app_show_system")

    private val backupStrings = listOf(DARK_MODE, LANGUAGE_TAG, ROUTING_MODE, REMOTE_DNS, DIRECT_DNS,
        PER_APP_PROXY_MODE, IPV6_MODE, CUSTOM_RULE_SETS)
    private val backupBooleans = listOf(DYNAMIC_COLOR, AUTO_CONNECT, PER_APP_PROXY_ENABLED,
        ENABLE_SOCKS_INBOUND, ENABLE_HTTP_INBOUND, AUTO_RECONNECT, ENABLE_GEO_RULES,
        ENABLE_GEO_CN_DOMAIN_RULE, ENABLE_GEO_CN_IP_RULE, ENABLE_GEO_ADS_BLOCK,
        ENABLE_GEO_BLOCK_QUIC, PER_APP_SHOW_SYSTEM, ENABLE_FAKE_DNS)

    suspend fun exportSettings(context: Context): JSONObject {
        val prefs = context.dataStore.data.first()
        return JSONObject().apply {
            backupStrings.forEach { key -> prefs[key]?.let { put(key.name, it) } }
            backupBooleans.forEach { key -> prefs[key]?.let { put(key.name, it) } }
            put(LAST_SELECTED_NODE_ID.name, prefs[LAST_SELECTED_NODE_ID] ?: 0L)
            put(PER_APP_PROXY_PACKAGES.name, JSONArray(prefs[PER_APP_PROXY_PACKAGES].orEmpty().sorted()))
        }
    }

    fun validateSettings(settings: JSONObject) {
        backupStrings.forEach { require(!settings.has(it.name) || settings.get(it.name) is String) }
        backupBooleans.forEach { require(!settings.has(it.name) || settings.get(it.name) is Boolean) }
        val selected = settings.get(LAST_SELECTED_NODE_ID.name)
        require(selected is Int || selected is Long)
        val packages = settings.getJSONArray(PER_APP_PROXY_PACKAGES.name)
        require(packages.length() <= 10_000)
        repeat(packages.length()) { require(packages.get(it) is String) }
        if (settings.has(ROUTING_MODE.name)) RoutingMode.valueOf(settings.getString(ROUTING_MODE.name))
        if (settings.has(IPV6_MODE.name)) IPv6Mode.valueOf(settings.getString(IPV6_MODE.name))
        if (settings.has(DARK_MODE.name)) require(settings.getString(DARK_MODE.name) in setOf("system", "on", "off", "light", "dark"))
        if (settings.has(PER_APP_PROXY_MODE.name)) require(settings.getString(PER_APP_PROXY_MODE.name) in setOf("whitelist", "blacklist"))
        if (settings.has(CUSTOM_RULE_SETS.name)) {
            val raw = settings.getString(CUSTOM_RULE_SETS.name)
            require(CustomRuleSetCodec.decode(raw).size == JSONArray(raw).length())
        }
    }

    internal fun restoredPreferences(current: Preferences, settings: JSONObject, selectedNodeId: Long): Preferences {
        validateSettings(settings)
        return current.toMutablePreferences().apply {
            val prefs = this
            backupStrings.forEach { key ->
                if (settings.has(key.name)) prefs[key] = settings.getString(key.name) else prefs.remove(key)
            }
            // The UI persists on/off; also normalize aliases accepted by older backups.
            when (prefs[DARK_MODE]) {
                "dark" -> prefs[DARK_MODE] = "on"
                "light" -> prefs[DARK_MODE] = "off"
            }
            backupBooleans.forEach { key ->
                if (settings.has(key.name)) prefs[key] = settings.getBoolean(key.name) else prefs.remove(key)
            }
            val packages = settings.getJSONArray(PER_APP_PROXY_PACKAGES.name)
            prefs[PER_APP_PROXY_PACKAGES] = (0 until packages.length()).map { packages.getString(it) }.toSet()
            prefs[LAST_SELECTED_NODE_ID] = selectedNodeId
        }
    }

    fun darkModeFlow(context: Context): Flow<String> =
        context.dataStore.data.map { it[DARK_MODE] ?: "system" }

    fun languageTagFlow(context: Context): Flow<String> =
        context.dataStore.data.map { it[LANGUAGE_TAG] ?: "" }

    fun dynamicColorFlow(context: Context): Flow<Boolean> =
        context.dataStore.data.map { it[DYNAMIC_COLOR] ?: true }

    fun autoConnectFlow(context: Context): Flow<Boolean> =
        context.dataStore.data.map { it[AUTO_CONNECT] ?: false }

    fun lastSelectedNodeIdFlow(context: Context): Flow<Long> =
        context.dataStore.data.map { it[LAST_SELECTED_NODE_ID] ?: -1L }

    fun routingModeFlow(context: Context): Flow<RoutingMode> =
        context.dataStore.data.map {
            runCatching { RoutingMode.valueOf(it[ROUTING_MODE] ?: "") }.getOrDefault(RoutingMode.GLOBAL_PROXY)
        }

    fun remoteDnsFlow(context: Context): Flow<String> =
        context.dataStore.data.map { it[REMOTE_DNS] ?: DEFAULT_REMOTE_DNS }

    fun directDnsFlow(context: Context): Flow<String> =
        context.dataStore.data.map { it[DIRECT_DNS] ?: DEFAULT_DIRECT_DNS }

    fun perAppProxyEnabledFlow(context: Context): Flow<Boolean> =
        context.dataStore.data.map { it[PER_APP_PROXY_ENABLED] ?: false }

    fun perAppProxyModeFlow(context: Context): Flow<String> =
        context.dataStore.data.map { it[PER_APP_PROXY_MODE] ?: "blacklist" }

    fun perAppProxyPackagesFlow(context: Context): Flow<Set<String>> =
        context.dataStore.data.map { it[PER_APP_PROXY_PACKAGES] ?: emptySet() }

    fun perAppShowSystemFlow(context: Context): Flow<Boolean> =
        context.dataStore.data.map { it[PER_APP_SHOW_SYSTEM] ?: false }

    fun enableSocksInboundFlow(context: Context): Flow<Boolean> =
        context.dataStore.data.map { it[ENABLE_SOCKS_INBOUND] ?: false }

    fun enableHttpInboundFlow(context: Context): Flow<Boolean> =
        context.dataStore.data.map { it[ENABLE_HTTP_INBOUND] ?: false }

    fun ipv6ModeFlow(context: Context): Flow<IPv6Mode> =
        context.dataStore.data.map {
            runCatching { IPv6Mode.valueOf(it[IPV6_MODE] ?: "") }.getOrDefault(IPv6Mode.DISABLE)
        }

    fun enableFakeDnsFlow(context: Context): Flow<Boolean> =
        context.dataStore.data.map { it[ENABLE_FAKE_DNS] ?: false }

    suspend fun setEnableFakeDns(context: Context, enabled: Boolean) {
        context.dataStore.edit { it[ENABLE_FAKE_DNS] = enabled }
    }

    fun autoReconnectFlow(context: Context): Flow<Boolean> =
        context.dataStore.data.map { it[AUTO_RECONNECT] ?: true }

    fun enableGeoRulesFlow(context: Context): Flow<Boolean> =
        context.dataStore.data.map { it[ENABLE_GEO_RULES] ?: false }

    fun enableGeoCnDomainRuleFlow(context: Context): Flow<Boolean> =
        context.dataStore.data.map { it[ENABLE_GEO_CN_DOMAIN_RULE] ?: false }

    fun enableGeoCnIpRuleFlow(context: Context): Flow<Boolean> =
        context.dataStore.data.map { it[ENABLE_GEO_CN_IP_RULE] ?: false }

    fun enableGeoAdsBlockFlow(context: Context): Flow<Boolean> =
        context.dataStore.data.map { it[ENABLE_GEO_ADS_BLOCK] ?: false }

    fun enableGeoBlockQuicFlow(context: Context): Flow<Boolean> =
        context.dataStore.data.map { it[ENABLE_GEO_BLOCK_QUIC] ?: false }

    fun customRuleSetsFlow(context: Context): Flow<List<CustomRuleSet>> =
        context.dataStore.data.map { CustomRuleSetCodec.decode(it[CUSTOM_RULE_SETS]) }

    // ── Setters ──

    suspend fun setDarkMode(context: Context, mode: String) {
        context.dataStore.edit { it[DARK_MODE] = mode }
    }

    suspend fun setLanguageTag(context: Context, languageTag: String) {
        context.dataStore.edit { it[LANGUAGE_TAG] = languageTag }
    }

    suspend fun setDynamicColor(context: Context, enabled: Boolean) {
        context.dataStore.edit { it[DYNAMIC_COLOR] = enabled }
    }

    suspend fun setAutoConnect(context: Context, enabled: Boolean) {
        context.dataStore.edit { it[AUTO_CONNECT] = enabled }
    }

    suspend fun setLastSelectedNodeId(context: Context, nodeId: Long) {
        context.dataStore.edit { preferences: MutablePreferences ->
            preferences[LAST_SELECTED_NODE_ID] = nodeId
        }
    }

    suspend fun replaceSelectedNode(context: Context, expectedId: Long, nodeId: Long) {
        context.dataStore.edit {
            if ((it[LAST_SELECTED_NODE_ID] ?: -1L) == expectedId) it[LAST_SELECTED_NODE_ID] = nodeId
        }
    }

    suspend fun setRoutingMode(context: Context, mode: RoutingMode) {
        context.dataStore.edit { it[ROUTING_MODE] = mode.name }
    }

    suspend fun setDnsServers(context: Context, remote: String, direct: String) {
        context.dataStore.edit {
            it[REMOTE_DNS] = remote
            it[DIRECT_DNS] = direct
        }
    }

    suspend fun setPerAppProxyEnabled(context: Context, enabled: Boolean) {
        context.dataStore.edit { it[PER_APP_PROXY_ENABLED] = enabled }
    }

    suspend fun setPerAppProxyMode(context: Context, mode: String) {
        context.dataStore.edit { it[PER_APP_PROXY_MODE] = mode }
    }

    suspend fun setPerAppProxyPackages(context: Context, packages: Set<String>) {
        context.dataStore.edit { it[PER_APP_PROXY_PACKAGES] = packages }
    }

    suspend fun setPerAppShowSystem(context: Context, show: Boolean) {
        context.dataStore.edit { it[PER_APP_SHOW_SYSTEM] = show }
    }

    suspend fun setEnableSocksInbound(context: Context, enabled: Boolean) {
        context.dataStore.edit { it[ENABLE_SOCKS_INBOUND] = enabled }
    }

    suspend fun setEnableHttpInbound(context: Context, enabled: Boolean) {
        context.dataStore.edit { it[ENABLE_HTTP_INBOUND] = enabled }
    }

    suspend fun setIPv6Mode(context: Context, mode: IPv6Mode) {
        context.dataStore.edit {
            it[IPV6_MODE] = mode.name
        }
    }

    suspend fun setAutoReconnect(context: Context, enabled: Boolean) {
        context.dataStore.edit { it[AUTO_RECONNECT] = enabled }
    }

    suspend fun setEnableGeoRules(context: Context, enabled: Boolean) {
        context.dataStore.edit { it[ENABLE_GEO_RULES] = enabled }
    }

    suspend fun setEnableGeoCnDomainRule(context: Context, enabled: Boolean) {
        context.dataStore.edit { it[ENABLE_GEO_CN_DOMAIN_RULE] = enabled }
    }

    suspend fun setEnableGeoCnIpRule(context: Context, enabled: Boolean) {
        context.dataStore.edit { it[ENABLE_GEO_CN_IP_RULE] = enabled }
    }

    suspend fun setEnableGeoAdsBlock(context: Context, enabled: Boolean) {
        context.dataStore.edit { it[ENABLE_GEO_ADS_BLOCK] = enabled }
    }

    suspend fun setEnableGeoBlockQuic(context: Context, enabled: Boolean) {
        context.dataStore.edit { it[ENABLE_GEO_BLOCK_QUIC] = enabled }
    }

    suspend fun setCustomRuleSets(context: Context, ruleSets: List<CustomRuleSet>) {
        context.dataStore.edit { it[CUSTOM_RULE_SETS] = CustomRuleSetCodec.encode(ruleSets) }
    }

    /**
     * Read all VPN config preferences in a single atomic snapshot.
     */
    data class VpnConfigPreferences(
        val routingMode: RoutingMode,
        val remoteDns: String,
        val directDns: String,
        val enableSocksInbound: Boolean,
        val enableHttpInbound: Boolean,
        val ipv6Mode: IPv6Mode,
        val enableFakeDns: Boolean,
        val enableGeoRules: Boolean,
        val enableGeoCnDomainRule: Boolean,
        val enableGeoCnIpRule: Boolean,
        val enableGeoAdsBlock: Boolean,
        val enableGeoBlockQuic: Boolean,
        val customRuleSets: List<CustomRuleSet>
    )

    suspend fun readVpnConfigPreferences(context: Context): VpnConfigPreferences {
        val prefs = context.dataStore.data.first()
        val routingMode = runCatching { RoutingMode.valueOf(prefs[ROUTING_MODE] ?: "") }
            .getOrDefault(RoutingMode.GLOBAL_PROXY)
        val ipv6Mode = runCatching { IPv6Mode.valueOf(prefs[IPV6_MODE] ?: "") }
            .getOrDefault(IPv6Mode.DISABLE)
        return VpnConfigPreferences(
            routingMode = routingMode,
            remoteDns = prefs[REMOTE_DNS] ?: DEFAULT_REMOTE_DNS,
            directDns = prefs[DIRECT_DNS] ?: DEFAULT_DIRECT_DNS,
            enableSocksInbound = prefs[ENABLE_SOCKS_INBOUND] ?: false,
            enableHttpInbound = prefs[ENABLE_HTTP_INBOUND] ?: false,
            ipv6Mode = ipv6Mode,
            enableFakeDns = prefs[ENABLE_FAKE_DNS] ?: false,
            enableGeoRules = prefs[ENABLE_GEO_RULES] ?: false,
            enableGeoCnDomainRule = prefs[ENABLE_GEO_CN_DOMAIN_RULE] ?: false,
            enableGeoCnIpRule = prefs[ENABLE_GEO_CN_IP_RULE] ?: false,
            enableGeoAdsBlock = prefs[ENABLE_GEO_ADS_BLOCK] ?: false,
            enableGeoBlockQuic = prefs[ENABLE_GEO_BLOCK_QUIC] ?: false,
            customRuleSets = CustomRuleSetCodec.decode(prefs[CUSTOM_RULE_SETS])
        )
    }
}
