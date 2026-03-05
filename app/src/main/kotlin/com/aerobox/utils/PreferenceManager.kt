package com.aerobox.utils

import android.content.Context
import androidx.datastore.preferences.core.MutablePreferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.core.stringSetPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.aerobox.data.model.RoutingMode
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

private val Context.dataStore by preferencesDataStore(name = "settings")

object PreferenceManager {
    private val DARK_MODE = stringPreferencesKey("dark_mode")
    private val DYNAMIC_COLOR = booleanPreferencesKey("dynamic_color")
    private val AUTO_CONNECT = booleanPreferencesKey("auto_connect")
    private val AUTO_UPDATE_SUBSCRIPTION = booleanPreferencesKey("auto_update_subscription")
    private val SHOW_NOTIFICATION = booleanPreferencesKey("show_notification")
    private val LAST_SELECTED_NODE_ID = longPreferencesKey("last_selected_node_id")

    // Phase 2: Routing & Network
    private val ROUTING_MODE = stringPreferencesKey("routing_mode")
    private val REMOTE_DNS = stringPreferencesKey("remote_dns")
    private val LOCAL_DNS = stringPreferencesKey("local_dns")
    private val ENABLE_DOH = booleanPreferencesKey("enable_doh")
    private val PER_APP_PROXY_ENABLED = booleanPreferencesKey("per_app_proxy_enabled")
    private val PER_APP_PROXY_MODE = stringPreferencesKey("per_app_proxy_mode") // "whitelist" or "blacklist"
    private val PER_APP_PROXY_PACKAGES = stringSetPreferencesKey("per_app_proxy_packages")
    private val ENABLE_SOCKS_INBOUND = booleanPreferencesKey("enable_socks_inbound")
    private val ENABLE_HTTP_INBOUND = booleanPreferencesKey("enable_http_inbound")
    private val ENABLE_IPV6 = booleanPreferencesKey("enable_ipv6")
    private val AUTO_RECONNECT = booleanPreferencesKey("auto_reconnect")
    private val ENABLE_GEO_RULES = booleanPreferencesKey("enable_geo_rules")
    private val ENABLE_GEO_CN_DOMAIN_RULE = booleanPreferencesKey("enable_geo_cn_domain_rule")
    private val ENABLE_GEO_CN_IP_RULE = booleanPreferencesKey("enable_geo_cn_ip_rule")
    private val ENABLE_GEO_ADS_BLOCK = booleanPreferencesKey("enable_geo_ads_block")
    private val ENABLE_GEO_BLOCK_QUIC = booleanPreferencesKey("enable_geo_block_quic")

    // ── Existing settings ──

    fun darkModeFlow(context: Context): Flow<String> =
        context.dataStore.data.map { it[DARK_MODE] ?: "system" }

    fun dynamicColorFlow(context: Context): Flow<Boolean> =
        context.dataStore.data.map { it[DYNAMIC_COLOR] ?: true }

    fun autoConnectFlow(context: Context): Flow<Boolean> =
        context.dataStore.data.map { it[AUTO_CONNECT] ?: false }

    fun autoUpdateSubscriptionFlow(context: Context): Flow<Boolean> =
        context.dataStore.data.map { it[AUTO_UPDATE_SUBSCRIPTION] ?: false }

    fun showNotificationFlow(context: Context): Flow<Boolean> =
        context.dataStore.data.map { it[SHOW_NOTIFICATION] ?: true }

    fun lastSelectedNodeIdFlow(context: Context): Flow<Long> =
        context.dataStore.data.map { it[LAST_SELECTED_NODE_ID] ?: -1L }

    // ── Phase 2: Routing & Network ──

    fun routingModeFlow(context: Context): Flow<RoutingMode> =
        context.dataStore.data.map {
            runCatching { RoutingMode.valueOf(it[ROUTING_MODE] ?: "") }.getOrDefault(RoutingMode.RULE_BASED)
        }

    fun remoteDnsFlow(context: Context): Flow<String> =
        context.dataStore.data.map { it[REMOTE_DNS] ?: "tls://8.8.8.8" }

    fun localDnsFlow(context: Context): Flow<String> =
        context.dataStore.data.map { it[LOCAL_DNS] ?: "223.5.5.5" }

    fun enableDohFlow(context: Context): Flow<Boolean> =
        context.dataStore.data.map { it[ENABLE_DOH] ?: true }

    fun perAppProxyEnabledFlow(context: Context): Flow<Boolean> =
        context.dataStore.data.map { it[PER_APP_PROXY_ENABLED] ?: false }

    fun perAppProxyModeFlow(context: Context): Flow<String> =
        context.dataStore.data.map { it[PER_APP_PROXY_MODE] ?: "blacklist" }

    fun perAppProxyPackagesFlow(context: Context): Flow<Set<String>> =
        context.dataStore.data.map { it[PER_APP_PROXY_PACKAGES] ?: emptySet() }

    fun enableSocksInboundFlow(context: Context): Flow<Boolean> =
        context.dataStore.data.map { it[ENABLE_SOCKS_INBOUND] ?: false }

    fun enableHttpInboundFlow(context: Context): Flow<Boolean> =
        context.dataStore.data.map { it[ENABLE_HTTP_INBOUND] ?: false }

    fun enableIPv6Flow(context: Context): Flow<Boolean> =
        context.dataStore.data.map { it[ENABLE_IPV6] ?: true }

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

    // ── Setters ──

    suspend fun setDarkMode(context: Context, mode: String) {
        context.dataStore.edit { it[DARK_MODE] = mode }
    }

    suspend fun setDynamicColor(context: Context, enabled: Boolean) {
        context.dataStore.edit { it[DYNAMIC_COLOR] = enabled }
    }

    suspend fun setAutoConnect(context: Context, enabled: Boolean) {
        context.dataStore.edit { it[AUTO_CONNECT] = enabled }
    }

    suspend fun setAutoUpdateSubscription(context: Context, enabled: Boolean) {
        context.dataStore.edit { it[AUTO_UPDATE_SUBSCRIPTION] = enabled }
    }

    suspend fun setShowNotification(context: Context, enabled: Boolean) {
        context.dataStore.edit { it[SHOW_NOTIFICATION] = enabled }
    }

    suspend fun setLastSelectedNodeId(context: Context, nodeId: Long) {
        context.dataStore.edit { preferences: MutablePreferences ->
            preferences[LAST_SELECTED_NODE_ID] = nodeId
        }
    }

    suspend fun setRoutingMode(context: Context, mode: RoutingMode) {
        context.dataStore.edit { it[ROUTING_MODE] = mode.name }
    }

    suspend fun setRemoteDns(context: Context, dns: String) {
        context.dataStore.edit { it[REMOTE_DNS] = dns }
    }

    suspend fun setLocalDns(context: Context, dns: String) {
        context.dataStore.edit { it[LOCAL_DNS] = dns }
    }

    suspend fun setEnableDoh(context: Context, enabled: Boolean) {
        context.dataStore.edit { it[ENABLE_DOH] = enabled }
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

    suspend fun setEnableSocksInbound(context: Context, enabled: Boolean) {
        context.dataStore.edit { it[ENABLE_SOCKS_INBOUND] = enabled }
    }

    suspend fun setEnableHttpInbound(context: Context, enabled: Boolean) {
        context.dataStore.edit { it[ENABLE_HTTP_INBOUND] = enabled }
    }

    suspend fun setEnableIPv6(context: Context, enabled: Boolean) {
        context.dataStore.edit { it[ENABLE_IPV6] = enabled }
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
}
