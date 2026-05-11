package com.aerobox.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.aerobox.AeroBoxApplication
import com.aerobox.R
import com.aerobox.core.config.ConfigGenerator
import com.aerobox.data.model.CustomRuleSet
import com.aerobox.data.model.IPv6Mode
import com.aerobox.data.model.InstalledAppInfo
import com.aerobox.data.model.RuleSetAction
import com.aerobox.data.model.RuleSetFormat
import com.aerobox.data.model.RoutingMode
import com.aerobox.data.repository.AppListRepository
import com.aerobox.data.repository.VpnConnectionResult
import com.aerobox.data.repository.VpnConfigResolver
import com.aerobox.service.VpnStateManager
import com.aerobox.utils.AppLocaleManager
import com.aerobox.utils.PreferenceManager
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

class SettingsViewModel(application: Application) : AndroidViewModel(application) {
    private val appContext = application.applicationContext
    private val appListRepository = AppListRepository(appContext)
    private val vpnRepository = AeroBoxApplication.vpnRepository
    private val configResolver = VpnConfigResolver(appContext)

    private val _installedApps = MutableStateFlow<List<InstalledAppInfo>>(emptyList())
    val installedApps: StateFlow<List<InstalledAppInfo>> = _installedApps.asStateFlow()

    private val _isLoadingInstalledApps = MutableStateFlow(false)
    val isLoadingInstalledApps: StateFlow<Boolean> = _isLoadingInstalledApps.asStateFlow()

    private val _uiMessage = MutableSharedFlow<String>(extraBufferCapacity = 1)
    val uiMessage: SharedFlow<String> = _uiMessage.asSharedFlow()

    val darkMode: StateFlow<String> = PreferenceManager.darkModeFlow(appContext)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), "system")

    val languageTag: StateFlow<String> = PreferenceManager.languageTagFlow(appContext)
        .stateIn(viewModelScope, SharingStarted.Eagerly, AppLocaleManager.SYSTEM_LANGUAGE_TAG)

    val dynamicColor: StateFlow<Boolean> = PreferenceManager.dynamicColorFlow(appContext)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), true)

    val autoConnect: StateFlow<Boolean> = PreferenceManager.autoConnectFlow(appContext)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), false)

    val routingMode: StateFlow<RoutingMode> = PreferenceManager.routingModeFlow(appContext)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), RoutingMode.GLOBAL_PROXY)

    val remoteDns: StateFlow<String> = PreferenceManager.remoteDnsFlow(appContext)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), PreferenceManager.DEFAULT_REMOTE_DNS)

    val directDns: StateFlow<String> = PreferenceManager.directDnsFlow(appContext)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), PreferenceManager.DEFAULT_DIRECT_DNS)

    val perAppProxyEnabled: StateFlow<Boolean> = PreferenceManager.perAppProxyEnabledFlow(appContext)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), false)

    val perAppProxyMode: StateFlow<String> = PreferenceManager.perAppProxyModeFlow(appContext)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), "blacklist")

    val perAppProxyPackages: StateFlow<Set<String>> = PreferenceManager.perAppProxyPackagesFlow(appContext)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptySet())

    val perAppShowSystem: StateFlow<Boolean> = PreferenceManager.perAppShowSystemFlow(appContext)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), false)

    val enableSocksInbound: StateFlow<Boolean> = PreferenceManager.enableSocksInboundFlow(appContext)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), false)

    val enableHttpInbound: StateFlow<Boolean> = PreferenceManager.enableHttpInboundFlow(appContext)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), false)

    val ipv6Mode: StateFlow<IPv6Mode> = PreferenceManager.ipv6ModeFlow(appContext)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), IPv6Mode.DISABLE)

    val autoReconnect: StateFlow<Boolean> = PreferenceManager.autoReconnectFlow(appContext)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), true)

    val enableGeoRules: StateFlow<Boolean> = PreferenceManager.enableGeoRulesFlow(appContext)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), false)

    val enableGeoCnDomainRule: StateFlow<Boolean> = PreferenceManager.enableGeoCnDomainRuleFlow(appContext)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), false)

    val enableGeoCnIpRule: StateFlow<Boolean> = PreferenceManager.enableGeoCnIpRuleFlow(appContext)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), false)

    val enableGeoAdsBlock: StateFlow<Boolean> = PreferenceManager.enableGeoAdsBlockFlow(appContext)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), false)

    val enableGeoBlockQuic: StateFlow<Boolean> = PreferenceManager.enableGeoBlockQuicFlow(appContext)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), false)

    val customRuleSets: StateFlow<List<CustomRuleSet>> = PreferenceManager.customRuleSetsFlow(appContext)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    suspend fun setDarkMode(mode: String) {
        PreferenceManager.setDarkMode(appContext, mode)
    }

    suspend fun setLanguageTag(languageTag: String) {
        PreferenceManager.setLanguageTag(appContext, languageTag)
    }

    suspend fun setDynamicColor(enabled: Boolean) {
        PreferenceManager.setDynamicColor(appContext, enabled)
    }

    suspend fun setAutoConnect(enabled: Boolean) {
        PreferenceManager.setAutoConnect(appContext, enabled)
    }

    suspend fun setRemoteDns(dns: String) {
        val normalizedDns = dns.trim()
        val currentPrefs = PreferenceManager.readVpnConfigPreferences(appContext)
        validateAndPersistDnsSettings(
            remoteDns = normalizedDns,
            directDns = currentPrefs.directDns
        ) ?: return
        refreshActiveConnectionForRuntimeChange(
            failurePrefix = appString(R.string.dns_setting_failed)
        )
    }

    suspend fun setDirectDns(dns: String) {
        val normalizedDns = dns.trim()
        val currentPrefs = PreferenceManager.readVpnConfigPreferences(appContext)
        validateAndPersistDnsSettings(
            remoteDns = currentPrefs.remoteDns,
            directDns = normalizedDns
        ) ?: return
        refreshActiveConnectionForRuntimeChange(
            failurePrefix = appString(R.string.dns_setting_failed)
        )
    }

    suspend fun setDnsServers(remoteDns: String, directDns: String) {
        val normalizedRemoteDns = remoteDns.trim()
        val normalizedDirectDns = directDns.trim()
        validateAndPersistDnsSettings(
            remoteDns = normalizedRemoteDns,
            directDns = normalizedDirectDns
        ) ?: return
        refreshActiveConnectionForRuntimeChange(
            failurePrefix = appString(R.string.dns_setting_failed)
        )
    }

    suspend fun resetDnsServers() {
        validateAndPersistDnsSettings(
            remoteDns = PreferenceManager.DEFAULT_REMOTE_DNS,
            directDns = PreferenceManager.DEFAULT_DIRECT_DNS
        ) ?: return
        refreshActiveConnectionForRuntimeChange(
            failurePrefix = appString(R.string.dns_setting_failed)
        )
    }

    suspend fun setPerAppProxyEnabled(enabled: Boolean) {
        PreferenceManager.setPerAppProxyEnabled(appContext, enabled)
        refreshActiveConnectionForRuntimeChange(
            failurePrefix = appString(R.string.perapp_setting_failed)
        )
    }

    suspend fun setPerAppProxyMode(mode: String) {
        PreferenceManager.setPerAppProxyMode(appContext, mode)
        refreshActiveConnectionForRuntimeChange(
            failurePrefix = appString(R.string.perapp_setting_failed)
        )
    }

    suspend fun setPerAppProxyPackages(packages: Set<String>) {
        PreferenceManager.setPerAppProxyPackages(appContext, packages)
        refreshActiveConnectionForRuntimeChange(
            failurePrefix = appString(R.string.perapp_setting_failed)
        )
    }

    suspend fun setPerAppShowSystem(show: Boolean) {
        PreferenceManager.setPerAppShowSystem(appContext, show)
    }

    suspend fun setEnableSocksInbound(enabled: Boolean) {
        PreferenceManager.setEnableSocksInbound(appContext, enabled)
        refreshActiveConnectionForInboundChange()
    }

    suspend fun setEnableHttpInbound(enabled: Boolean) {
        PreferenceManager.setEnableHttpInbound(appContext, enabled)
        refreshActiveConnectionForInboundChange()
    }

    suspend fun setIPv6Mode(mode: IPv6Mode) {
        PreferenceManager.setIPv6Mode(appContext, mode)
        refreshActiveConnectionForRuntimeChange(
            failurePrefix = appString(R.string.ipv6_setting_failed)
        )
    }

    suspend fun setAutoReconnect(enabled: Boolean) {
        PreferenceManager.setAutoReconnect(appContext, enabled)
    }

    suspend fun setEnableGeoRules(enabled: Boolean) {
        PreferenceManager.setEnableGeoRules(appContext, enabled)
        refreshActiveConnectionForRuntimeChange(
            failurePrefix = appString(R.string.geo_setting_failed)
        )
    }

    suspend fun setEnableGeoCnDomainRule(enabled: Boolean) {
        PreferenceManager.setEnableGeoCnDomainRule(appContext, enabled)
        refreshActiveConnectionForRuntimeChange(
            failurePrefix = appString(R.string.geo_setting_failed)
        )
    }

    suspend fun setEnableGeoCnIpRule(enabled: Boolean) {
        PreferenceManager.setEnableGeoCnIpRule(appContext, enabled)
        refreshActiveConnectionForRuntimeChange(
            failurePrefix = appString(R.string.geo_setting_failed)
        )
    }

    suspend fun setEnableGeoAdsBlock(enabled: Boolean) {
        PreferenceManager.setEnableGeoAdsBlock(appContext, enabled)
        refreshActiveConnectionForRuntimeChange(
            failurePrefix = appString(R.string.geo_setting_failed)
        )
    }

    suspend fun setEnableGeoBlockQuic(enabled: Boolean) {
        PreferenceManager.setEnableGeoBlockQuic(appContext, enabled)
        refreshActiveConnectionForRuntimeChange(
            failurePrefix = appString(R.string.geo_setting_failed)
        )
    }

    suspend fun saveCustomRuleSet(
        existingId: Long?,
        name: String,
        url: String,
        format: RuleSetFormat,
        action: RuleSetAction,
        enabled: Boolean
    ): Boolean {
        val normalizedName = name.trim()
        val normalizedUrl = url.trim()
        val validationError = validateCustomRuleSetInput(normalizedName, normalizedUrl)
        if (validationError != null) {
            _uiMessage.tryEmit(validationError)
            return false
        }

        val current = customRuleSets.value
        val id = existingId?.takeIf { it > 0L } ?: generateRuleSetId(current)
        val updatedRuleSet = CustomRuleSet(
            id = id,
            name = normalizedName,
            url = normalizedUrl,
            format = format,
            action = action,
            enabled = enabled
        )
        val updated = if (existingId != null && current.any { it.id == existingId }) {
            current.map { if (it.id == existingId) updatedRuleSet else it }
        } else {
            current + updatedRuleSet
        }
        PreferenceManager.setCustomRuleSets(appContext, updated)
        refreshActiveConnectionForRuntimeChange(
            failurePrefix = appString(R.string.geo_setting_failed)
        )
        return true
    }

    suspend fun deleteCustomRuleSet(ruleSet: CustomRuleSet) {
        PreferenceManager.setCustomRuleSets(
            appContext,
            customRuleSets.value.filterNot { it.id == ruleSet.id }
        )
        refreshActiveConnectionForRuntimeChange(
            failurePrefix = appString(R.string.geo_setting_failed)
        )
    }

    suspend fun setCustomRuleSetEnabled(ruleSet: CustomRuleSet, enabled: Boolean) {
        PreferenceManager.setCustomRuleSets(
            appContext,
            customRuleSets.value.map { if (it.id == ruleSet.id) it.copy(enabled = enabled) else it }
        )
        refreshActiveConnectionForRuntimeChange(
            failurePrefix = appString(R.string.geo_setting_failed)
        )
    }

    fun loadInstalledApps(forceRefresh: Boolean = false) {
        val explicitPackages = perAppProxyPackages.value
        val visiblePackages = _installedApps.value.asSequence().map { it.packageName }.toSet()
        if (!forceRefresh &&
            _installedApps.value.isNotEmpty() &&
            explicitPackages.all { it in visiblePackages }
        ) {
            return
        }
        viewModelScope.launch {
            _isLoadingInstalledApps.value = true
            runCatching {
                appListRepository.getInstalledApps(forceRefresh = forceRefresh)
            }.onSuccess { apps ->
                _installedApps.value = apps
            }.onFailure {
                _installedApps.value = emptyList()
            }
            _isLoadingInstalledApps.value = false
        }
    }

    private suspend fun refreshActiveConnectionForInboundChange() {
        refreshActiveConnectionForRuntimeChange(
            failurePrefix = appString(R.string.inbound_setting_failed)
        )
    }

    private fun validateCustomRuleSetInput(name: String, url: String): String? {
        if (name.isBlank()) return appString(R.string.routing_custom_rule_name_empty)
        val uri = runCatching { java.net.URI(url) }.getOrNull()
            ?: return appString(R.string.routing_custom_rule_url_invalid)
        val scheme = uri.scheme?.lowercase()
        if (scheme != "https" && scheme != "http") {
            return appString(R.string.routing_custom_rule_url_invalid)
        }
        if (uri.host.isNullOrBlank()) {
            return appString(R.string.routing_custom_rule_url_invalid)
        }
        return null
    }

    private fun generateRuleSetId(current: List<CustomRuleSet>): Long {
        val used = current.mapTo(mutableSetOf()) { it.id }
        var candidate = System.currentTimeMillis()
        while (candidate <= 0L || candidate in used) {
            candidate++
        }
        return candidate
    }

    private suspend fun validateAndPersistDnsSettings(
        remoteDns: String,
        directDns: String
    ): PreferenceManager.VpnConfigPreferences? {
        val currentPrefs = PreferenceManager.readVpnConfigPreferences(appContext)
        val candidatePrefs = currentPrefs.copy(
            remoteDns = remoteDns,
            directDns = directDns
        )

        val syntaxError = ConfigGenerator.validateDnsSettings(
            context = localizedStringContext(),
            remoteDns = remoteDns,
            directDns = directDns,
            ipv6Mode = currentPrefs.ipv6Mode
        )
        if (syntaxError != null) {
            _uiMessage.tryEmit(appString(R.string.dns_invalid_format, syntaxError))
            return null
        }

        val state = VpnStateManager.vpnState.value
        val currentNode = state.currentNode
        if (state.isConnected && currentNode != null) {
            val candidateConfig = runCatching {
                configResolver.buildConfig(
                    node = currentNode,
                    preferencesOverride = candidatePrefs
                )
            }.getOrElse { error ->
                val message = error.message?.takeIf { it.isNotBlank() }
                    ?: appString(R.string.config_generation_failed)
                _uiMessage.tryEmit(appString(R.string.dns_invalid_format, message))
                return null
            }
            val configError = configResolver.validateConfig(candidateConfig)
            if (configError != null) {
                _uiMessage.tryEmit(appString(R.string.dns_invalid_format, configError))
                return null
            }
        }

        PreferenceManager.setRemoteDns(appContext, remoteDns)
        PreferenceManager.setDirectDns(appContext, directDns)
        return candidatePrefs
    }

    private suspend fun refreshActiveConnectionForRuntimeChange(
        failurePrefix: String
    ) {
        val state = VpnStateManager.vpnState.value
        val currentNode = state.currentNode ?: return
        if (!state.isConnected) return

        when (val result = vpnRepository.reloadActiveConnection(currentNode)) {
            is VpnConnectionResult.Success -> {
                _uiMessage.tryEmit(appString(R.string.applying))
            }

            is VpnConnectionResult.InvalidConfig -> {
                _uiMessage.tryEmit(
                    appString(R.string.setting_failed_with_error_format, failurePrefix, result.error)
                )
            }

            is VpnConnectionResult.Failure -> {
                val details = result.throwable.message?.takeIf { it.isNotBlank() }
                _uiMessage.tryEmit(
                    details?.let {
                        appString(R.string.setting_failed_with_error_format, failurePrefix, it)
                    } ?: failurePrefix
                )
            }

            VpnConnectionResult.NoNodeAvailable -> {
                _uiMessage.tryEmit(
                    appString(
                        R.string.setting_failed_with_error_format,
                        failurePrefix,
                        appString(R.string.current_node_unavailable)
                    )
                )
            }
        }
    }

    private fun localizedStringContext() = AppLocaleManager.localizedContext(appContext, languageTag.value)

    private fun appString(resId: Int, vararg formatArgs: Any): String {
        val context = localizedStringContext()
        return if (formatArgs.isEmpty()) {
            context.getString(resId)
        } else {
            context.getString(resId, *formatArgs)
        }
    }
}
