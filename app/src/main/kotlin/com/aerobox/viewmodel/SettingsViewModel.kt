package com.aerobox.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.aerobox.AeroBoxApplication
import com.aerobox.BuildConfig
import com.aerobox.R
import com.aerobox.core.config.ConfigGenerator
import com.aerobox.core.logging.RuntimeLogBuffer
import com.aerobox.data.model.CustomRuleSet
import com.aerobox.data.model.IPv6Mode
import com.aerobox.data.model.InstalledAppInfo
import com.aerobox.data.model.RuleSetAction
import com.aerobox.data.model.RuleSetFormat
import com.aerobox.data.model.RoutingMode
import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.isValidCustomRuleSetUrl
import com.aerobox.data.repository.AppUpdateInfo
import com.aerobox.data.repository.AppUpdateRepository
import com.aerobox.data.repository.AppListRepository
import com.aerobox.data.repository.VpnConnectionResult
import com.aerobox.data.repository.VpnConfigResolver
import com.aerobox.service.VpnStateManager
import com.aerobox.utils.AppLocaleManager
import com.aerobox.utils.PreferenceManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

class SettingsViewModel(application: Application) : AndroidViewModel(application) {
    private val appContext = application.applicationContext
    private val appListRepository = AppListRepository(appContext)
    private val appUpdateRepository = AppUpdateRepository()
    private val vpnRepository = AeroBoxApplication.vpnRepository
    private val configResolver = VpnConfigResolver(appContext)
    private val runtimeSettingsMutex = Mutex()

    private val _installedApps = MutableStateFlow<List<InstalledAppInfo>>(emptyList())
    val installedApps: StateFlow<List<InstalledAppInfo>> = _installedApps.asStateFlow()

    private val _isLoadingInstalledApps = MutableStateFlow(false)
    val isLoadingInstalledApps: StateFlow<Boolean> = _isLoadingInstalledApps.asStateFlow()

    private val _uiMessage = MutableSharedFlow<String>(extraBufferCapacity = 1)
    val uiMessage: SharedFlow<String> = _uiMessage.asSharedFlow()

    private val _isCheckingAppUpdate = MutableStateFlow(false)
    val isCheckingAppUpdate: StateFlow<Boolean> = _isCheckingAppUpdate.asStateFlow()

    private val _availableAppUpdate = MutableStateFlow<AppUpdateInfo?>(null)
    val availableAppUpdate: StateFlow<AppUpdateInfo?> = _availableAppUpdate.asStateFlow()

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

    suspend fun setDnsServers(remoteDns: String, directDns: String) {
        applyDnsSettings(remoteDns.trim(), directDns.trim())
    }

    suspend fun resetDnsServers() {
        applyDnsSettings(
            remoteDns = PreferenceManager.DEFAULT_REMOTE_DNS,
            directDns = PreferenceManager.DEFAULT_DIRECT_DNS
        )
    }

    suspend fun setPerAppProxyEnabled(enabled: Boolean) {
        applyRuntimeSetting(
            newValue = enabled,
            readCurrent = { PreferenceManager.perAppProxyEnabledFlow(appContext).first() },
            persist = { PreferenceManager.setPerAppProxyEnabled(appContext, it) },
            failurePrefix = appString(R.string.perapp_setting_failed)
        )
    }

    suspend fun setPerAppProxyMode(mode: String) {
        applyRuntimeSetting(
            newValue = mode,
            readCurrent = { PreferenceManager.perAppProxyModeFlow(appContext).first() },
            persist = { PreferenceManager.setPerAppProxyMode(appContext, it) },
            failurePrefix = appString(R.string.perapp_setting_failed)
        )
    }

    suspend fun setPerAppProxyPackages(packages: Set<String>) {
        applyRuntimeSetting(
            newValue = packages,
            readCurrent = { PreferenceManager.perAppProxyPackagesFlow(appContext).first() },
            persist = { PreferenceManager.setPerAppProxyPackages(appContext, it) },
            failurePrefix = appString(R.string.perapp_setting_failed)
        )
    }

    suspend fun setPerAppShowSystem(show: Boolean) {
        PreferenceManager.setPerAppShowSystem(appContext, show)
    }

    suspend fun setEnableSocksInbound(enabled: Boolean) {
        applyRuntimeSetting(
            newValue = enabled,
            readCurrent = { PreferenceManager.enableSocksInboundFlow(appContext).first() },
            persist = { PreferenceManager.setEnableSocksInbound(appContext, it) },
            failurePrefix = appString(R.string.inbound_setting_failed)
        )
    }

    suspend fun setEnableHttpInbound(enabled: Boolean) {
        applyRuntimeSetting(
            newValue = enabled,
            readCurrent = { PreferenceManager.enableHttpInboundFlow(appContext).first() },
            persist = { PreferenceManager.setEnableHttpInbound(appContext, it) },
            failurePrefix = appString(R.string.inbound_setting_failed)
        )
    }

    suspend fun setIPv6Mode(mode: IPv6Mode) {
        applyRuntimeSetting(
            newValue = mode,
            readCurrent = { PreferenceManager.ipv6ModeFlow(appContext).first() },
            persist = { PreferenceManager.setIPv6Mode(appContext, it) },
            failurePrefix = appString(R.string.ipv6_setting_failed)
        )
    }

    suspend fun setAutoReconnect(enabled: Boolean) {
        PreferenceManager.setAutoReconnect(appContext, enabled)
    }

    suspend fun setEnableGeoRules(enabled: Boolean) {
        applyRuntimeSetting(
            newValue = enabled,
            readCurrent = { PreferenceManager.enableGeoRulesFlow(appContext).first() },
            persist = { PreferenceManager.setEnableGeoRules(appContext, it) },
            failurePrefix = appString(R.string.geo_setting_failed)
        )
    }

    suspend fun setEnableGeoCnDomainRule(enabled: Boolean) {
        applyRuntimeSetting(
            newValue = enabled,
            readCurrent = { PreferenceManager.enableGeoCnDomainRuleFlow(appContext).first() },
            persist = { PreferenceManager.setEnableGeoCnDomainRule(appContext, it) },
            failurePrefix = appString(R.string.geo_setting_failed)
        )
    }

    suspend fun setEnableGeoCnIpRule(enabled: Boolean) {
        applyRuntimeSetting(
            newValue = enabled,
            readCurrent = { PreferenceManager.enableGeoCnIpRuleFlow(appContext).first() },
            persist = { PreferenceManager.setEnableGeoCnIpRule(appContext, it) },
            failurePrefix = appString(R.string.geo_setting_failed)
        )
    }

    suspend fun setEnableGeoAdsBlock(enabled: Boolean) {
        applyRuntimeSetting(
            newValue = enabled,
            readCurrent = { PreferenceManager.enableGeoAdsBlockFlow(appContext).first() },
            persist = { PreferenceManager.setEnableGeoAdsBlock(appContext, it) },
            failurePrefix = appString(R.string.geo_setting_failed)
        )
    }

    suspend fun setEnableGeoBlockQuic(enabled: Boolean) {
        applyRuntimeSetting(
            newValue = enabled,
            readCurrent = { PreferenceManager.enableGeoBlockQuicFlow(appContext).first() },
            persist = { PreferenceManager.setEnableGeoBlockQuic(appContext, it) },
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

        return runtimeSettingsMutex.withLock {
            val activeNode = VpnStateManager.vpnState.value.currentNode
            val current = PreferenceManager.customRuleSetsFlow(appContext).first()
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
            val applied = refreshActiveConnectionForRuntimeChange(
                failurePrefix = appString(R.string.geo_setting_failed)
            )
            if (!applied) {
                rollbackRuntimeChange(activeNode) {
                    PreferenceManager.setCustomRuleSets(appContext, current)
                }
            }
            applied
        }
    }

    suspend fun deleteCustomRuleSet(ruleSet: CustomRuleSet) {
        runtimeSettingsMutex.withLock {
            val activeNode = VpnStateManager.vpnState.value.currentNode
            val current = PreferenceManager.customRuleSetsFlow(appContext).first()
            val updated = current.filterNot { it.id == ruleSet.id }
            PreferenceManager.setCustomRuleSets(appContext, updated)
            if (!refreshActiveConnectionForRuntimeChange(appString(R.string.geo_setting_failed))) {
                rollbackRuntimeChange(activeNode) {
                    PreferenceManager.setCustomRuleSets(appContext, current)
                }
            }
        }
    }

    suspend fun setCustomRuleSetEnabled(ruleSet: CustomRuleSet, enabled: Boolean) {
        runtimeSettingsMutex.withLock {
            val activeNode = VpnStateManager.vpnState.value.currentNode
            val current = PreferenceManager.customRuleSetsFlow(appContext).first()
            val updated = current.map { if (it.id == ruleSet.id) it.copy(enabled = enabled) else it }
            PreferenceManager.setCustomRuleSets(appContext, updated)
            if (!refreshActiveConnectionForRuntimeChange(appString(R.string.geo_setting_failed))) {
                rollbackRuntimeChange(activeNode) {
                    PreferenceManager.setCustomRuleSets(appContext, current)
                }
            }
        }
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

    fun checkForAppUpdate() {
        if (_isCheckingAppUpdate.value) return
        viewModelScope.launch {
            _isCheckingAppUpdate.value = true
            _uiMessage.tryEmit(appString(R.string.app_update_checking))
            runCatching {
                withContext(Dispatchers.IO) {
                    appUpdateRepository.checkLatestRelease(BuildConfig.VERSION_NAME)
                }
            }.onSuccess { update ->
                if (update.isUpdateAvailable) {
                    _availableAppUpdate.value = update
                } else {
                    _uiMessage.tryEmit(appString(R.string.app_update_already_latest))
                }
            }.onFailure {
                _uiMessage.tryEmit(appString(R.string.app_update_check_failed))
            }
            _isCheckingAppUpdate.value = false
        }
    }

    fun dismissAppUpdateDialog() {
        _availableAppUpdate.value = null
    }

    private fun validateCustomRuleSetInput(name: String, url: String): String? {
        if (name.isBlank()) return appString(R.string.routing_custom_rule_name_empty)
        if (!isValidCustomRuleSetUrl(url)) {
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

    private suspend fun validateDnsSettings(
        remoteDns: String,
        directDns: String
    ): PreferenceManager.VpnConfigPreferences? {
        val currentPrefs = PreferenceManager.readVpnConfigPreferences(appContext)
        val candidatePrefs = currentPrefs.copy(
            remoteDns = remoteDns,
            directDns = directDns
        )

        val syntaxError = ConfigGenerator.validateDnsSettings(
            context = AppLocaleManager.localizedContext(appContext, languageTag.value),
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

        return candidatePrefs
    }

    private suspend fun applyDnsSettings(remoteDns: String, directDns: String) {
        runtimeSettingsMutex.withLock {
            val activeNode = VpnStateManager.vpnState.value.currentNode
            val currentPrefs = PreferenceManager.readVpnConfigPreferences(appContext)
            validateDnsSettings(remoteDns, directDns) ?: return@withLock
            if (currentPrefs.remoteDns == remoteDns && currentPrefs.directDns == directDns) {
                return@withLock
            }
            PreferenceManager.setRemoteDns(appContext, remoteDns)
            PreferenceManager.setDirectDns(appContext, directDns)
            if (!refreshActiveConnectionForRuntimeChange(appString(R.string.dns_setting_failed))) {
                rollbackRuntimeChange(activeNode) {
                    PreferenceManager.setRemoteDns(appContext, currentPrefs.remoteDns)
                    PreferenceManager.setDirectDns(appContext, currentPrefs.directDns)
                }
            }
        }
    }

    private suspend fun <T> applyRuntimeSetting(
        newValue: T,
        readCurrent: suspend () -> T,
        persist: suspend (T) -> Unit,
        failurePrefix: String
    ): Boolean {
        return runtimeSettingsMutex.withLock {
            val activeNode = VpnStateManager.vpnState.value.currentNode
            val previousValue = readCurrent()
            if (previousValue == newValue) return@withLock true
            persist(newValue)
            val applied = refreshActiveConnectionForRuntimeChange(failurePrefix)
            if (!applied) {
                rollbackRuntimeChange(activeNode) {
                    persist(previousValue)
                }
            }
            applied
        }
    }

    private suspend fun rollbackRuntimeChange(
        activeNode: ProxyNode?,
        rollback: suspend () -> Unit
    ) {
        rollback()
        if (activeNode == null || VpnStateManager.vpnState.value.isConnected) return

        val restoreResult = vpnRepository.reloadActiveConnection(activeNode)
        if (restoreResult !is VpnConnectionResult.Success) {
            val details = when (restoreResult) {
                is VpnConnectionResult.InvalidConfig -> restoreResult.error
                is VpnConnectionResult.Failure -> restoreResult.throwable.message
                VpnConnectionResult.NoNodeAvailable -> "current node unavailable"
                is VpnConnectionResult.Success -> null
            }
            RuntimeLogBuffer.append(
                "error",
                "Failed to restore VPN after rolling back settings: ${details ?: "unknown error"}"
            )
        }
    }

    private suspend fun refreshActiveConnectionForRuntimeChange(
        failurePrefix: String
    ): Boolean {
        val state = VpnStateManager.vpnState.value
        val currentNode = state.currentNode ?: return true
        if (!state.isConnected) return true

        return when (val result = vpnRepository.reloadActiveConnection(currentNode)) {
            is VpnConnectionResult.Success -> {
                _uiMessage.tryEmit(appString(R.string.applying))
                true
            }

            is VpnConnectionResult.InvalidConfig -> {
                _uiMessage.tryEmit(
                    appString(R.string.setting_failed_with_error_format, failurePrefix, result.error)
                )
                false
            }

            is VpnConnectionResult.Failure -> {
                val details = result.throwable.message?.takeIf { it.isNotBlank() }
                _uiMessage.tryEmit(
                    details?.let {
                        appString(R.string.setting_failed_with_error_format, failurePrefix, it)
                    } ?: failurePrefix
                )
                false
            }

            VpnConnectionResult.NoNodeAvailable -> {
                _uiMessage.tryEmit(
                    appString(
                        R.string.setting_failed_with_error_format,
                        failurePrefix,
                        appString(R.string.current_node_unavailable)
                    )
                )
                false
            }
        }
    }

    private fun appString(resId: Int, vararg formatArgs: Any) =
        AppLocaleManager.string(appContext, languageTag.value, resId, *formatArgs)
}
