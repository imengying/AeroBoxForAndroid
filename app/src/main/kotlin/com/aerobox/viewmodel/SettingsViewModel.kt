package com.aerobox.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
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
import com.aerobox.data.model.isValidCustomRuleSetUrl
import com.aerobox.data.repository.AppUpdateInfo
import com.aerobox.data.repository.AppUpdateRepository
import com.aerobox.data.repository.AppListRepository
import com.aerobox.data.repository.VpnConnectionResult
import com.aerobox.utils.AppLocaleManager
import com.aerobox.utils.PreferenceManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.CancellationException
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
import kotlinx.coroutines.withContext

class SettingsViewModel(
    application: Application,
    private val vpnRepository: com.aerobox.data.repository.VpnRepository,
    private val appListRepository: AppListRepository,
    private val appUpdateRepository: AppUpdateRepository
) : AndroidViewModel(application) {
    private val appContext = application.applicationContext

    private val _installedApps = MutableStateFlow<List<InstalledAppInfo>>(emptyList())
    val installedApps: StateFlow<List<InstalledAppInfo>> = _installedApps.asStateFlow()

    private val _isLoadingInstalledApps = MutableStateFlow(false)
    val isLoadingInstalledApps: StateFlow<Boolean> = _isLoadingInstalledApps.asStateFlow()

    private val _installedAppsLoadFailed = MutableStateFlow(false)
    val installedAppsLoadFailed = _installedAppsLoadFailed.asStateFlow()

    private val _uiMessage = MutableSharedFlow<String>(extraBufferCapacity = 1)
    val uiMessage: SharedFlow<String> = _uiMessage.asSharedFlow()

    private val _isCheckingAppUpdate = MutableStateFlow(false)
    val isCheckingAppUpdate: StateFlow<Boolean> = _isCheckingAppUpdate.asStateFlow()

    private val _availableAppUpdate = MutableStateFlow<AppUpdateInfo?>(null)
    val availableAppUpdate: StateFlow<AppUpdateInfo?> = _availableAppUpdate.asStateFlow()

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

        return updateCustomRuleSets { current ->
            val id = existingId?.takeIf { it > 0L } ?: generateRuleSetId(current)
            val updated = CustomRuleSet(id, normalizedName, normalizedUrl, format, action, enabled)
            if (existingId != null && current.any { it.id == existingId }) {
                current.map { if (it.id == existingId) updated else it }
            } else current + updated
        }
    }

    suspend fun deleteCustomRuleSet(ruleSet: CustomRuleSet) {
        updateCustomRuleSets { current -> current.filterNot { it.id == ruleSet.id } }
    }

    suspend fun setCustomRuleSetEnabled(ruleSet: CustomRuleSet, enabled: Boolean) {
        updateCustomRuleSets { current ->
            current.map { if (it.id == ruleSet.id) it.copy(enabled = enabled) else it }
        }
    }

    private suspend fun updateCustomRuleSets(transform: (List<CustomRuleSet>) -> List<CustomRuleSet>): Boolean {
        val result = vpnRepository.runtimeSettings.update(
            readCurrent = { PreferenceManager.customRuleSetsFlow(appContext).first() },
            persist = { PreferenceManager.setCustomRuleSets(appContext, it) },
            transform = transform
        )
        return showRuntimeSettingsResult(result, appString(R.string.geo_setting_failed))
    }

    fun loadInstalledApps() {
        if (_isLoadingInstalledApps.value) return
        _isLoadingInstalledApps.value = true
        _installedAppsLoadFailed.value = false
        viewModelScope.launch {
            try {
                val apps = appListRepository.getInstalledApps()
                if (apps.isEmpty()) {
                    _installedAppsLoadFailed.value = true
                    RuntimeLogBuffer.appendError("Installed app query returned no selectable packages")
                } else {
                    _installedApps.value = apps
                }
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                // Keep the last usable list and the user's selection on transient failures.
                _installedAppsLoadFailed.value = true
                RuntimeLogBuffer.appendError("Installed app query failed: ${error.javaClass.simpleName}")
            } finally {
                _isLoadingInstalledApps.value = false
            }
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

    private fun validateDnsSettings(
        remoteDns: String,
        directDns: String,
        ipv6Mode: IPv6Mode
    ): Boolean {
        val syntaxError = ConfigGenerator.validateDnsSettings(
            context = AppLocaleManager.localizedContext(appContext, languageTag.value),
            remoteDns = remoteDns,
            directDns = directDns,
            ipv6Mode = ipv6Mode
        )
        if (syntaxError != null) {
            _uiMessage.tryEmit(appString(R.string.dns_invalid_format, syntaxError))
            return false
        }
        return true
    }

    private suspend fun applyDnsSettings(remoteDns: String, directDns: String) {
        val result = vpnRepository.runtimeSettings.update(
            readCurrent = {
                val prefs = PreferenceManager.readVpnConfigPreferences(appContext)
                prefs.remoteDns to prefs.directDns
            },
            persist = { (remote, direct) -> PreferenceManager.setDnsServers(appContext, remote, direct) },
            transform = { previous ->
                val ipv6Mode = PreferenceManager.readVpnConfigPreferences(appContext).ipv6Mode
                if (validateDnsSettings(remoteDns, directDns, ipv6Mode)) remoteDns to directDns else previous
            }
        )
        showRuntimeSettingsResult(result, appString(R.string.dns_setting_failed))
    }

    private suspend fun <T> applyRuntimeSetting(
        newValue: T,
        readCurrent: suspend () -> T,
        persist: suspend (T) -> Unit,
        failurePrefix: String
    ): Boolean = showRuntimeSettingsResult(
        vpnRepository.runtimeSettings.update(readCurrent, persist) { newValue }, failurePrefix
    )

    private fun showRuntimeSettingsResult(
        result: com.aerobox.data.repository.RuntimeSettingsResult,
        failurePrefix: String
    ): Boolean {
        if (result.reloaded) _uiMessage.tryEmit(appString(R.string.applying))
        val details = when (val failure = result.failure) {
            is VpnConnectionResult.InvalidConfig -> failure.error
            is VpnConnectionResult.Failure -> failure.throwable.message
            VpnConnectionResult.NoNodeAvailable -> appString(R.string.current_node_unavailable)
            else -> null
        }
        if (!result.applied) {
            _uiMessage.tryEmit(details?.takeIf { it.isNotBlank() }?.let {
                appString(R.string.setting_failed_with_error_format, failurePrefix, it)
            } ?: failurePrefix)
        }
        return result.applied
    }

    private fun appString(resId: Int, vararg formatArgs: Any) =
        AppLocaleManager.string(appContext, languageTag.value, resId, *formatArgs)
}
