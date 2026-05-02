package com.aerobox.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.aerobox.AeroBoxApplication
import com.aerobox.R
import com.aerobox.core.config.ConfigGenerator
import com.aerobox.data.model.IPv6Mode
import com.aerobox.data.model.InstalledAppInfo
import com.aerobox.data.model.RoutingMode
import com.aerobox.data.repository.AppListRepository
import com.aerobox.data.repository.VpnConnectionResult
import com.aerobox.data.repository.VpnConfigResolver
import com.aerobox.service.VpnStateManager
import com.aerobox.utils.PreferenceManager
import kotlinx.coroutines.flow.first
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

    suspend fun setDarkMode(mode: String) {
        PreferenceManager.setDarkMode(appContext, mode)
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
            failurePrefix = appContext.getString(R.string.dns_setting_failed)
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
            failurePrefix = appContext.getString(R.string.dns_setting_failed)
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
            failurePrefix = appContext.getString(R.string.dns_setting_failed)
        )
    }

    suspend fun resetDnsServers() {
        validateAndPersistDnsSettings(
            remoteDns = PreferenceManager.DEFAULT_REMOTE_DNS,
            directDns = PreferenceManager.DEFAULT_DIRECT_DNS
        ) ?: return
        refreshActiveConnectionForRuntimeChange(
            failurePrefix = appContext.getString(R.string.dns_setting_failed)
        )
    }

    suspend fun setPerAppProxyEnabled(enabled: Boolean) {
        PreferenceManager.setPerAppProxyEnabled(appContext, enabled)
        refreshActiveConnectionForRuntimeChange(
            failurePrefix = appContext.getString(R.string.perapp_setting_failed)
        )
    }

    suspend fun setPerAppProxyMode(mode: String) {
        PreferenceManager.setPerAppProxyMode(appContext, mode)
        refreshActiveConnectionForRuntimeChange(
            failurePrefix = appContext.getString(R.string.perapp_setting_failed)
        )
    }

    suspend fun setPerAppProxyPackages(packages: Set<String>) {
        PreferenceManager.setPerAppProxyPackages(appContext, packages)
        refreshActiveConnectionForRuntimeChange(
            failurePrefix = appContext.getString(R.string.perapp_setting_failed)
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
            failurePrefix = appContext.getString(R.string.ipv6_setting_failed)
        )
    }

    suspend fun setAutoReconnect(enabled: Boolean) {
        PreferenceManager.setAutoReconnect(appContext, enabled)
    }

    suspend fun setEnableGeoRules(enabled: Boolean) {
        PreferenceManager.setEnableGeoRules(appContext, enabled)
        refreshActiveConnectionForRuntimeChange(
            failurePrefix = appContext.getString(R.string.geo_setting_failed)
        )
    }

    suspend fun setEnableGeoCnDomainRule(enabled: Boolean) {
        PreferenceManager.setEnableGeoCnDomainRule(appContext, enabled)
        refreshActiveConnectionForRuntimeChange(
            failurePrefix = appContext.getString(R.string.geo_setting_failed)
        )
    }

    suspend fun setEnableGeoCnIpRule(enabled: Boolean) {
        PreferenceManager.setEnableGeoCnIpRule(appContext, enabled)
        refreshActiveConnectionForRuntimeChange(
            failurePrefix = appContext.getString(R.string.geo_setting_failed)
        )
    }

    suspend fun setEnableGeoAdsBlock(enabled: Boolean) {
        PreferenceManager.setEnableGeoAdsBlock(appContext, enabled)
        refreshActiveConnectionForRuntimeChange(
            failurePrefix = appContext.getString(R.string.geo_setting_failed)
        )
    }

    suspend fun setEnableGeoBlockQuic(enabled: Boolean) {
        PreferenceManager.setEnableGeoBlockQuic(appContext, enabled)
        refreshActiveConnectionForRuntimeChange(
            failurePrefix = appContext.getString(R.string.geo_setting_failed)
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
            failurePrefix = appContext.getString(R.string.inbound_setting_failed)
        )
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
            remoteDns = remoteDns,
            directDns = directDns,
            ipv6Mode = currentPrefs.ipv6Mode
        )
        if (syntaxError != null) {
            _uiMessage.tryEmit(appContext.getString(R.string.dns_invalid_format, syntaxError))
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
                    ?: appContext.getString(R.string.config_generation_failed)
                _uiMessage.tryEmit(appContext.getString(R.string.dns_invalid_format, message))
                return null
            }
            val configError = configResolver.validateConfig(candidateConfig)
            if (configError != null) {
                _uiMessage.tryEmit(appContext.getString(R.string.dns_invalid_format, configError))
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
                _uiMessage.tryEmit(appContext.getString(R.string.applying))
            }

            is VpnConnectionResult.InvalidConfig -> {
                _uiMessage.tryEmit(
                    appContext.getString(R.string.setting_failed_with_error_format, failurePrefix, result.error)
                )
            }

            is VpnConnectionResult.Failure -> {
                val details = result.throwable.message?.takeIf { it.isNotBlank() }
                _uiMessage.tryEmit(
                    details?.let {
                        appContext.getString(R.string.setting_failed_with_error_format, failurePrefix, it)
                    } ?: failurePrefix
                )
            }

            VpnConnectionResult.NoNodeAvailable -> {
                _uiMessage.tryEmit(
                    appContext.getString(
                        R.string.setting_failed_with_error_format,
                        failurePrefix,
                        appContext.getString(R.string.current_node_unavailable)
                    )
                )
            }
        }
    }
}
