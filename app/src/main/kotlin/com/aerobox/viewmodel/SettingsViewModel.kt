package com.aerobox.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.aerobox.core.config.ConfigGenerator
import com.aerobox.data.model.IPv6Mode
import com.aerobox.data.model.InstalledAppInfo
import com.aerobox.data.model.RoutingMode
import com.aerobox.data.repository.AppListRepository
import com.aerobox.data.repository.VpnConnectionResult
import com.aerobox.data.repository.VpnConfigResolver
import com.aerobox.data.repository.VpnRepository
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
    private val vpnRepository = VpnRepository(appContext)
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
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), "1.1.1.1")

    val localDns: StateFlow<String> = PreferenceManager.localDnsFlow(appContext)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), "223.5.5.5")

    val enableDoh: StateFlow<Boolean> = PreferenceManager.enableDohFlow(appContext)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), true)

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
        validateAndPersistDnsSettings(
            remoteDns = normalizedDns,
            localDns = PreferenceManager.localDnsFlow(appContext).first(),
            enableDoh = PreferenceManager.enableDohFlow(appContext).first()
        ) ?: return
        refreshActiveConnectionForRuntimeChange(
            failurePrefix = "应用 DNS 设置失败"
        )
    }

    suspend fun setLocalDns(dns: String) {
        val normalizedDns = dns.trim()
        validateAndPersistDnsSettings(
            remoteDns = PreferenceManager.remoteDnsFlow(appContext).first(),
            localDns = normalizedDns,
            enableDoh = PreferenceManager.enableDohFlow(appContext).first()
        ) ?: return
        refreshActiveConnectionForRuntimeChange(
            failurePrefix = "应用 DNS 设置失败"
        )
    }

    suspend fun setDnsServers(remoteDns: String, localDns: String) {
        val normalizedRemoteDns = remoteDns.trim()
        val normalizedLocalDns = localDns.trim()
        validateAndPersistDnsSettings(
            remoteDns = normalizedRemoteDns,
            localDns = normalizedLocalDns,
            enableDoh = PreferenceManager.enableDohFlow(appContext).first()
        ) ?: return
        refreshActiveConnectionForRuntimeChange(
            failurePrefix = "应用 DNS 设置失败"
        )
    }

    suspend fun setEnableDoh(enabled: Boolean) {
        validateAndPersistDnsSettings(
            remoteDns = PreferenceManager.remoteDnsFlow(appContext).first(),
            localDns = PreferenceManager.localDnsFlow(appContext).first(),
            enableDoh = enabled
        ) ?: return
        refreshActiveConnectionForRuntimeChange(
            failurePrefix = "应用 DNS 设置失败"
        )
    }

    suspend fun setPerAppProxyEnabled(enabled: Boolean) {
        PreferenceManager.setPerAppProxyEnabled(appContext, enabled)
        refreshActiveConnectionForRuntimeChange(
            failurePrefix = "应用分应用代理设置失败"
        )
    }

    suspend fun setPerAppProxyMode(mode: String) {
        PreferenceManager.setPerAppProxyMode(appContext, mode)
        refreshActiveConnectionForRuntimeChange(
            failurePrefix = "应用分应用代理设置失败"
        )
    }

    suspend fun setPerAppProxyPackages(packages: Set<String>) {
        PreferenceManager.setPerAppProxyPackages(appContext, packages)
        refreshActiveConnectionForRuntimeChange(
            failurePrefix = "应用分应用代理设置失败"
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
            failurePrefix = "应用 IPv6 设置失败"
        )
    }

    suspend fun setAutoReconnect(enabled: Boolean) {
        PreferenceManager.setAutoReconnect(appContext, enabled)
    }

    suspend fun setEnableGeoRules(enabled: Boolean) {
        PreferenceManager.setEnableGeoRules(appContext, enabled)
        refreshActiveConnectionForRuntimeChange(
            failurePrefix = "应用规则设置失败"
        )
    }

    suspend fun setEnableGeoCnDomainRule(enabled: Boolean) {
        PreferenceManager.setEnableGeoCnDomainRule(appContext, enabled)
        refreshActiveConnectionForRuntimeChange(
            failurePrefix = "应用规则设置失败"
        )
    }

    suspend fun setEnableGeoCnIpRule(enabled: Boolean) {
        PreferenceManager.setEnableGeoCnIpRule(appContext, enabled)
        refreshActiveConnectionForRuntimeChange(
            failurePrefix = "应用规则设置失败"
        )
    }

    suspend fun setEnableGeoAdsBlock(enabled: Boolean) {
        PreferenceManager.setEnableGeoAdsBlock(appContext, enabled)
        refreshActiveConnectionForRuntimeChange(
            failurePrefix = "应用规则设置失败"
        )
    }

    suspend fun setEnableGeoBlockQuic(enabled: Boolean) {
        PreferenceManager.setEnableGeoBlockQuic(appContext, enabled)
        refreshActiveConnectionForRuntimeChange(
            failurePrefix = "应用规则设置失败"
        )
    }

    fun loadInstalledApps(forceRefresh: Boolean = false) {
        if (_installedApps.value.isNotEmpty() && !forceRefresh) return
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
            failurePrefix = "应用入站设置失败"
        )
    }

    private suspend fun validateAndPersistDnsSettings(
        remoteDns: String,
        localDns: String,
        enableDoh: Boolean
    ): PreferenceManager.VpnConfigPreferences? {
        val currentPrefs = PreferenceManager.readVpnConfigPreferences(appContext)
        val candidatePrefs = currentPrefs.copy(
            remoteDns = remoteDns,
            localDns = localDns,
            enableDoh = enableDoh
        )

        val syntaxError = ConfigGenerator.validateDnsSettings(
            remoteDns = remoteDns,
            localDns = localDns,
            enableDoh = enableDoh,
            ipv6Mode = currentPrefs.ipv6Mode
        )
        if (syntaxError != null) {
            _uiMessage.tryEmit("DNS 设置无效：$syntaxError")
            return null
        }

        val state = VpnStateManager.vpnState.value
        val currentNode = state.currentNode
        if (state.isConnected && currentNode != null) {
            val candidateConfig = configResolver.buildConfig(
                node = currentNode,
                preferencesOverride = candidatePrefs
            )
            val configError = configResolver.validateConfig(candidateConfig)
            if (configError != null) {
                _uiMessage.tryEmit("DNS 设置无效：$configError")
                return null
            }
        }

        PreferenceManager.setRemoteDns(appContext, remoteDns)
        PreferenceManager.setLocalDns(appContext, localDns)
        PreferenceManager.setEnableDoh(appContext, enableDoh)
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
                _uiMessage.tryEmit("正在应用")
            }

            is VpnConnectionResult.InvalidConfig -> {
                _uiMessage.tryEmit("$failurePrefix：${result.error}")
            }

            is VpnConnectionResult.Failure -> {
                val details = result.throwable.message?.takeIf { it.isNotBlank() }
                _uiMessage.tryEmit(
                    details?.let { "$failurePrefix：$it" } ?: failurePrefix
                )
            }

            VpnConnectionResult.NoNodeAvailable -> {
                _uiMessage.tryEmit("$failurePrefix：当前节点不可用")
            }
        }
    }
}
