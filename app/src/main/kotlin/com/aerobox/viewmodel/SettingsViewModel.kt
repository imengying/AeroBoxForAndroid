package com.aerobox.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.aerobox.data.model.RoutingMode
import com.aerobox.utils.PreferenceManager
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.stateIn

class SettingsViewModel(application: Application) : AndroidViewModel(application) {
    private val appContext = application.applicationContext

    val darkMode: StateFlow<String> = PreferenceManager.darkModeFlow(appContext)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), "system")

    val dynamicColor: StateFlow<Boolean> = PreferenceManager.dynamicColorFlow(appContext)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), true)

    val autoConnect: StateFlow<Boolean> = PreferenceManager.autoConnectFlow(appContext)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), false)

    val autoUpdateSubscription: StateFlow<Boolean> =
        PreferenceManager.autoUpdateSubscriptionFlow(appContext)
            .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), false)

    val showNotification: StateFlow<Boolean> = PreferenceManager.showNotificationFlow(appContext)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), true)

    // Phase 2
    val routingMode: StateFlow<RoutingMode> = PreferenceManager.routingModeFlow(appContext)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), RoutingMode.RULE_BASED)

    val remoteDns: StateFlow<String> = PreferenceManager.remoteDnsFlow(appContext)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), "tls://8.8.8.8")

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

    val enableSocksInbound: StateFlow<Boolean> = PreferenceManager.enableSocksInboundFlow(appContext)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), false)

    val enableHttpInbound: StateFlow<Boolean> = PreferenceManager.enableHttpInboundFlow(appContext)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), false)

    val enableIPv6: StateFlow<Boolean> = PreferenceManager.enableIPv6Flow(appContext)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), true)

    val autoReconnect: StateFlow<Boolean> = PreferenceManager.autoReconnectFlow(appContext)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), true)

    suspend fun setDarkMode(mode: String) {
        PreferenceManager.setDarkMode(appContext, mode)
    }

    suspend fun setDynamicColor(enabled: Boolean) {
        PreferenceManager.setDynamicColor(appContext, enabled)
    }

    suspend fun setAutoConnect(enabled: Boolean) {
        PreferenceManager.setAutoConnect(appContext, enabled)
    }

    suspend fun setAutoUpdateSubscription(enabled: Boolean) {
        PreferenceManager.setAutoUpdateSubscription(appContext, enabled)
    }

    suspend fun setShowNotification(enabled: Boolean) {
        PreferenceManager.setShowNotification(appContext, enabled)
    }

    // Phase 2 setters
    suspend fun setRoutingMode(mode: RoutingMode) {
        PreferenceManager.setRoutingMode(appContext, mode)
    }

    suspend fun setRemoteDns(dns: String) {
        PreferenceManager.setRemoteDns(appContext, dns)
    }

    suspend fun setLocalDns(dns: String) {
        PreferenceManager.setLocalDns(appContext, dns)
    }

    suspend fun setEnableDoh(enabled: Boolean) {
        PreferenceManager.setEnableDoh(appContext, enabled)
    }

    suspend fun setPerAppProxyEnabled(enabled: Boolean) {
        PreferenceManager.setPerAppProxyEnabled(appContext, enabled)
    }

    suspend fun setPerAppProxyMode(mode: String) {
        PreferenceManager.setPerAppProxyMode(appContext, mode)
    }

    suspend fun setPerAppProxyPackages(packages: Set<String>) {
        PreferenceManager.setPerAppProxyPackages(appContext, packages)
    }

    suspend fun setEnableSocksInbound(enabled: Boolean) {
        PreferenceManager.setEnableSocksInbound(appContext, enabled)
    }

    suspend fun setEnableHttpInbound(enabled: Boolean) {
        PreferenceManager.setEnableHttpInbound(appContext, enabled)
    }

    suspend fun setEnableIPv6(enabled: Boolean) {
        PreferenceManager.setEnableIPv6(appContext, enabled)
    }

    suspend fun setAutoReconnect(enabled: Boolean) {
        PreferenceManager.setAutoReconnect(appContext, enabled)
    }
}
