package com.aerobox.data.repository

import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat
import com.aerobox.core.config.ConfigGenerator
import com.aerobox.core.geo.GeoAssetManager
import com.aerobox.core.native.SingBoxNative
import com.aerobox.data.model.ProxyNode
import com.aerobox.service.AeroBoxVpnService
import com.aerobox.utils.PreferenceManager
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.first

class VpnRepository(private val context: Context) {
    val isRunning: StateFlow<Boolean> = AeroBoxVpnService.isRunning

    fun startVpn(config: String) {
        val intent = Intent(context, AeroBoxVpnService::class.java).apply {
            action = AeroBoxVpnService.ACTION_START
            putExtra(AeroBoxVpnService.EXTRA_CONFIG, config)
        }
        ContextCompat.startForegroundService(context, intent)
    }

    fun stopVpn() {
        val intent = Intent(context, AeroBoxVpnService::class.java).apply {
            action = AeroBoxVpnService.ACTION_STOP
        }
        context.startService(intent)
    }

    /**
     * Validate config via libbox. Returns null if valid, error message otherwise.
     */
    fun checkConfig(config: String): String? =
        SingBoxNative.checkConfig(config)

    /**
     * Build a sing-box config JSON string for the given node,
     * reading all user preferences (routing, DNS, IPv6, geo paths, etc.).
     */
    suspend fun buildConfig(node: ProxyNode): String {
        val routingMode = PreferenceManager.routingModeFlow(context).first()
        val remoteDns = PreferenceManager.remoteDnsFlow(context).first()
        val localDns = PreferenceManager.localDnsFlow(context).first()
        val enableDoh = PreferenceManager.enableDohFlow(context).first()
        val enableSocksInbound = PreferenceManager.enableSocksInboundFlow(context).first()
        val enableHttpInbound = PreferenceManager.enableHttpInboundFlow(context).first()
        val enableIPv6 = PreferenceManager.enableIPv6Flow(context).first()

        return ConfigGenerator.generateSingBoxConfig(
            node = node,
            routingMode = routingMode,
            remoteDns = remoteDns,
            localDns = localDns,
            enableDoh = enableDoh,
            enableSocksInbound = enableSocksInbound,
            enableHttpInbound = enableHttpInbound,
            enableIPv6 = enableIPv6,
            geoipPath = GeoAssetManager.getGeoIpFile(context).absolutePath,
            geositePath = GeoAssetManager.getGeoSiteFile(context).absolutePath
        )
    }
}
