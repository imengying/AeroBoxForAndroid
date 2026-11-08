package com.aerobox

import android.content.Context
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.preferencesDataStoreFile
import androidx.room.Room
import com.aerobox.core.network.SharedHttpClient
import com.aerobox.data.database.AppDatabase
import com.aerobox.data.repository.BackupRepository
import com.aerobox.data.repository.HttpSubscriptionDownloader
import com.aerobox.data.repository.PreferenceSelectedNodeStore
import com.aerobox.data.repository.RecoveringSettingsStore
import com.aerobox.data.repository.SubscriptionRepository
import com.aerobox.data.repository.VpnConfigResolver
import com.aerobox.data.repository.VpnRepository
import com.aerobox.service.VpnStateManager
import com.aerobox.utils.PreferenceManager
import com.aerobox.work.SubscriptionUpdateScheduler
import kotlinx.coroutines.CoroutineScope
import org.json.JSONObject

val Context.appContainer: AppContainer
    get() = (applicationContext as AeroBoxApplication).container

/** Application-scoped composition root. Consumers receive the dependencies they actually use. */
class AppContainer(context: Context, scope: CoroutineScope) {
    private val context = context.applicationContext
    val database: AppDatabase by lazy {
        Room.databaseBuilder(this.context, AppDatabase::class.java, "aerobox.db")
            .addMigrations(AppDatabase.MIGRATION_1_2, AppDatabase.MIGRATION_2_3).build()
    }
    val settingsStore: RecoveringSettingsStore by lazy {
        RecoveringSettingsStore(
            PreferenceDataStoreFactory.create(scope = scope, produceFile = { this.context.preferencesDataStoreFile("settings") }),
            pending = { database.pendingRestoreDao() },
            applyBackup = { prefs, record ->
                PreferenceManager.restoredPreferences(prefs, JSONObject(record.settings), record.selectedNodeId)
            }
        )
    }
    val subscriptionRepository: SubscriptionRepository by lazy {
        SubscriptionRepository(this.context, database, HttpSubscriptionDownloader(SharedHttpClient.base),
            PreferenceSelectedNodeStore(this.context)) { SubscriptionUpdateScheduler.reconfigure(this.context) }
    }
    val vpnConfigResolver: VpnConfigResolver by lazy {
        VpnConfigResolver(this.context, database.proxyNodeDao(), subscriptionRepository)
    }
    val vpnRepository: VpnRepository by lazy {
        VpnRepository(this.context, vpnConfigResolver, subscriptionRepository)
    }
    val backupRepository: BackupRepository by lazy {
        BackupRepository(this.context, database, settingsStore, vpnRepository.runtimeSettingsMutex,
            { VpnStateManager.vpnState.value.serviceActive }, subscriptionRepository::isValidRemoteSubscriptionUrl)
        { SubscriptionUpdateScheduler.reconfigure(this.context) }
    }
}
