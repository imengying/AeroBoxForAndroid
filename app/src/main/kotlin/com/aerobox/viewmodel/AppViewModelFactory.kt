package com.aerobox.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.createSavedStateHandle
import androidx.lifecycle.viewmodel.CreationExtras
import com.aerobox.appContainer
import com.aerobox.data.repository.AppListRepository
import com.aerobox.data.repository.AppUpdateRepository
import com.aerobox.core.errors.LocalizedException
import com.aerobox.viewmodel.nodeeditor.NodeDraftStore
import com.aerobox.utils.PreferenceManager
import kotlinx.coroutines.flow.first
import java.io.File
import java.util.UUID

object AppViewModelFactory : ViewModelProvider.Factory {
    override fun <T : ViewModel> create(modelClass: Class<T>, extras: CreationExtras): T {
        val application = requireNotNull(extras[ViewModelProvider.AndroidViewModelFactory.APPLICATION_KEY])
        val dependencies = application.appContainer
        val model = when (modelClass) {
            HomeViewModel::class.java -> HomeViewModel(application, dependencies.database.proxyNodeDao(),
                dependencies.vpnRepository, dependencies.subscriptionRepository)
            SubscriptionViewModel::class.java -> SubscriptionViewModel(application, dependencies.subscriptionRepository)
            SettingsViewModel::class.java -> SettingsViewModel(application, dependencies.vpnRepository,
                AppListRepository(application), AppUpdateRepository())
            PerAppSelectionViewModel::class.java -> {
                val savedState = extras.createSavedStateHandle()
                val token = savedState.get<String>("app_selection_file")?.takeIf(NodeIdFile::isValidToken)
                    ?: UUID.randomUUID().toString().also { savedState["app_selection_file"] = it }
                PerAppSelectionViewModel(
                    load = { PreferenceManager.perAppProxyPackagesFlow(application).first() },
                    apply = { draft ->
                        dependencies.vpnRepository.runtimeSettings.update(
                            readCurrent = { PreferenceManager.perAppProxyPackagesFlow(application).first() },
                            persist = { PreferenceManager.setPerAppProxyPackages(application, it) },
                            transform = draft::applyTo
                        ).applied
                    },
                    drafts = AppSelectionDraftStore(File(application.noBackupFilesDir, "app-selections/$token"))
                )
            }
            DataTransferViewModel::class.java -> DataTransferViewModel(application, extras.createSavedStateHandle(),
                dependencies.subscriptionRepository, dependencies.database.proxyNodeDao(), dependencies.backupRepository)
            NodeEditViewModel::class.java -> {
                val savedState = extras.createSavedStateHandle()
                val token = savedState.get<String>("node_draft_file")?.takeIf(NodeIdFile::isValidToken)
                    ?: UUID.randomUUID().toString().also { savedState["node_draft_file"] = it }
                NodeEditViewModel(
                    nodeId = requireNotNull(savedState.get<Long>("nodeId")),
                    load = dependencies.database.proxyNodeDao()::getNodeById,
                    isRemote = { id -> dependencies.database.subscriptionDao().getById(id)?.url?.isNotBlank() == true },
                    update = dependencies.subscriptionRepository::updateNode,
                    drafts = NodeDraftStore(File(application.noBackupFilesDir, "node-drafts/$token")),
                    errorMessage = { if (it is LocalizedException) it.resolveMessage(application) else it.message.orEmpty() }
                )
            }
            else -> error("Unsupported ViewModel: ${modelClass.name}")
        }
        return modelClass.cast(model)!!
    }
}
