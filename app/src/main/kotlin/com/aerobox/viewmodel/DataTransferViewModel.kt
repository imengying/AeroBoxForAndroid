package com.aerobox.viewmodel

import android.app.Application
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.viewModelScope
import com.aerobox.R
import com.aerobox.core.config.ConfigGenerator
import com.aerobox.core.errors.LocalizedException
import com.aerobox.data.repository.BackupRepository
import com.aerobox.data.repository.DocumentIo
import com.aerobox.data.repository.ImportGroupTarget
import com.aerobox.data.model.Subscription
import java.io.File
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Keeps file and batch operations alive across screen recreation. */
class DataTransferViewModel(
    application: Application,
    savedStateHandle: SavedStateHandle,
    private val repository: com.aerobox.data.repository.SubscriptionRepository,
    private val nodeDao: com.aerobox.data.database.ProxyNodeDao,
    private val backupRepository: BackupRepository
) : AndroidViewModel(application) {
    private val context: Application get() = getApplication()
    private val _busy = MutableStateFlow(false)
    val busy = _busy.asStateFlow()
    private val _message = MutableStateFlow<String?>(null)
    val message = _message.asStateFlow()
    private val pendingNodeExport = PendingNodeExport(savedStateHandle, File(application.noBackupFilesDir, "node-exports"))
    private val selection = NodeSelectionStore(savedStateHandle, File(application.noBackupFilesDir, "node-selections"),
        viewModelScope, ::reportFailure)
    val selectedNodes = selection.ids
    val selectionReady = selection.ready

    fun selectNodes(ids: Collection<Long>) { selection.replace(ids) }

    fun dismissMessage() { _message.value = null }

    fun observeSubscription(id: Long) = repository.observeSubscriptionById(id)
    fun observeNodes(id: Long) = repository.observeNodesInGroup(id)
    fun observeLocalGroups() = repository.getLocalGroups()
    suspend fun renameLocalGroup(group: Subscription, name: String) = repository.renameLocalGroup(group, name)
    fun deleteGroup(group: Subscription) = runOperation { repository.deleteSubscription(group) }

    suspend fun prepareNodeExport(ids: List<Long>): Boolean {
        if (_busy.value) return false
        _busy.value = true
        return try {
            selection.flush()
            pendingNodeExport.prepare(ids)
            true
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            reportFailure(error)
            false
        } finally {
            _busy.value = false
        }
    }

    fun cancelNodeExport() {
        val requestId = pendingNodeExport.requestId
        viewModelScope.launch { pendingNodeExport.clear(requestId) }
    }

    fun exportNodes(uri: Uri) {
        val requestId = pendingNodeExport.requestId
        runOperation(onSuccess = { pendingNodeExport.clear(requestId) }) {
            val ids = pendingNodeExport.load(requestId)
                ?: throw LocalizedException(R.string.node_export_request_unavailable)
            val nodes = ids.chunked(500).flatMap { nodeDao.getNodesByIds(it) }
            check(nodes.isNotEmpty()) { context.getString(R.string.current_node_unavailable) }
            DocumentIo.write(context, uri, ConfigGenerator.exportNodes(nodes))
        }
    }

    fun copyNodes(ids: List<Long>, target: ImportGroupTarget) = runOperation {
        repository.copyNodes(ids, target).error?.let { throw it }
    }

    fun deleteNodes(ids: List<Long>) = runOperation { repository.deleteNodes(ids) }
    fun exportBackup(uri: Uri) = runOperation { backupRepository.export(uri) }
    fun restoreBackup(uri: Uri) = runOperation { backupRepository.restore(uri) }

    fun exportDiagnostics(uri: Uri) = runOperation {
        val state = com.aerobox.service.VpnStateManager.vpnState.value
        val settings = com.aerobox.utils.PreferenceManager.readVpnConfigPreferences(context)
        val logs = (com.aerobox.core.logging.CrashDiagnostics.entries.value +
            com.aerobox.core.logging.RuntimeLogBuffer.lines.value).sortedBy { it.timestamp }
        val report = org.json.JSONObject()
            .put("appVersion", com.aerobox.BuildConfig.VERSION_NAME)
            .put("coreVersion", com.aerobox.core.native.SingBoxNative.version.value)
            .put("androidApi", android.os.Build.VERSION.SDK_INT)
            .put("androidRelease", android.os.Build.VERSION.RELEASE)
            .put("manufacturer", android.os.Build.MANUFACTURER)
            .put("model", android.os.Build.MODEL)
            .put("systemBuild", android.os.Build.DISPLAY)
            .put("securityPatch", android.os.Build.VERSION.SECURITY_PATCH)
            .put("abis", org.json.JSONArray(android.os.Build.SUPPORTED_ABIS.toList()))
            .put("connected", state.isConnected)
            .put("serviceActive", com.aerobox.service.VpnStateManager.vpnState.value.serviceActive)
            .put("vpnPermissionGranted", android.net.VpnService.prepare(context) == null)
            .put("batteryOptimizationExempt", context.getSystemService(android.os.PowerManager::class.java)
                ?.isIgnoringBatteryOptimizations(context.packageName) ?: false)
            .put("notificationsEnabled", androidx.core.app.NotificationManagerCompat.from(context).areNotificationsEnabled())
            .put("protocol", state.currentNode?.type?.name ?: "")
            .put("routingMode", settings.routingMode.name)
            .put("ipv6Mode", settings.ipv6Mode.name)
            .put("logLevel", "error")
            .put("logs", org.json.JSONArray().apply {
                logs.forEach { put(org.json.JSONObject().put("time", it.timestamp).put("message", it.message)) }
            })
        DocumentIo.write(context, uri, report.toString(2))
    }

    private fun reportFailure(error: Exception) {
        val details = if (error is LocalizedException) error.resolveMessage(context) else error.message.orEmpty()
        _message.value = "${context.getString(R.string.operation_failed)}: $details"
    }

    private fun runOperation(onSuccess: suspend () -> Unit = {}, action: suspend () -> Unit) {
        if (_busy.value) return
        _busy.value = true
        viewModelScope.launch {
            try {
                withContext(Dispatchers.IO) { action() }
                onSuccess()
                _message.value = context.getString(R.string.operation_complete)
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                reportFailure(error)
            } finally {
                _busy.value = false
            }
        }
    }
}
