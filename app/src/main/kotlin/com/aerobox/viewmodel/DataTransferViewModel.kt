package com.aerobox.viewmodel

import android.app.Application
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.aerobox.AeroBoxApplication
import com.aerobox.R
import com.aerobox.core.config.ConfigGenerator
import com.aerobox.core.errors.LocalizedException
import com.aerobox.data.repository.BackupRepository
import com.aerobox.data.repository.DocumentIo
import com.aerobox.data.repository.ImportGroupTarget
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Keeps file and batch operations alive across screen recreation. */
class DataTransferViewModel(application: Application) : AndroidViewModel(application) {
    private val context: Application get() = getApplication()
    private val repository get() = AeroBoxApplication.subscriptionRepository
    private val _busy = MutableStateFlow(false)
    val busy = _busy.asStateFlow()
    private val _message = MutableStateFlow<String?>(null)
    val message = _message.asStateFlow()
    var exportNodeIds: List<Long> = emptyList()
        private set

    fun dismissMessage() { _message.value = null }

    fun prepareNodeExport(ids: List<Long>) { exportNodeIds = ids.toList() }

    fun exportNodes(uri: Uri) = runOperation {
        val ids = exportNodeIds
        val nodes = ids.chunked(500).flatMap { AeroBoxApplication.database.proxyNodeDao().getNodesByIds(it) }
        check(nodes.isNotEmpty()) { context.getString(R.string.current_node_unavailable) }
        DocumentIo.write(context, uri, ConfigGenerator.exportNodes(nodes))
    }

    fun copyNodes(ids: List<Long>, target: ImportGroupTarget) = runOperation {
        repository.copyNodes(ids, target).error?.let { throw it }
    }

    fun deleteNodes(ids: List<Long>) = runOperation { repository.deleteNodes(ids) }
    fun exportBackup(uri: Uri) = runOperation { BackupRepository(context).export(uri) }
    fun restoreBackup(uri: Uri) = runOperation { BackupRepository(context).restore(uri) }

    fun exportDiagnostics(uri: Uri) = runOperation {
        val state = com.aerobox.service.VpnStateManager.vpnState.value
        val settings = com.aerobox.utils.PreferenceManager.readVpnConfigPreferences(context)
        val logs = (com.aerobox.core.logging.CrashDiagnostics.entries.value +
            com.aerobox.core.logging.RuntimeLogBuffer.lines.value).sortedBy { it.timestamp }
        val report = org.json.JSONObject()
            .put("appVersion", com.aerobox.BuildConfig.VERSION_NAME)
            .put("coreVersion", com.aerobox.core.native.SingBoxNative.version.value)
            .put("androidApi", android.os.Build.VERSION.SDK_INT)
            .put("abis", org.json.JSONArray(android.os.Build.SUPPORTED_ABIS.toList()))
            .put("connected", state.isConnected)
            .put("protocol", state.currentNode?.type?.name ?: "")
            .put("routingMode", settings.routingMode.name)
            .put("ipv6Mode", settings.ipv6Mode.name)
            .put("logLevel", "error")
            .put("logs", org.json.JSONArray().apply {
                logs.forEach { put(org.json.JSONObject().put("time", it.timestamp).put("message", it.message)) }
            })
        DocumentIo.write(context, uri, report.toString(2))
    }

    private fun runOperation(action: suspend () -> Unit) {
        if (_busy.value) return
        _busy.value = true
        viewModelScope.launch {
            try {
                withContext(Dispatchers.IO) { action() }
                _message.value = context.getString(R.string.operation_complete)
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                val details = if (error is LocalizedException) error.resolveMessage(context) else error.message.orEmpty()
                _message.value = "${context.getString(R.string.operation_failed)}: $details"
            } finally {
                _busy.value = false
            }
        }
    }
}
