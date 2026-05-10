package com.aerobox.viewmodel

import android.app.Application
import android.net.Uri
import android.provider.OpenableColumns
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.aerobox.R
import com.aerobox.AeroBoxApplication
import com.aerobox.core.subscription.ParseDiagnostics
import com.aerobox.data.model.Subscription
import com.aerobox.data.model.isLocalGroup
import com.aerobox.data.repository.ImportGroupTarget
import com.aerobox.data.repository.NoValidNodesException
import com.aerobox.data.repository.PreparedLocalImport
import com.aerobox.data.repository.SubscriptionImportResult
import com.aerobox.data.repository.SubscriptionRepository
import com.aerobox.data.repository.SubscriptionUpdateResult
import com.aerobox.data.repository.SubscriptionUpdateSummary
import com.aerobox.utils.AppLocaleManager
import com.aerobox.utils.PreferenceManager
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import java.io.IOException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import javax.net.ssl.SSLException

// Content that was successfully parsed but is waiting for the user to choose a
// target local group. The UI observes this and shows GroupPickerDialog.
data class PendingImport(
    val prepared: PreparedLocalImport,
    val suggestedName: String,
    val nodeCount: Int
)

// A subscription URL was detected via QR scan or external intent. We defer the
// actual fetch/import until the user confirms (and potentially renames it) in
// the subscription editor dialog.
data class PendingSubscriptionLink(
    val url: String,
    val suggestedName: String,
    val autoUpdate: Boolean,
    val updateInterval: Long
)

class SubscriptionViewModel(application: Application) : AndroidViewModel(application) {
    private val appContext = application.applicationContext
    private val repository = AeroBoxApplication.subscriptionRepository
    private val languageTag = PreferenceManager.languageTagFlow(appContext)
        .stateIn(viewModelScope, SharingStarted.Eagerly, AppLocaleManager.SYSTEM_LANGUAGE_TAG)

    val subscriptions = repository.getAllSubscriptions()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    val localGroups = repository.getLocalGroups()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    val ungroupedNodeCount = repository.observeUngroupedNodeCount()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), 0)

    private val _isLoading = MutableStateFlow(false)
    val isLoading: StateFlow<Boolean> = _isLoading.asStateFlow()

    private val _uiMessage = MutableSharedFlow<String>(extraBufferCapacity = 1)
    val uiMessage: SharedFlow<String> = _uiMessage.asSharedFlow()

    private val _pendingImport = MutableStateFlow<PendingImport?>(null)
    val pendingImport: StateFlow<PendingImport?> = _pendingImport.asStateFlow()

    private val _pendingSubscriptionLink = MutableStateFlow<PendingSubscriptionLink?>(null)
    val pendingSubscriptionLink: StateFlow<PendingSubscriptionLink?> =
        _pendingSubscriptionLink.asStateFlow()

    fun addSubscription(
        name: String,
        url: String,
        autoUpdate: Boolean,
        updateInterval: Long
    ) {
        if (!isValidSubscriptionUrl(url)) {
            _uiMessage.tryEmit(appString(R.string.subscription_link_invalid))
            return
        }

        viewModelScope.launch {
            _isLoading.value = true
            val result = runCatching {
                repository.addSubscription(
                    name = name,
                    url = url,
                    autoUpdate = autoUpdate,
                    updateInterval = updateInterval
                )
            }
            result
                .onSuccess { importResult ->
                    _uiMessage.tryEmit(formatImportResultMessage(importResult))
                }
                .onFailure { error ->
                    _uiMessage.tryEmit(appString(R.string.import_subscription_failed, toFriendlyError(error)))
                }
            _isLoading.value = false
        }
    }

    fun deleteSubscription(subscription: Subscription) {
        viewModelScope.launch {
            repository.deleteSubscription(subscription)
            val tag = appString(
                if (subscription.isLocalGroup()) R.string.group_noun else R.string.subscription_noun
            )
            _uiMessage.tryEmit(appString(R.string.deleted_item_format, tag, subscription.name))
        }
    }


    fun reorderSubscriptions(orderedSubscriptions: List<Subscription>) {
        viewModelScope.launch {
            repository.reorderSubscriptions(orderedSubscriptions)
        }
    }

    fun editSubscription(
        subscription: Subscription,
        name: String,
        url: String,
        autoUpdate: Boolean,
        updateInterval: Long
    ) {
        val isLocal = subscription.isLocalGroup()
        if (!isLocal && !isValidSubscriptionUrl(url)) {
            _uiMessage.tryEmit(appString(R.string.subscription_link_invalid))
            return
        }

        viewModelScope.launch {
            repository.updateSubscriptionDetails(
                subscription = subscription,
                name = name,
                url = url,
                autoUpdate = autoUpdate,
                updateInterval = updateInterval
            )
            val tag = appString(
                if (isLocal) R.string.group_noun else R.string.subscription_noun
            )
            _uiMessage.tryEmit(
                appString(
                    R.string.modified_item_format,
                    tag,
                    name.ifBlank { subscription.name }
                )
            )
        }
    }

    fun updateSubscription(subscription: Subscription) {
        if (subscription.isLocalGroup()) {
            _uiMessage.tryEmit(appString(R.string.local_group_no_refresh))
            return
        }
        viewModelScope.launch {
            _isLoading.value = true
            val result = runCatching {
                repository.updateSubscription(subscription)
            }
            result
                .onSuccess { updateResult ->
                    _uiMessage.tryEmit(formatUpdateResultMessage(subscription.name, updateResult))
                }
                .onFailure { error ->
                    _uiMessage.tryEmit(appString(R.string.update_subscription_failed, toFriendlyError(error)))
                }
            _isLoading.value = false
        }
    }

    fun updateAllSubscriptions() {
        viewModelScope.launch {
            val subs = subscriptions.value
            val refreshable = subs.filterNot { it.isLocalGroup() }
            if (refreshable.isEmpty()) {
                _uiMessage.tryEmit(appString(R.string.no_refreshable_subscription))
                return@launch
            }

            _isLoading.value = true
            val results = repository.refreshAllSubscriptions(refreshable)
            val successResults = results.mapNotNull { it.getOrNull() }
            val successCount = successResults.size
            val failCount = results.size - successCount
            val lastError = results.asReversed().firstNotNullOfOrNull { it.exceptionOrNull() }
            val addedCount = successResults.sumOf { it.summary.addedCount }
            val updatedCount = successResults.sumOf { it.summary.updatedCount }
            val deletedCount = successResults.sumOf { it.summary.deletedCount }
            val metadataCount = successResults.count { it.metadataFromHeader }
            val insecureCount = successResults.sumOf { it.insecureNodeCount }
            if (failCount == 0) {
                _uiMessage.tryEmit(
                    buildString {
                        append(
                            appString(
                                R.string.subscription_update_complete_all_format,
                                successCount,
                                addedCount,
                                updatedCount,
                                deletedCount
                            )
                        )
                        if (metadataCount > 0) {
                            append(appString(R.string.subscription_update_metadata_suffix, metadataCount))
                        }
                        if (insecureCount > 0) {
                            append('\n')
                            append(
                                appString(
                                    R.string.warning_insecure_nodes_format,
                                    insecureCount
                                )
                            )
                        }
                    }
                )
            } else {
                val suffix = lastError?.let {
                    appString(R.string.subscription_update_partial_fail_error_suffix, toFriendlyError(it))
                } ?: ""
                _uiMessage.tryEmit(
                    buildString {
                        append(
                            appString(
                                R.string.subscription_update_partial_fail_format,
                                successCount,
                                failCount,
                                addedCount,
                                updatedCount,
                                deletedCount
                            )
                        )
                        if (metadataCount > 0) {
                            append(appString(R.string.subscription_update_metadata_suffix, metadataCount))
                        }
                        if (insecureCount > 0) {
                            append('\n')
                            append(
                                appString(
                                    R.string.warning_insecure_nodes_format,
                                    insecureCount
                                )
                            )
                        }
                        append(suffix)
                    }
                )
            }
            _isLoading.value = false
        }
    }

    // Handles QR scan results and external VIEW intents. Subscription URLs are
    // surfaced via [pendingSubscriptionLink] so the user can edit the name
    // before committing. Inline node content goes via [pendingImport] for
    // group selection.
    fun importExternalSource(
        source: String,
        nameHint: String = "",
        autoUpdate: Boolean = true,
        updateInterval: Long = SubscriptionRepository.DEFAULT_UPDATE_INTERVAL_MS
    ) {
        val trimmedSource = source.trim()
        if (trimmedSource.isBlank()) {
            _uiMessage.tryEmit(appString(R.string.import_empty_content))
            return
        }

        if (repository.isValidRemoteSubscriptionUrl(trimmedSource)) {
            _pendingSubscriptionLink.value = PendingSubscriptionLink(
                url = trimmedSource,
                suggestedName = nameHint.trim(),
                autoUpdate = autoUpdate,
                updateInterval = updateInterval
            )
            return
        }

        viewModelScope.launch {
            _isLoading.value = true
            runCatching { repository.prepareLocalImport(trimmedSource, nameHint.trim()) }
                .onSuccess { prepared ->
                    _pendingImport.value = PendingImport(
                        prepared = prepared,
                        suggestedName = nameHint.trim().ifBlank { prepared.resolvedName.orEmpty() },
                        nodeCount = prepared.nodes.size
                    )
                }
                .onFailure { error ->
                    _uiMessage.tryEmit(appString(R.string.import_failed, toFriendlyError(error)))
                }
            _isLoading.value = false
        }
    }

    // Called from NodeImportDialog — user has already picked a target in-dialog,
    // so this runs prepare + commit without a separate picker step.
    fun importNodeContent(
        source: String,
        target: ImportGroupTarget
    ) {
        val trimmedSource = source.trim()
        if (trimmedSource.isBlank()) {
            _uiMessage.tryEmit(appString(R.string.node_empty_content))
            return
        }
        if (repository.isValidRemoteSubscriptionUrl(trimmedSource)) {
            _uiMessage.tryEmit(appString(R.string.node_content_use_subscription_entry))
            return
        }
        viewModelScope.launch {
            _isLoading.value = true
            runCatching {
                val prepared = repository.prepareLocalImport(trimmedSource, nameHintFrom(target))
                repository.commitLocalImport(prepared, target)
            }
                .onSuccess { importResult ->
                    _uiMessage.tryEmit(formatImportResultMessage(importResult))
                }
                .onFailure { error ->
                    _uiMessage.tryEmit(appString(R.string.import_failed, toFriendlyError(error)))
                }
            _isLoading.value = false
        }
    }

    fun importLocalFile(uri: Uri) {
        viewModelScope.launch {
            _isLoading.value = true
            val result = runCatching {
                val resolver = appContext.contentResolver
                var displayName: String? = null
                var sizeBytes: Long? = null
                resolver.query(uri, null, null, null, null)?.use { cursor ->
                    if (cursor.moveToFirst()) {
                        val nameIdx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                        if (nameIdx >= 0) displayName = cursor.getString(nameIdx)
                        val sizeIdx = cursor.getColumnIndex(OpenableColumns.SIZE)
                        if (sizeIdx >= 0) sizeBytes = cursor.getLong(sizeIdx)
                    }
                }
                if (sizeBytes != null && sizeBytes > 8L * 1024L * 1024L) {
                    throw IllegalStateException(appString(R.string.local_file_too_large))
                }
                val content = resolver.openInputStream(uri)?.use { input -> input.readBytes() }
                    ?.toString(Charsets.UTF_8)
                    ?.removePrefix("\uFEFF")
                    ?.trim()
                    ?: throw IllegalStateException(appString(R.string.cannot_read_local_file))
                val baseName = displayName.orEmpty().substringBeforeLast('.')
                val prepared = repository.prepareLocalImport(content, baseName)
                prepared to baseName
            }
            result
                .onSuccess { (prepared, baseName) ->
                    _pendingImport.value = PendingImport(
                        prepared = prepared,
                        suggestedName = baseName.ifBlank { prepared.resolvedName.orEmpty() },
                        nodeCount = prepared.nodes.size
                    )
                }
                .onFailure { error ->
                    _uiMessage.tryEmit(appString(R.string.import_local_file_failed, toFriendlyError(error)))
                }
            _isLoading.value = false
        }
    }

    fun confirmPendingImport(target: ImportGroupTarget) {
        val current = _pendingImport.value ?: return
        _pendingImport.value = null
        viewModelScope.launch {
            _isLoading.value = true
            runCatching { repository.commitLocalImport(current.prepared, target) }
                .onSuccess { importResult ->
                    _uiMessage.tryEmit(formatImportResultMessage(importResult))
                }
                .onFailure { error ->
                    _uiMessage.tryEmit(appString(R.string.import_failed, toFriendlyError(error)))
                }
            _isLoading.value = false
        }
    }

    fun cancelPendingImport() {
        _pendingImport.value = null
    }

    fun confirmPendingSubscriptionLink(
        name: String,
        url: String,
        autoUpdate: Boolean,
        updateInterval: Long
    ) {
        _pendingSubscriptionLink.value = null
        addSubscription(
            name = name,
            url = url,
            autoUpdate = autoUpdate,
            updateInterval = updateInterval
        )
    }

    fun cancelPendingSubscriptionLink() {
        _pendingSubscriptionLink.value = null
    }

    private fun nameHintFrom(target: ImportGroupTarget): String {
        return when (target) {
            is ImportGroupTarget.New -> target.name
            is ImportGroupTarget.Existing -> ""
            is ImportGroupTarget.Ungrouped -> ""
        }
    }

    private fun isValidSubscriptionUrl(url: String): Boolean {
        return repository.isValidRemoteSubscriptionUrl(url)
    }

    private fun formatImportResultMessage(result: SubscriptionImportResult): String {
        val error = result.error
        if (error == null && result.nodeCount > 0) {
            val successPrefix = if (result.subscriptionId == 0L) {
                appString(R.string.import_success_ungrouped_format, result.nodeCount)
            } else {
                appString(R.string.import_success_with_count_format, result.nodeCount)
            }
            return buildString {
                append(successPrefix)
                if (result.metadataFromHeader) {
                    append(appString(R.string.import_success_metadata_suffix))
                }
                if (result.insecureNodeCount > 0) {
                    append('\n')
                    append(
                        appString(
                            R.string.warning_insecure_nodes_format,
                            result.insecureNodeCount
                        )
                    )
                }
            }
        }

        val detail = when {
            error?.message == SubscriptionRepository.NO_VALID_NODES_ERROR ->
                friendlyNoValidNodesMessage(result.diagnostics)

            error?.message == SubscriptionRepository.LOCAL_GROUP_TARGET_INVALID_ERROR ->
                appString(R.string.import_fail_local_group_target)

            error?.message == SubscriptionRepository.INVALID_SUBSCRIPTION_URL_ERROR ->
                appString(R.string.subscription_link_invalid)

            error != null ->
                toFriendlyError(error)

            else ->
                friendlyNoValidNodesMessage(result.diagnostics)
        }
        return appString(R.string.import_failed, detail)
    }

    private fun toFriendlyError(error: Throwable): String {
        return when (error) {
            is NoValidNodesException -> friendlyNoValidNodesMessage(error.diagnostics)
            is IllegalArgumentException ->
                when (error.message) {
                    SubscriptionRepository.INVALID_SUBSCRIPTION_URL_ERROR ->
                        appString(R.string.subscription_link_invalid)
                    else -> error.message?.takeIf { it.isNotBlank() }
                        ?: appString(R.string.error_config_exception)
                }
            is IllegalStateException ->
                when (error.message) {
                    SubscriptionRepository.NO_VALID_NODES_ERROR ->
                        appString(R.string.error_no_valid_nodes)
                    SubscriptionRepository.LOCAL_GROUP_TARGET_INVALID_ERROR ->
                        appString(R.string.import_fail_local_group_target)
                    else -> error.message?.takeIf { it.isNotBlank() }
                        ?: appString(R.string.error_config_exception)
                }
            is UnknownHostException -> appString(R.string.error_unknown_host)
            is SocketTimeoutException -> appString(R.string.error_socket_timeout)
            is SSLException -> appString(R.string.error_ssl)
            is IOException -> {
                val text = error.message.orEmpty()
                when {
                    text == SubscriptionRepository.SUBSCRIPTION_RESPONSE_TOO_LARGE_ERROR ->
                        appString(R.string.error_subscription_response_too_large)
                    text.startsWith("HTTP ") ->
                        appString(R.string.error_http_server_returned_format, text)
                    text.isNotBlank() -> text
                    else -> appString(R.string.error_network_general)
                }
            }
            else -> error.message?.takeIf { it.isNotBlank() }
                ?: appString(R.string.error_unknown)
        }
    }

    private fun friendlyNoValidNodesMessage(diagnostics: ParseDiagnostics): String {
        val hints = diagnostics.reasonCounts.entries
            .sortedByDescending { it.value }
            .mapNotNull { (reason, _) -> diagnosticsHint(reason) }
            .distinct()
            .take(2)

        return if (hints.isEmpty()) {
            appString(R.string.error_no_valid_nodes)
        } else {
            appString(R.string.error_no_valid_nodes_hints_format, hints.joinToString("；"))
        }
    }

    private fun diagnosticsHint(reason: String): String? {
        val resId = when (reason) {
            "unsupported_subscription_content",
            "invalid_json_content",
            "invalid_clash_yaml" -> R.string.diag_unsupported_subscription_content

            "missing_clash_proxies" -> R.string.diag_missing_clash_proxies

            "unsupported_json_type",
            "unsupported_clash_type",
            "unsupported_uri_scheme" -> R.string.diag_unsupported_type_or_scheme

            "unsupported_json_transport",
            "unsupported_clash_transport",
            "unsupported_json_network" -> R.string.diag_unsupported_transport

            "missing_json_endpoint",
            "missing_clash_endpoint" -> R.string.diag_missing_endpoint

            "invalid_json_item",
            "invalid_clash_proxy_item" -> R.string.diag_invalid_item

            "invalid_or_unsupported_shadowsocks_uri",
            "invalid_or_unsupported_vmess_uri",
            "invalid_or_unsupported_vless_uri",
            "invalid_or_unsupported_trojan_uri",
            "invalid_or_unsupported_hysteria2_uri",
            "invalid_or_unsupported_tuic_uri",
            "invalid_or_unsupported_naive_uri",
            "invalid_or_unsupported_socks_uri",
            "invalid_or_unsupported_http_uri" -> R.string.diag_invalid_uri

            "informational_entry",
            "duplicate_entry" -> return null

            else -> return null
        }
        return appString(resId)
    }

    private fun formatUpdateResultMessage(
        subscriptionName: String,
        result: SubscriptionUpdateResult
    ): String {
        val summaryText = formatSummary(result.summary)
        return buildString {
            append(appString(R.string.subscription_update_complete_format, subscriptionName))
            if (summaryText.isNotBlank()) {
                append(appString(R.string.subscription_update_summary_paren_format, summaryText))
            }
            if (result.metadataFromHeader) {
                append(appString(R.string.subscription_update_metadata_single_suffix))
            }
            if (result.insecureNodeCount > 0) {
                append('\n')
                append(
                    appString(
                        R.string.warning_insecure_nodes_format,
                        result.insecureNodeCount
                    )
                )
            }
        }
    }

    private fun formatSummary(summary: SubscriptionUpdateSummary): String {
        return if (summary.changedCount == 0) {
            appString(R.string.summary_no_change)
        } else {
            appString(
                R.string.summary_changes_format,
                summary.addedCount,
                summary.updatedCount,
                summary.deletedCount
            )
        }
    }

    private fun localizedStringContext() = AppLocaleManager.localizedContext(appContext, languageTag.value)

    private fun appString(resId: Int, vararg formatArgs: Any): String {
        val context = localizedStringContext()
        return if (formatArgs.isEmpty()) {
            context.getString(resId)
        } else {
            context.getString(resId, *formatArgs)
        }
    }
}
