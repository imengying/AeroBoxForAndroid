package com.aerobox.viewmodel

import android.app.Application
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.aerobox.core.subscription.ParseDiagnostics
import com.aerobox.data.repository.NoValidNodesException
import com.aerobox.data.model.Subscription
import com.aerobox.data.repository.SubscriptionRepository
import com.aerobox.data.repository.SubscriptionImportResult
import com.aerobox.data.repository.SubscriptionUpdateResult
import com.aerobox.data.repository.SubscriptionUpdateSummary
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

class SubscriptionViewModel(application: Application) : AndroidViewModel(application) {
    private val appContext = application.applicationContext
    private val repository = SubscriptionRepository(appContext)

    val subscriptions = repository.getAllSubscriptions()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    private val _isLoading = MutableStateFlow(false)
    val isLoading: StateFlow<Boolean> = _isLoading.asStateFlow()

    private val _uiMessage = MutableSharedFlow<String>(extraBufferCapacity = 1)
    val uiMessage: SharedFlow<String> = _uiMessage.asSharedFlow()

    fun addSubscription(
        name: String,
        url: String,
        autoUpdate: Boolean,
        updateInterval: Long
    ) {
        if (!isValidSubscriptionUrl(url)) {
            _uiMessage.tryEmit("订阅链接无效，请使用 HTTPS 链接")
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
                    _uiMessage.tryEmit("导入订阅失败：${toFriendlyError(error)}")
                }
            _isLoading.value = false
        }
    }

    fun deleteSubscription(subscription: Subscription) {
        viewModelScope.launch {
            repository.deleteSubscription(subscription)
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
        if (!isValidSubscriptionUrl(url)) {
            _uiMessage.tryEmit("订阅链接无效，请使用 HTTPS 链接")
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
            _uiMessage.tryEmit("订阅已修改：${name.ifBlank { subscription.name }}")
        }
    }

    fun updateSubscription(subscription: Subscription) {
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
                    _uiMessage.tryEmit("更新订阅失败：${toFriendlyError(error)}")
                }
            _isLoading.value = false
        }
    }

    fun updateAllSubscriptions() {
        viewModelScope.launch {
            val subs = subscriptions.value
            if (subs.isEmpty()) {
                _uiMessage.tryEmit("暂无订阅可更新")
                return@launch
            }

            _isLoading.value = true
            val results = repository.refreshAllSubscriptions(subs)
            val successResults = results.mapNotNull { it.getOrNull() }
            val successCount = successResults.size
            val failCount = results.size - successCount
            val lastError = results.asReversed().firstNotNullOfOrNull { it.exceptionOrNull() }
            val addedCount = successResults.sumOf { it.summary.addedCount }
            val updatedCount = successResults.sumOf { it.summary.updatedCount }
            val deletedCount = successResults.sumOf { it.summary.deletedCount }
            val metadataCount = successResults.count { it.metadataFromHeader }
            if (failCount == 0) {
                _uiMessage.tryEmit(
                    buildString {
                        append("订阅更新完成：").append(successCount).append(" 个")
                        append("（新增 ").append(addedCount)
                        append(" / 更新 ").append(updatedCount)
                        append(" / 删除 ").append(deletedCount).append("）")
                        if (metadataCount > 0) {
                            append("，").append(metadataCount).append(" 个同步流量/到期信息")
                        }
                    }
                )
            } else {
                val suffix = lastError?.let { "，${toFriendlyError(it)}" } ?: ""
                _uiMessage.tryEmit(
                    buildString {
                        append("订阅部分更新失败（成功 ").append(successCount)
                        append(" / 失败 ").append(failCount)
                        append("，新增 ").append(addedCount)
                        append(" / 更新 ").append(updatedCount)
                        append(" / 删除 ").append(deletedCount)
                        append("）")
                        if (metadataCount > 0) {
                            append("，").append(metadataCount).append(" 个同步流量/到期信息")
                        }
                        append(suffix)
                    }
                )
            }
            _isLoading.value = false
        }
    }

    private fun isValidSubscriptionUrl(url: String): Boolean {
        return runCatching {
            val parsed = Uri.parse(url.trim())
            val scheme = parsed.scheme?.lowercase()
            scheme == "https" && !parsed.host.isNullOrBlank()
        }.getOrDefault(false)
    }

    private fun formatImportResultMessage(result: SubscriptionImportResult): String {
        val error = result.error
        if (error == null && result.nodeCount > 0) {
            return buildString {
                append("导入成功：").append(result.nodeCount).append(" 个节点")
                if (result.metadataFromHeader) {
                    append("，已读取订阅流量/到期信息")
                }
            }
        }

        return when {
            error?.message == SubscriptionRepository.NO_VALID_NODES_ERROR ->
                "导入失败：${friendlyNoValidNodesMessage(result.diagnostics)}"

            error != null ->
                "导入订阅失败：${toFriendlyError(error)}"

            else ->
                "导入失败：${friendlyNoValidNodesMessage(result.diagnostics)}"
        }
    }

    private fun toFriendlyError(error: Throwable): String {
        return when (error) {
            is NoValidNodesException -> friendlyNoValidNodesMessage(error.diagnostics)
            is IllegalStateException ->
                if (error.message == SubscriptionRepository.NO_VALID_NODES_ERROR) {
                    "未解析到可用节点，请检查订阅格式"
                } else {
                    error.message?.takeIf { it.isNotBlank() } ?: "配置异常"
                }
            is UnknownHostException -> "无法连接订阅服务器，请检查网络或链接"
            is SocketTimeoutException -> "连接超时，请稍后重试"
            is SSLException -> "TLS/证书校验失败，请检查订阅链接"
            is IOException -> {
                val text = error.message.orEmpty()
                if (text.startsWith("HTTP ")) {
                    "订阅服务器返回 $text"
                } else {
                    text.ifBlank { "网络异常，请稍后重试" }
                }
            }
            else -> error.message?.takeIf { it.isNotBlank() } ?: "未知错误"
        }
    }

    private fun friendlyNoValidNodesMessage(diagnostics: ParseDiagnostics): String {
        val hints = diagnostics.reasonCounts.entries
            .sortedByDescending { it.value }
            .mapNotNull { (reason, _) -> diagnosticsHint(reason) }
            .distinct()
            .take(2)

        return if (hints.isEmpty()) {
            "未解析到可用节点，请检查订阅格式"
        } else {
            "未解析到可用节点。可能原因：${hints.joinToString("；")}"
        }
    }

    private fun diagnosticsHint(reason: String): String? {
        return when (reason) {
            "unsupported_subscription_content",
            "invalid_json_content",
            "invalid_clash_yaml" -> "订阅内容不是受支持的 sing-box、Clash 或节点链接格式"

            "missing_clash_proxies" -> "Clash 配置里没有 proxies 节点列表"

            "unsupported_json_type",
            "unsupported_clash_type",
            "unsupported_uri_scheme" -> "订阅里包含当前暂不支持的节点类型或链接协议"

            "unsupported_json_transport",
            "unsupported_clash_transport",
            "unsupported_json_network" -> "订阅里包含当前暂不支持的传输配置"

            "missing_json_endpoint",
            "missing_clash_endpoint" -> "部分节点缺少服务器地址或端口"

            "invalid_json_item",
            "invalid_clash_proxy_item" -> "订阅里的部分节点条目格式不正确"

            "invalid_or_unsupported_shadowsocks_uri",
            "invalid_or_unsupported_vmess_uri",
            "invalid_or_unsupported_vless_uri",
            "invalid_or_unsupported_trojan_uri",
            "invalid_or_unsupported_hysteria2_uri",
            "invalid_or_unsupported_tuic_uri",
            "invalid_or_unsupported_socks_uri",
            "invalid_or_unsupported_http_uri" -> "节点链接格式不正确，或包含当前暂不支持的参数"

            "informational_entry",
            "duplicate_entry" -> null

            else -> null
        }
    }

    private fun formatUpdateResultMessage(
        subscriptionName: String,
        result: SubscriptionUpdateResult
    ): String {
        val summaryText = formatSummary(result.summary)
        return buildString {
            append("订阅更新完成：").append(subscriptionName)
            if (summaryText.isNotBlank()) {
                append("（").append(summaryText).append("）")
            }
            if (result.metadataFromHeader) {
                append("，已同步流量/到期信息")
            }
        }
    }

    private fun formatSummary(summary: SubscriptionUpdateSummary): String {
        return if (summary.changedCount == 0) {
            "无节点变更"
        } else {
            buildString {
                append("新增 ").append(summary.addedCount)
                append(" / 更新 ").append(summary.updatedCount)
                append(" / 删除 ").append(summary.deletedCount)
            }
        }
    }
}
