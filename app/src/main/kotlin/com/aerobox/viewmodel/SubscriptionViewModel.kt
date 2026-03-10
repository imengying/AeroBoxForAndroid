package com.aerobox.viewmodel

import android.app.Application
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
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
            _uiMessage.tryEmit("订阅链接无效，请使用 http/https 链接")
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
            _uiMessage.tryEmit("订阅链接无效，请使用 http/https 链接")
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
            _isLoading.value = true
            val subs = subscriptions.value
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
            (scheme == "http" || scheme == "https") && !parsed.host.isNullOrBlank()
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
                "导入失败：未解析到可用节点，请检查订阅格式"

            error != null ->
                "导入订阅失败：${toFriendlyError(error)}"

            else ->
                "导入失败：未解析到可用节点，请检查订阅格式"
        }
    }

    private fun toFriendlyError(error: Throwable): String {
        return when (error) {
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
