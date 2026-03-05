package com.aerobox.viewmodel

import android.app.Application
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.Subscription
import com.aerobox.data.repository.SubscriptionRepository
import com.aerobox.data.repository.SubscriptionImportResult
import com.aerobox.utils.NetworkUtils
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flowOf
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

    private val _selectedSubscriptionId = MutableStateFlow<Long?>(null)
    val selectedSubscriptionId: StateFlow<Long?> = _selectedSubscriptionId.asStateFlow()

    val selectedSubscriptionNodes: StateFlow<List<ProxyNode>> = _selectedSubscriptionId
        .flatMapLatest { id ->
            if (id != null) repository.getNodesBySubscription(id)
            else flowOf(emptyList())
        }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    private val _isLoading = MutableStateFlow(false)
    val isLoading: StateFlow<Boolean> = _isLoading.asStateFlow()

    private val _uiMessage = MutableSharedFlow<String>(extraBufferCapacity = 1)
    val uiMessage: SharedFlow<String> = _uiMessage.asSharedFlow()

    fun selectSubscription(subscription: Subscription) {
        _selectedSubscriptionId.value = subscription.id
    }

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
            if (_selectedSubscriptionId.value == subscription.id) {
                _selectedSubscriptionId.value = null
            }
        }
    }

    fun updateSubscription(subscription: Subscription) {
        viewModelScope.launch {
            _isLoading.value = true
            val result = runCatching {
                repository.updateSubscription(subscription)
            }
            result
                .onSuccess {
                    _uiMessage.tryEmit("订阅更新完成：${subscription.name}")
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
            var successCount = 0
            var failCount = 0
            var lastError: Throwable? = null
            subs.forEach { subscription ->
                runCatching {
                    repository.updateSubscription(subscription)
                }.onSuccess {
                    successCount++
                }.onFailure { error ->
                    failCount++
                    lastError = error
                }
            }
            if (failCount == 0) {
                _uiMessage.tryEmit("订阅更新完成：$successCount 个")
            } else {
                val suffix = lastError?.let { "，${toFriendlyError(it)}" } ?: ""
                _uiMessage.tryEmit("订阅部分更新失败（成功 $successCount / 失败 $failCount）$suffix")
            }
            _isLoading.value = false
        }
    }

    fun testAllNodesLatency() {
        viewModelScope.launch {
            val nodes = selectedSubscriptionNodes.value
            nodes.forEach { node ->
                launch {
                    val latency = NetworkUtils.pingTcp(node.server, node.port)
                    repository.updateNodeLatency(node.id, latency)
                }
            }
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
        if (result.error == null && result.nodeCount > 0) {
            return "导入成功：${result.nodeCount} 个节点"
        }

        return when {
            result.error?.message == SubscriptionRepository.NO_VALID_NODES_ERROR ->
                "导入失败：未解析到可用节点，请检查订阅格式"

            result.error != null ->
                "导入订阅失败：${toFriendlyError(result.error)}"

            else ->
                "导入失败：未解析到可用节点，请检查订阅格式"
        }
    }

    private fun toFriendlyError(error: Throwable): String {
        return when (error) {
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
}
