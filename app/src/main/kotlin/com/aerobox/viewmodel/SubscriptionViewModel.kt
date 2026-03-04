package com.aerobox.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.Subscription
import com.aerobox.data.repository.SubscriptionRepository
import com.aerobox.utils.NetworkUtils
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

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

    fun selectSubscription(subscription: Subscription) {
        _selectedSubscriptionId.value = subscription.id
    }

    fun addSubscription(name: String, url: String) {
        viewModelScope.launch {
            _isLoading.value = true
            runCatching {
                repository.addSubscription(name, url)
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
            runCatching {
                repository.updateSubscription(subscription)
            }
            _isLoading.value = false
        }
    }

    fun updateAllSubscriptions() {
        viewModelScope.launch {
            _isLoading.value = true
            runCatching {
                val subs = subscriptions.value
                repository.refreshAllSubscriptions(subs)
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
}
