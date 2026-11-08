package com.aerobox.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.aerobox.R
import com.aerobox.data.model.ProxyNode
import com.aerobox.data.repository.NodeUpdateResult
import com.aerobox.viewmodel.nodeeditor.NodeDraftStore
import com.aerobox.viewmodel.nodeeditor.NodeEditDraft
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class NodeEditState(
    val draft: NodeEditDraft? = null,
    val loading: Boolean = true,
    val saving: Boolean = false,
    val remote: Boolean = false,
    val conflict: Boolean = false,
    val missing: Boolean = false,
    val completed: Boolean = false,
    val message: Int? = null,
    val details: String? = null
)

/** Owns loading, durable drafts and save lifetime independently of the Compose screen. */
class NodeEditViewModel(
    private val nodeId: Long,
    private val load: suspend (Long) -> ProxyNode?,
    private val isRemote: suspend (Long) -> Boolean,
    private val update: suspend (ProxyNode, ProxyNode) -> NodeUpdateResult,
    private val drafts: NodeDraftStore,
    private val errorMessage: (Exception) -> String
) : ViewModel() {
    private val mutable = MutableStateFlow(NodeEditState())
    val state = mutable.asStateFlow()
    private var writer: Job? = null
    private var loader: Job? = null

    init { reload(discard = false) }

    fun change(key: String, value: String) {
        val current = mutable.value
        if (current.saving || current.loading || current.completed || current.missing) return
        val draft = current.draft?.change(key, value) ?: return
        mutable.value = current.copy(draft = draft)
        val previous = writer
        previous?.cancel()
        writer = viewModelScope.launch {
            // Keep the write chain ordered even if another keystroke cancels this waiter.
            withContext(NonCancellable) { previous?.join() }
            delay(150)
            try { drafts.write(draft) }
            catch (e: CancellationException) { throw e }
            catch (_: Exception) { mutable.value = mutable.value.copy(message = R.string.node_edit_draft_error) }
        }
    }

    fun reload(discard: Boolean = true) {
        if (mutable.value.saving || mutable.value.completed || loader?.isActive == true) return
        mutable.value = mutable.value.copy(loading = true)
        loader = viewModelScope.launch {
            writer?.cancelAndJoin()
            try {
                if (discard) drafts.clear()
                val node = load(nodeId)
                if (node == null) {
                    mutable.value = NodeEditState(loading = false, missing = true)
                    return@launch
                }
                var warning: Int? = null
                val stored = try { drafts.read()?.takeIf { it.nodeId == nodeId } }
                catch (e: CancellationException) { throw e }
                catch (_: Exception) { warning = R.string.node_edit_draft_error; null }
                mutable.value = NodeEditState(
                    draft = NodeEditDraft(node, stored?.edits.orEmpty(), stored?.fingerprint ?: NodeDraftStore.fingerprint(node)), loading = false,
                    remote = node.subscriptionId > 0 && isRemote(node.subscriptionId),
                    conflict = stored != null && stored.fingerprint != NodeDraftStore.fingerprint(node),
                    message = warning
                )
            } catch (e: CancellationException) { throw e }
            catch (_: Exception) { mutable.value = mutable.value.copy(loading = false, message = R.string.operation_failed) }
        }
    }

    fun save() {
        val current = mutable.value
        val draft = current.draft ?: return
        if (current.loading || current.saving || current.completed || current.conflict || current.missing || !draft.changed || draft.errors().isNotEmpty()) return
        mutable.value = current.copy(saving = true, message = null, details = null)
        viewModelScope.launch {
            writer?.cancelAndJoin()
            try {
                drafts.write(draft)
                when (update(draft.node(), draft.original)) {
                    NodeUpdateResult.SAVED -> {
                        runCatching { drafts.clear() }
                        mutable.value = mutable.value.copy(completed = true)
                    }
                    NodeUpdateResult.NOT_FOUND -> mutable.value = mutable.value.copy(missing = true)
                    NodeUpdateResult.CONFLICT -> mutable.value = mutable.value.copy(conflict = true)
                }
            } catch (e: CancellationException) { throw e }
            catch (e: Exception) {
                mutable.value = mutable.value.copy(message = R.string.operation_failed, details = errorMessage(e))
            } finally { mutable.value = mutable.value.copy(saving = false) }
        }
    }

    fun discardAndClose() {
        if (mutable.value.saving || mutable.value.completed) return
        mutable.value = mutable.value.copy(saving = true)
        viewModelScope.launch {
            loader?.cancelAndJoin()
            writer?.cancelAndJoin()
            try {
                drafts.clear()
                mutable.value = mutable.value.copy(completed = true)
            } catch (e: CancellationException) { throw e }
            catch (_: Exception) {
                mutable.value = mutable.value.copy(message = R.string.node_edit_draft_error)
            } finally { mutable.value = mutable.value.copy(saving = false) }
        }
    }

    fun dismissMessage() { mutable.value = mutable.value.copy(message = null, details = null) }
}
