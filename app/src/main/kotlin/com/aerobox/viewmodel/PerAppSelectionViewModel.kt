package com.aerobox.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.aerobox.R
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class PerAppSelectionState(
    val draft: AppSelectionDraft? = null,
    val loading: Boolean = true,
    val saving: Boolean = false,
    val completed: Boolean = false,
    val message: Int? = null
)

/** Navigation-scoped selection and save lifetime survive recreation of the Compose screen. */
class PerAppSelectionViewModel(
    private val load: suspend () -> Set<String>,
    private val apply: suspend (AppSelectionDraft) -> Boolean,
    private val drafts: AppSelectionDraftStore
) : ViewModel() {
    private val mutable = MutableStateFlow(PerAppSelectionState())
    val state = mutable.asStateFlow()
    private var writer: Job? = null
    private var loader: Job? = null

    init { reload() }

    fun reload() {
        if (loader?.isActive == true || mutable.value.saving || mutable.value.completed) return
        mutable.value = mutable.value.copy(loading = true, message = null)
        loader = viewModelScope.launch {
            try {
                val stored = drafts.read()
                val draft = stored ?: AppSelectionDraft(load())
                mutable.value = PerAppSelectionState(draft = draft, loading = false)
            } catch (error: CancellationException) { throw error }
            catch (_: Exception) {
                mutable.value = mutable.value.copy(loading = false, message = R.string.per_app_selection_load_failed)
            }
        }
    }

    fun toggle(packageName: String) {
        val current = mutable.value
        val draft = current.draft ?: return
        if (current.loading || current.saving || current.completed) return
        val selected = if (packageName in draft.selected) draft.selected - packageName else draft.selected + packageName
        val updated = draft.copy(selected = selected)
        mutable.value = current.copy(draft = updated)
        val previous = writer
        previous?.cancel()
        writer = viewModelScope.launch {
            withContext(NonCancellable) { previous?.join() }
            try { drafts.write(updated) }
            catch (error: CancellationException) { throw error }
            catch (_: Exception) {
                mutable.value = mutable.value.copy(message = R.string.per_app_selection_draft_failed)
            }
        }
    }

    fun saveAndClose() {
        val current = mutable.value
        val draft = current.draft ?: return
        if (current.loading || current.saving || current.completed) return
        mutable.value = current.copy(saving = true, message = null)
        viewModelScope.launch {
            writer?.cancelAndJoin()
            try {
                if (draft.changed) {
                    drafts.write(draft)
                    if (!apply(draft)) {
                        mutable.value = mutable.value.copy(message = R.string.perapp_setting_failed)
                        return@launch
                    }
                }
                drafts.clear()
                mutable.value = mutable.value.copy(completed = true)
            } catch (error: CancellationException) { throw error }
            catch (_: Exception) {
                mutable.value = mutable.value.copy(message = R.string.perapp_setting_failed)
            } finally { mutable.value = mutable.value.copy(saving = false) }
        }
    }

    fun dismissMessage() { mutable.value = mutable.value.copy(message = null) }
}
