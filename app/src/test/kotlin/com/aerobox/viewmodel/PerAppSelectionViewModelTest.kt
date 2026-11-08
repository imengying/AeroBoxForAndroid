package com.aerobox.viewmodel

import androidx.lifecycle.ViewModelStore
import com.aerobox.R
import java.io.File
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

@OptIn(ExperimentalCoroutinesApi::class)
class PerAppSelectionViewModelTest {
    @get:Rule val temporary = TemporaryFolder()
    private val models = ViewModelStore()
    private var index = 0
    private val file get() = File(temporary.root, "selection")
    private val drafts get() = AppSelectionDraftStore(file)

    @Before fun before() { Dispatchers.setMain(StandardTestDispatcher()) }
    @After fun after() { models.clear(); Dispatchers.resetMain() }

    private fun model(
        load: suspend () -> Set<String> = { setOf("app.original") },
        apply: suspend (AppSelectionDraft) -> Boolean = { true }
    ) = PerAppSelectionViewModel(load, apply, drafts).also { models.put("selection-${index++}", it) }

    @Test fun restoredDraftKeepsUnsavedChangesAndOriginalSortOrder() = runTest {
        val pending = AppSelectionDraft(setOf("app.original"), setOf("app.added"))
        drafts.write(pending)
        val restored = model(load = { error("A restored draft must not be replaced by initial settings") })
        assertEquals(pending, restored.state.first { !it.loading }.draft)
    }

    @Test fun lateInitialSettingsCannotBeReplacedByAnEmptySelection() = runTest {
        val settings = CompletableDeferred<Set<String>>()
        var saves = 0
        val editor = model(load = { settings.await() }, apply = { saves++; true })
        editor.toggle("app.early")
        editor.saveAndClose()
        settings.complete(setOf("app.persisted"))
        val ready = editor.state.first { !it.loading }
        assertEquals(setOf("app.persisted"), ready.draft!!.selected)
        assertEquals(0, saves)
        editor.saveAndClose()
        editor.state.first { it.completed && !it.saving }
        assertEquals("Unchanged selection must not reload the VPN", 0, saves)
    }

    @Test fun singleSaveKeepsDraftUntilApplyCompletesThenRemovesIt() = runTest {
        val applying = CompletableDeferred<AppSelectionDraft>()
        val release = CompletableDeferred<Boolean>()
        var saves = 0
        val editor = model(apply = { saves++; applying.complete(it); release.await() })
        editor.state.first { !it.loading }
        editor.toggle("app.added")
        editor.toggle("app.original")
        editor.saveAndClose()
        editor.saveAndClose()
        val pending = applying.await()
        assertEquals(setOf("app.added"), pending.selected)
        assertEquals(pending, drafts.read())
        editor.toggle("app.tooLate")
        assertEquals(pending, editor.state.value.draft)
        assertEquals(1, saves)
        release.complete(true)
        editor.state.first { it.completed && !it.saving }
        assertNull(drafts.read())
    }

    @Test fun failedApplyKeepsThePageAndDraftForRetry() = runTest {
        var canApply = false
        val editor = model(apply = { canApply })
        editor.state.first { !it.loading }
        editor.toggle("app.added")
        editor.saveAndClose()
        val failed = editor.state.first { !it.saving && it.message == R.string.perapp_setting_failed }
        assertFalse(failed.completed)
        assertEquals(setOf("app.original", "app.added"), drafts.read()!!.selected)
        canApply = true
        editor.saveAndClose()
        editor.state.first { it.completed && !it.saving }
        assertNull(drafts.read())
    }

    @Test fun writeFailureDoesNotApplyOrDiscardChanges() = runTest {
        val editor = model(apply = { error("Persistence must succeed before applying") })
        editor.state.first { !it.loading }
        assertTrue(file.mkdir())
        editor.toggle("app.added")
        editor.saveAndClose()
        val failed = editor.state.first { !it.saving && it.message == R.string.perapp_setting_failed }
        assertFalse(failed.completed)
        assertTrue("app.added" in failed.draft!!.selected)
    }

    @Test fun unreadableDraftDoesNotSilentlyOverwriteSavedSelection() = runTest {
        file.writeText("invalid draft")
        var saves = 0
        val editor = model(apply = { saves++; true })
        val failed = editor.state.first { !it.loading }
        assertNull(failed.draft)
        assertEquals(R.string.per_app_selection_load_failed, failed.message)
        editor.toggle("app.added")
        editor.saveAndClose()
        assertEquals(0, saves)
        assertTrue(file.delete())
        editor.reload()
        assertEquals(setOf("app.original"), editor.state.first { !it.loading && it.draft != null }.draft!!.selected)
    }

    @Test fun restoredChangesPreserveUnrelatedConcurrentSettings() {
        val pending = AppSelectionDraft(setOf("app.remove", "app.keep"), setOf("app.keep", "app.add"))
        assertEquals(setOf("app.keep", "app.external", "app.add"),
            pending.applyTo(setOf("app.remove", "app.keep", "app.external")))
        assertEquals(setOf("app.external", "app.add"), pending.applyTo(setOf("app.external")))
    }

    @Test fun largeSelectionsRoundTripAndInvalidWritesLeavePreviousDraftIntact() = runTest {
        val packages = (1..5_000).mapTo(mutableSetOf()) { "org.example.application$it" }
        val draft = AppSelectionDraft(packages, packages - "org.example.application1")
        drafts.write(draft)
        assertEquals(draft, AppSelectionDraftStore(file).read())
        try {
            drafts.write(AppSelectionDraft(setOf("x".repeat(256)))); fail("Invalid package should fail")
        } catch (_: IllegalArgumentException) { }
        assertEquals(draft, drafts.read())
        assertFalse(File(file.parentFile, "${file.name}.tmp").exists())
    }
}
