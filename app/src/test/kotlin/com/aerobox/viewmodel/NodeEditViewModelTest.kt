package com.aerobox.viewmodel

import androidx.lifecycle.ViewModelStore
import com.aerobox.R
import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.ProxyType
import com.aerobox.data.repository.NodeUpdateResult
import com.aerobox.viewmodel.nodeeditor.NodeDraftStore
import com.aerobox.viewmodel.nodeeditor.NodeEditDraft
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
class NodeEditViewModelTest {
    @get:Rule val temporary = TemporaryFolder()
    private val models = ViewModelStore()
    private var index = 0
    private val node = ProxyNode(id = 42, name = "Example", type = ProxyType.TROJAN,
        server = "example.invalid", port = 443, password = "fixture", subscriptionId = 7)
    private val file get() = File(temporary.root, "draft")
    private val drafts get() = NodeDraftStore(file)

    @Before fun before() { Dispatchers.setMain(StandardTestDispatcher()) }
    @After fun after() { models.clear(); Dispatchers.resetMain() }

    private fun model(
        current: ProxyNode? = node,
        load: suspend (Long) -> ProxyNode? = { current },
        update: suspend (ProxyNode, ProxyNode) -> NodeUpdateResult = { _, _ -> NodeUpdateResult.SAVED }
    ): NodeEditViewModel = NodeEditViewModel(42, load, { true }, update, drafts, { "Test failure" })
        .also { models.put("editor-${index++}", it) }

    @Test fun restorationKeepsRawEditsAndDetectsAChangedSource() = runTest {
        drafts.write(NodeEditDraft(node).change("name", "My name").change("port", "999999999999"))
        val editor = model(node.copy(server = "updated.invalid"))
        val restored = editor.state.first { !it.loading }
        assertTrue(restored.conflict)
        assertTrue(restored.remote)
        assertEquals("My name", restored.draft!!.node().name)
        assertTrue("port" in restored.draft.errors())
        editor.save()
        assertFalse(editor.state.value.saving)
        editor.reload()
        val reloaded = editor.state.first { !it.loading && !it.conflict }
        assertFalse(reloaded.draft!!.changed)
        assertEquals("updated.invalid", reloaded.draft.node().server)
        assertNull(drafts.read())
    }

    @Test fun savingIsSingleFlightAndClearsTheDraftOnlyAfterSuccess() = runTest {
        val started = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        var calls = 0
        val editor = model(update = { changed, original ->
            calls++
            assertEquals(node, original)
            assertEquals("Changed", changed.name)
            started.complete(Unit)
            release.await()
            NodeUpdateResult.SAVED
        })
        editor.state.first { !it.loading }
        editor.change("name", "Changed")
        editor.save()
        editor.save()
        started.await()
        assertEquals(1, calls)
        assertEquals("Changed", drafts.read()!!.edits["name"])
        editor.change("name", "Should be ignored")
        release.complete(Unit)
        val saved = editor.state.first { it.completed && !it.saving }
        assertEquals("Changed", saved.draft!!.node().name)
        assertNull(drafts.read())
        editor.save()
        assertEquals(1, calls)
    }

    @Test fun nativeValidationFailurePreservesEditsForRetry() = runTest {
        val editor = model(update = { _, _ -> throw IllegalArgumentException("fixture") })
        editor.state.first { !it.loading }
        editor.change("name", "Changed")
        editor.save()
        val failed = editor.state.first { it.message == R.string.operation_failed && !it.saving }
        assertFalse(failed.completed)
        assertEquals("Changed", failed.draft!!.node().name)
        assertEquals("Test failure", failed.details)
        assertEquals("Changed", drafts.read()!!.edits["name"])
    }

    @Test fun concurrentUpdateAndDeletionDoNotSilentlyCloseTheEditor() = runTest {
        for (result in listOf(NodeUpdateResult.CONFLICT, NodeUpdateResult.NOT_FOUND)) {
            val editor = model(update = { _, _ -> result })
            editor.state.first { !it.loading }
            editor.change("name", "Changed")
            editor.save()
            val state = editor.state.first { !it.saving && (it.conflict || it.missing) }
            assertFalse(state.completed)
            assertEquals(result == NodeUpdateResult.CONFLICT, state.conflict)
            assertEquals(result == NodeUpdateResult.NOT_FOUND, state.missing)
            assertNotNull(drafts.read())
            editor.discardAndClose()
            editor.state.first { it.completed && !it.saving }
        }
    }

    @Test fun invalidDraftCannotReachTheRepository() = runTest {
        var calls = 0
        val editor = model(update = { _, _ -> calls++; NodeUpdateResult.SAVED })
        editor.state.first { !it.loading }
        editor.change("port", "99999999999")
        editor.save()
        assertFalse(editor.state.value.saving)
        assertEquals(0, calls)
        editor.discardAndClose()
        editor.state.first { it.completed && !it.saving }
        assertNull(drafts.read())
    }

    @Test fun leavingDuringLoadCannotReopenTheScreenOrOverwriteCompletedState() = runTest {
        val started = CompletableDeferred<Unit>()
        val editor = model(load = { started.complete(Unit); CompletableDeferred<ProxyNode>().await() })
        started.await()
        editor.discardAndClose()
        val closed = editor.state.first { it.completed && !it.saving }
        assertNull(closed.draft)
    }

    @Test fun persistenceFailureIsVisibleAndDoesNotWriteTheNode() = runTest {
        assertTrue(file.mkdir())
        var calls = 0
        val editor = model(update = { _, _ -> calls++; NodeUpdateResult.SAVED })
        editor.state.first { !it.loading }
        editor.change("name", "Changed")
        editor.save()
        editor.state.first { it.message == R.string.operation_failed && !it.saving }
        assertEquals(0, calls)
        assertFalse(editor.state.value.completed)
        assertTrue(editor.state.value.draft!!.changed)
    }
}
