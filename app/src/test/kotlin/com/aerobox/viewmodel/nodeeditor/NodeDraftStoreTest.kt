package com.aerobox.viewmodel.nodeeditor

import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.ProxyType
import java.io.File
import java.io.RandomAccessFile
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class NodeDraftStoreTest {
    @get:Rule val temporary = TemporaryFolder()
    private val node = ProxyNode(id = 42, name = "Example", type = ProxyType.TROJAN,
        server = "example.invalid", port = 443, password = "original")

    @Test fun draftsRestoreRawInvalidValuesAndSecretsThenCanBeCleared() = runTest {
        val file = File(temporary.root, "draft")
        val draft = NodeEditDraft(node).change("port", "999999999999").change("password", "  changed\nsecret  ")
        NodeDraftStore(file).write(draft)
        val restored = NodeDraftStore(file).read()!!
        assertEquals(node.id, restored.nodeId)
        assertEquals(draft.edits, restored.edits)
        assertEquals(draft.sourceFingerprint, restored.fingerprint)
        NodeDraftStore(file).clear()
        assertNull(NodeDraftStore(file).read())
    }

    @Test fun staleBaselineSurvivesFurtherEditsAndDoesNotBecomeCurrent() = runTest {
        val file = File(temporary.root, "draft")
        val old = NodeEditDraft(node).change("name", "My name")
        val current = node.copy(server = "changed.invalid")
        val resumed = NodeEditDraft(current, old.edits, old.sourceFingerprint).change("port", "8443")
        NodeDraftStore(file).write(resumed)
        assertEquals(NodeDraftStore.fingerprint(node), NodeDraftStore(file).read()!!.fingerprint)
        assertNotEquals(NodeDraftStore.fingerprint(current), NodeDraftStore(file).read()!!.fingerprint)
    }

    @Test fun corruptedOversizedAndUnknownFieldsAreRejected() = runTest {
        val file = File(temporary.root, "draft")
        for (contents in listOf("not-json", "{\"version\":1,\"edits\":{\"unknown\":\"value\"}}")) {
            file.writeText(contents)
            assertTrue(runCatching { NodeDraftStore(file).read() }.isFailure)
        }
        RandomAccessFile(file, "rw").use { it.setLength(4L * 1024 * 1024 + 1) }
        assertTrue(runCatching { NodeDraftStore(file).read() }.isFailure)
    }

    @Test fun metadataChangesDoNotConflictWithRestoredDrafts() {
        assertEquals(NodeDraftStore.fingerprint(node),
            NodeDraftStore.fingerprint(node.copy(latency = 123, subscriptionId = 7, createdAt = 999)))
        assertNotEquals(NodeDraftStore.fingerprint(node), NodeDraftStore.fingerprint(node.copy(password = "changed")))
    }
}
