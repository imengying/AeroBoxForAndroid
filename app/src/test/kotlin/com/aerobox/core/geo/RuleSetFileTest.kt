package com.aerobox.core.geo

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.tukaani.xz.LZMA2Options
import org.tukaani.xz.XZInputStream
import org.tukaani.xz.XZOutputStream

class RuleSetFileTest {
    @get:Rule val temporary = TemporaryFolder()
    private val original = "SRS\u0001original rules".toByteArray()
    private val replacement = "SRS\u0002updated rules".toByteArray()

    @Test fun downloadedAndCompressedRulesReplaceTheWholeFile() {
        val file = existingRuleSet()
        file.writeRuleSet(replacement.inputStream())
        assertArrayEquals(replacement, file.readBytes())
        assertTrue(file.hasRuleSetHeader())

        XZInputStream(compress(original).inputStream()).use(file::writeRuleSet)
        assertArrayEquals(original, file.readBytes())
        assertNoTemporaryFile(file)
    }

    @Test fun invalidOrTruncatedHeaderPreservesExistingRules() {
        val file = existingRuleSet()
        for (invalid in listOf(byteArrayOf(), "SRS".toByteArray(), "<html>error</html>".toByteArray())) {
            assertThrows(IOException::class.java) { file.writeRuleSet(invalid.inputStream()) }
            assertArrayEquals(original, file.readBytes())
            assertNoTemporaryFile(file)
        }
    }

    @Test fun interruptedDownloadPreservesExistingRulesAndRemovesPartialFile() {
        val file = existingRuleSet()
        val input = object : ByteArrayInputStream(replacement + ByteArray(16_384)) {
            override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
                if (available() == 0) throw IOException("Connection interrupted")
                return super.read(buffer, offset, length)
            }
        }
        assertThrows(IOException::class.java) { file.writeRuleSet(input) }
        assertArrayEquals(original, file.readBytes())
        assertNoTemporaryFile(file)
    }

    @Test fun truncatedCompressedAssetPreservesExistingRules() {
        val file = existingRuleSet()
        val compressed = compress(replacement)
        assertThrows(IOException::class.java) {
            XZInputStream(compressed.copyOf(compressed.size - 8).inputStream()).use(file::writeRuleSet)
        }
        assertArrayEquals(original, file.readBytes())
        assertNoTemporaryFile(file)
    }

    @Test fun failedReplacementDoesNotDeleteTheDestination() {
        val directory = temporary.newFolder("rules.srs")
        val existing = File(directory, "keep").apply { writeBytes(original) }
        assertThrows(IOException::class.java) { directory.writeRuleSet(replacement.inputStream()) }
        assertArrayEquals(original, existing.readBytes())
        assertNoTemporaryFile(directory)
    }

    @Test fun missingOrInvalidLocalFilesAreUnavailable() {
        val file = File(temporary.root, "rules.srs")
        assertFalse(file.hasRuleSetHeader())
        for (invalid in listOf("", "SRS", "not a rule set")) {
            file.writeText(invalid)
            assertFalse(file.hasRuleSetHeader())
        }
        assertFalse(temporary.root.hasRuleSetHeader())
    }

    private fun existingRuleSet() = temporary.newFile("rules.srs").apply { writeBytes(original) }

    private fun compress(contents: ByteArray): ByteArray {
        val output = ByteArrayOutputStream()
        XZOutputStream(output, LZMA2Options()).use { it.write(contents) }
        return output.toByteArray()
    }

    private fun assertNoTemporaryFile(file: File) {
        assertFalse(File(file.parentFile, "${file.name}.tmp").exists())
    }
}
