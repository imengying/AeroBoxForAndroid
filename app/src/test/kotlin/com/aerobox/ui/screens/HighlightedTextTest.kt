package com.aerobox.ui.screens

import androidx.compose.ui.text.SpanStyle
import org.junit.Assert.assertEquals
import org.junit.Test

class HighlightedTextTest {
    @Test fun expandingLowercaseCharacterDoesNotShiftHighlightBounds() {
        val highlighted = buildHighlightedText("İa", "a", SpanStyle())

        assertEquals("İa", highlighted.text)
        assertEquals(listOf(1 to 2), highlighted.spanStyles.map { it.start to it.end })
    }

    @Test fun repeatedMatchesUseOriginalOffsetsAndIgnoreCase() {
        val highlighted = buildHighlightedText("İa A", " a ", SpanStyle())

        assertEquals("İa A", highlighted.text)
        assertEquals(listOf(1 to 2, 3 to 4), highlighted.spanStyles.map { it.start to it.end })
    }
}
