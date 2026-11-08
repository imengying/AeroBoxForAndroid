package com.aerobox.core.subscription

import java.util.Base64
import okhttp3.Headers
import org.junit.Assert.*
import org.junit.Test

class SubscriptionMetadataParserTest {
    @Test fun headerTakesPriorityAndOnlySupportedLeadingCommentsAreRemoved() {
        val title = Base64.getEncoder().encodeToString("订阅标题".toByteArray())
        val source = "# profile-title: comment\n# unknown: keep\nnode\n" + "\n".repeat(8) + "# profile-title: late"
        val metadata = SubscriptionMetadataParser.parse(source, "https://example.com/source.yaml", Headers.headersOf(
            "PROFILE-TITLE", "BASE64:$title", "Content-Disposition", "attachment; filename=fallback.yaml"
        ))
        assertEquals("订阅标题", metadata.profileTitle)
        assertFalse(metadata.sanitizedContent.contains("profile-title: comment"))
        assertTrue(metadata.sanitizedContent.contains("# unknown: keep"))
        assertTrue(metadata.sanitizedContent.endsWith("# profile-title: late"))
    }

    @Test fun commentTitlePrecedesFilenameAndUrl() {
        val metadata = SubscriptionMetadataParser.parse("; profile-title: comment\nnode", "https://example.com/source.yaml",
            Headers.headersOf("Content-Disposition", "attachment; filename=fallback.yaml"))
        assertEquals("comment", metadata.profileTitle)
    }

    @Test fun filenamesAndUrlFragmentsDecodeUtf8WithoutChangingPlusSigns() {
        assertEquals("测试+a", SubscriptionMetadataParser.parse("node", null,
            Headers.headersOf("Content-Disposition", "attachment; filename*=UTF-8''%E6%B5%8B%E8%AF%95+a.yaml")).profileTitle)
        assertEquals("test+name", SubscriptionMetadataParser.parse("node", "https://example.com/a.yaml#test+name", null).profileTitle)
        assertEquals("test+name", SubscriptionMetadataParser.parse("node", "https://example.com/test%2Bname.yaml", null).profileTitle)
    }

    @Test fun redirectsMustRemainValidHttpsUrls() {
        val metadata = SubscriptionMetadataParser.parse("node", "https://example.com/source",
            Headers.headersOf("moved-permanently-to", "http://example.com/insecure"))
        assertNull(metadata.canonicalUrl)
        assertTrue(SubscriptionMetadataParser.isValidRemoteSubscriptionUrl("HTTPS://example.com/a"))
        listOf("file:///tmp/a", "http://example.com", "https://", "text").forEach {
            assertFalse(it, SubscriptionMetadataParser.isValidRemoteSubscriptionUrl(it))
        }
    }

    @Test fun invalidOrOverflowingIntervalsFallBackToCommentMetadata() {
        val metadata = SubscriptionMetadataParser.parse("# profile-update-interval: 2\nnode", null,
            Headers.headersOf("profile-update-interval", Long.MAX_VALUE.toString()))
        assertEquals(7_200_000L, metadata.updateIntervalMs)
        assertNull(SubscriptionMetadataParser.parse("# profile-update-interval: -1", null, null).updateIntervalMs)
    }

    @Test fun usageCountersCannotOverflowRemainingTrafficAndExpiryAcceptsSecondsOrMillis() {
        val metadata = SubscriptionMetadataParser.parse("node", null, Headers.headersOf("subscription-userinfo",
            "upload=${Long.MAX_VALUE}; download=${Long.MAX_VALUE}; total=100; expire=1800000000"))
        assertEquals(0L, metadata.userInfo!!.remainingBytes())
        assertEquals(1_800_000_000_000L, metadata.userInfo.expireTimestamp)
        val legacy = SubscriptionMetadataParser.parse("# subscription-userinfo: upload=-1; download=20; totl=100; expire=1800000000000", null, null)
        assertEquals(80L, legacy.userInfo!!.remainingBytes())
        assertEquals(1_800_000_000_000L, legacy.userInfo.expireTimestamp)
    }
}
