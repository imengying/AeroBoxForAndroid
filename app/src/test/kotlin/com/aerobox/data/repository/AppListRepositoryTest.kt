package com.aerobox.data.repository

import com.aerobox.data.model.InstalledAppInfo
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test

class AppListRepositoryTest {
    private val app = InstalledAppInfo("Browser", "test.browser", false, true)

    @Test fun emptyQueryDoesNotPreventRecovery() = runBlocking {
        var queries = 0
        val repository = AppListRepository { if (++queries == 1) emptyList() else listOf(app) }
        assertTrue(repository.getInstalledApps().isEmpty())
        assertEquals(listOf(app), repository.getInstalledApps())
        assertEquals(2, queries)
    }

    @Test fun refreshReflectsPackageChanges() = runBlocking {
        var installed = listOf(app)
        val repository = AppListRepository { installed }
        assertEquals(installed, repository.getInstalledApps())
        installed = listOf(app.copy(packageName = "test.new"))
        assertEquals(installed, repository.getInstalledApps())
    }

    @Test fun failedQueryIsReportedAndCanBeRetried() = runBlocking {
        var queryFails = false
        val repository = AppListRepository {
            if (queryFails) throw SecurityException("access restricted")
            listOf(app)
        }
        repository.getInstalledApps()
        queryFails = true
        try {
            repository.getInstalledApps()
            fail("Expected the query failure to reach the caller")
        } catch (_: SecurityException) {
            queryFails = false
        }
        assertEquals(listOf(app), repository.getInstalledApps())
    }

    @Test fun brokenLabelFallsBackToPackageName() {
        assertEquals("test.browser", AppListRepository.appLabel("test.browser") { throw IllegalStateException() })
        assertEquals("test.browser", AppListRepository.appLabel("test.browser") { " " })
        assertEquals("test.browser", AppListRepository.appLabel("test.browser") { null })
        assertEquals("Browser", AppListRepository.appLabel("test.browser") { "Browser" })
    }
}
