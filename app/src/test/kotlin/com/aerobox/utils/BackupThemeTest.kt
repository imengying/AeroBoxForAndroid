package com.aerobox.utils

import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.stringPreferencesKey
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class BackupThemeTest {
    private fun settings(mode: String) = JSONObject().put("dark_mode", mode)
        .put("last_selected_node_id", 0L).put("per_app_proxy_packages", JSONArray())

    @Test fun themesWrittenByTheSettingsUiCanBeRestored() {
        for (mode in listOf("system", "on", "off")) {
            val restored = PreferenceManager.restoredPreferences(emptyPreferences(), settings(mode), 0L)
            assertEquals(mode, restored[stringPreferencesKey("dark_mode")])
        }
    }

    @Test fun valuesOutsideTheSettingsUiChoicesAreRejected() {
        for (mode in listOf("dark", "light", "invalid")) {
            try {
                PreferenceManager.validateSettings(settings(mode))
                fail("Unknown theme accepted: $mode")
            } catch (_: IllegalArgumentException) { }
        }
    }
}
