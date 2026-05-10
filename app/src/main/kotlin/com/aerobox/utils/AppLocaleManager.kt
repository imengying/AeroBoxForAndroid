package com.aerobox.utils

import android.app.LocaleManager
import android.content.Context
import android.content.res.Configuration
import android.os.Build
import android.os.LocaleList
import java.util.Locale

object AppLocaleManager {
    const val SYSTEM_LANGUAGE_TAG = ""

    val supportedLanguages = listOf(
        SupportedLanguage(SYSTEM_LANGUAGE_TAG, com.aerobox.R.string.settings_language_system),
        SupportedLanguage("en", com.aerobox.R.string.settings_language_english),
        SupportedLanguage("zh-CN", com.aerobox.R.string.settings_language_chinese_simplified),
        SupportedLanguage("zh-TW", com.aerobox.R.string.settings_language_chinese_traditional),
        SupportedLanguage("fa", com.aerobox.R.string.settings_language_persian),
        SupportedLanguage("ru", com.aerobox.R.string.settings_language_russian)
    )

    fun normalize(languageTag: String): String {
        val trimmed = languageTag.trim()
        return supportedLanguages.firstOrNull { it.tag.equals(trimmed, ignoreCase = true) }?.tag
            ?: SYSTEM_LANGUAGE_TAG
    }

    fun apply(context: Context, languageTag: String) {
        val normalized = normalize(languageTag)
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            applyToResources(context.applicationContext, normalized)
            return
        }
        val localeManager = context.getSystemService(LocaleManager::class.java) ?: return
        localeManager.applicationLocales = if (normalized.isBlank()) {
            LocaleList.getEmptyLocaleList()
        } else {
            LocaleList.forLanguageTags(normalized)
        }
    }

    fun currentLanguageTag(context: Context, storedLanguageTag: String): String {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val localeManager = context.getSystemService(LocaleManager::class.java)
            val systemTags = localeManager?.applicationLocales?.toLanguageTags().orEmpty()
            return normalize(systemTags.substringBefore(','))
        }
        return normalize(storedLanguageTag)
    }

    fun wrapContext(base: Context, languageTag: String): Context {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) return base
        val normalized = normalize(languageTag)
        if (normalized.isBlank()) return base
        val locale = Locale.forLanguageTag(normalized)
        val config = Configuration(base.resources.configuration)
        config.setLocales(LocaleList(locale))
        return base.createConfigurationContext(config)
    }

    @Suppress("DEPRECATION")
    private fun applyToResources(context: Context, languageTag: String) {
        val config = Configuration(context.resources.configuration)
        if (languageTag.isBlank()) {
            config.setLocales(LocaleList.getDefault())
        } else {
            config.setLocales(LocaleList(Locale.forLanguageTag(languageTag)))
        }
        context.resources.updateConfiguration(config, context.resources.displayMetrics)
    }
}

data class SupportedLanguage(
    val tag: String,
    val labelResId: Int
)
