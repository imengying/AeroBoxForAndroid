package com.aerobox.utils

import android.content.Context
import android.content.res.Configuration
import android.os.Build
import android.os.LocaleList

object AppLocaleManager {
    const val SYSTEM_LANGUAGE_TAG = ""
    private const val LOCALE_SERVICE_NAME = "locale"

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

    fun apply(context: Context, languageTag: String): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return false
        val normalized = normalize(languageTag)
        val locales = if (normalized.isBlank()) {
            LocaleList.getEmptyLocaleList()
        } else {
            LocaleList.forLanguageTags(normalized)
        }
        val localeManager = context.getSystemService(LOCALE_SERVICE_NAME) ?: return false
        return runCatching {
            localeManager.javaClass
                .getMethod("setApplicationLocales", LocaleList::class.java)
                .invoke(localeManager, locales)
            true
        }.getOrDefault(false)
    }

    fun localizedContext(base: Context, languageTag: String): Context {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) return base
        val normalized = normalize(languageTag)
        if (normalized.isBlank()) return base

        val configuration = Configuration(base.resources.configuration)
        configuration.setLocales(LocaleList.forLanguageTags(normalized))
        return base.createConfigurationContext(configuration)
    }

    fun currentLanguageTag(context: Context, storedLanguageTag: String): String {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val systemTags = runCatching {
                val localeManager = context.getSystemService(LOCALE_SERVICE_NAME) ?: return@runCatching ""
                val locales = localeManager.javaClass
                    .getMethod("getApplicationLocales")
                    .invoke(localeManager) as? LocaleList
                locales?.toLanguageTags().orEmpty()
            }.getOrDefault("")
            if (systemTags.isNotBlank()) {
                return normalize(systemTags.substringBefore(','))
            }
        }
        return normalize(storedLanguageTag)
    }
}

data class SupportedLanguage(
    val tag: String,
    val labelResId: Int
)
