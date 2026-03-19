package com.aerobox.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.aerobox.R
import com.aerobox.ui.components.SectionHeader

private data class LicenseNotice(
    val id: String,
    val title: String,
    val summary: String,
    val body: String
)

private data class GeneratedLicenseMetadata(
    val libraryName: String,
    val offset: Int,
    val length: Int
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LicenseScreen(
    onNavigateBack: () -> Unit
) {
    val context = LocalContext.current
    var notices by remember { mutableStateOf<List<LicenseNotice>?>(null) }
    var expandedIds by remember { mutableStateOf(setOf<String>()) }

    LaunchedEffect(Unit) {
        notices = loadLicenseNotices(context)
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.open_source_licenses)) },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = null)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface
                )
            )
        },
    ) { innerPadding ->
        when (val current = notices) {
            null -> {
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(innerPadding)
                        .padding(24.dp),
                    verticalArrangement = Arrangement.Center
                ) {
                    CircularProgressIndicator()
                }
            }
            else -> {
                LazyColumn(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(innerPadding),
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    item {
                        SectionHeader(title = "许可证列表")
                    }
                    item {
                        Text(
                            text = "当前页已合并展示 sing-box / libbox 与其他第三方依赖许可证",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(horizontal = 4.dp)
                        )
                    }
                    items(current, key = { it.id }) { notice ->
                        LicenseNoticeCard(
                            notice = notice,
                            expanded = expandedIds.contains(notice.id),
                            onToggle = {
                                expandedIds = if (expandedIds.contains(notice.id)) {
                                    expandedIds - notice.id
                                } else {
                                    expandedIds + notice.id
                                }
                            }
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun LicenseNoticeCard(
    notice: LicenseNotice,
    expanded: Boolean,
    onToggle: () -> Unit
) {
    Card(
        onClick = onToggle,
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.large,
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainerLow
        )
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(
                    text = notice.title,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.onSurface
                )
                Text(
                    text = notice.summary,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Text(
                text = if (expanded) "收起" else "展开查看",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.primary
            )
            if (expanded) {
                Text(
                    text = notice.body,
                    style = MaterialTheme.typography.bodySmall.copy(
                        fontFamily = FontFamily.Monospace
                    ),
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            } else {
                Icon(
                    Icons.AutoMirrored.Filled.KeyboardArrowRight,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.outline
                )
            }
        }
    }
}

private fun loadLicenseNotices(context: android.content.Context): List<LicenseNotice> {
    val notices = mutableListOf<LicenseNotice>()
    val singBoxBody = runCatching {
        context.resources.openRawResource(R.raw.sing_box_notice)
            .bufferedReader()
            .use { it.readText().trim() }
    }.getOrElse { "读取 sing-box 许可证失败" }
    notices += LicenseNotice(
        id = "sing-box",
        title = "sing-box / libbox",
        summary = "SagerNet · GPL-3.0-or-later",
        body = singBoxBody
    )
    notices += loadGeneratedLicenseNotices(context)
    return notices
}

private fun loadGeneratedLicenseNotices(context: android.content.Context): List<LicenseNotice> {
    val resources = context.resources
    val metadataResId = resources.getIdentifier(
        "third_party_license_metadata",
        "raw",
        context.packageName
    )
    val licensesResId = resources.getIdentifier(
        "third_party_licenses",
        "raw",
        context.packageName
    )
    if (metadataResId == 0 || licensesResId == 0) {
        return listOf(
            LicenseNotice(
                id = "generated-missing",
                title = "其他第三方依赖",
                summary = "自动生成的许可证资源当前不可用",
                body = "构建产物中未找到 third_party_license_metadata / third_party_licenses。"
            )
        )
    }

    val metadataEntries = runCatching {
        resources.openRawResource(metadataResId).bufferedReader().useLines { lines ->
            lines.mapNotNull(::parseGeneratedLicenseMetadata).toList()
        }
    }.getOrDefault(emptyList())
    val licenseBytes = runCatching {
        resources.openRawResource(licensesResId).use { it.readBytes() }
    }.getOrElse { return emptyList() }

    if (metadataEntries.isEmpty()) {
        return emptyList()
    }

    return metadataEntries
        .groupBy { it.offset to it.length }
        .entries
        .sortedBy { (_, entries) -> entries.first().libraryName.lowercase() }
        .mapIndexedNotNull { index, (_, entries) ->
            val offset = entries.first().offset
            val length = entries.first().length
            if (offset < 0 || length <= 0 || offset + length > licenseBytes.size) {
                return@mapIndexedNotNull null
            }
            val libraries = entries.map { it.libraryName }.sorted()
            val title = if (libraries.size == 1) {
                libraries.first()
            } else {
                "${libraries.first()} 等 ${libraries.size} 个依赖"
            }
            val summary = if (libraries.size == 1) {
                "自动生成"
            } else {
                libraries.joinToString(separator = " · ")
            }
            val body = buildString {
                append("Libraries:\n")
                append(libraries.joinToString(separator = "\n"))
                append("\n\n")
                append(String(licenseBytes, offset, length, Charsets.UTF_8).trim())
            }
            LicenseNotice(
                id = "generated_$index",
                title = title,
                summary = summary,
                body = body
            )
        }
}

private fun parseGeneratedLicenseMetadata(line: String): GeneratedLicenseMetadata? {
    val trimmed = line.trim()
    if (trimmed.isEmpty()) return null
    val match = Regex("""^(\d+):(\d+)\s+(.+)$""").matchEntire(trimmed) ?: return null
    return GeneratedLicenseMetadata(
        libraryName = match.groupValues[3].trim(),
        offset = match.groupValues[1].toIntOrNull() ?: return null,
        length = match.groupValues[2].toIntOrNull() ?: return null
    )
}
