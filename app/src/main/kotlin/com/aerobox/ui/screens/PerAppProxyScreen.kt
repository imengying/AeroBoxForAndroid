package com.aerobox.ui.screens

import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Surface
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.aerobox.viewmodel.SettingsViewModel
import com.aerobox.data.model.InstalledAppInfo
import com.aerobox.R
import com.aerobox.utils.findComponentActivity
import com.google.accompanist.drawablepainter.rememberDrawablePainter
import kotlinx.coroutines.launch


private fun buildHighlightedText(
    text: String,
    query: String,
    highlightStyle: SpanStyle
): AnnotatedString {
    val keyword = query.trim()
    if (keyword.isBlank()) return AnnotatedString(text)

    val lowerText = text.lowercase()
    val lowerKeyword = keyword.lowercase()
    var searchStart = 0
    var matchIndex = lowerText.indexOf(lowerKeyword, searchStart)
    if (matchIndex < 0) return AnnotatedString(text)

    return buildAnnotatedString {
        while (matchIndex >= 0) {
            append(text.substring(searchStart, matchIndex))
            withStyle(highlightStyle) {
                append(text.substring(matchIndex, matchIndex + keyword.length))
            }
            searchStart = matchIndex + keyword.length
            matchIndex = lowerText.indexOf(lowerKeyword, searchStart)
        }
        if (searchStart < text.length) {
            append(text.substring(searchStart))
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PerAppProxyScreen(
    onNavigateBack: () -> Unit,
    viewModel: SettingsViewModel = viewModel(
        viewModelStoreOwner = requireNotNull(LocalView.current.context.findComponentActivity()) {
            "PerAppProxyScreen requires a ComponentActivity"
        }
    )
) {
    val context = LocalContext.current
    val packageManager = context.packageManager
    val scope = rememberCoroutineScope()
    val mode by viewModel.perAppProxyMode.collectAsStateWithLifecycle()
    val selectedPackages by viewModel.perAppProxyPackages.collectAsStateWithLifecycle()
    val apps by viewModel.installedApps.collectAsStateWithLifecycle()
    val isLoadingApps by viewModel.isLoadingInstalledApps.collectAsStateWithLifecycle()
    val showSystem by viewModel.perAppShowSystem.collectAsStateWithLifecycle()
    var searchQuery by remember { mutableStateOf("") }
    var pendingShowSystem by remember { mutableStateOf<Boolean?>(null) }
    val effectiveShowSystem = pendingShowSystem ?: showSystem

    // Snapshot selected packages at screen open for stable sort order.
    // Selecting/deselecting an app won't cause it to jump in the list.
    // We wait until the first app-list load completes (apps.isNotEmpty)
    // so that selectedPackages has had time to be populated from DataStore;
    // otherwise the snapshot would capture the stateIn initial emptySet().
    var initialSelectedPackages by remember { mutableStateOf<Set<String>?>(null) }
    LaunchedEffect(isLoadingApps, selectedPackages) {
        if (initialSelectedPackages == null && !isLoadingApps && apps.isNotEmpty()) {
            initialSelectedPackages = selectedPackages
        }
    }
    LaunchedEffect(showSystem) {
        if (pendingShowSystem == showSystem) {
            pendingShowSystem = null
        }
    }
    val stableSelectedPackages = initialSelectedPackages ?: selectedPackages

    LaunchedEffect(selectedPackages) {
        viewModel.loadInstalledApps()
    }

    val filteredApps = remember(apps, effectiveShowSystem, searchQuery, selectedPackages, stableSelectedPackages) {
        apps
            .asSequence()
            .filter { app ->
                // Always show selected apps (even system apps) so they don't disappear
                if (selectedPackages.contains(app.packageName)) return@filter true
                if (!effectiveShowSystem && app.isSystem) return@filter false
                true
            }
            .filter { app ->
                val query = searchQuery.trim()
                if (query.isBlank()) {
                    true
                } else {
                    app.label.contains(query, ignoreCase = true) ||
                        app.packageName.contains(query, ignoreCase = true)
                }
            }
            .sortedWith(
                compareByDescending<InstalledAppInfo> {
                    stableSelectedPackages.contains(it.packageName)
                }.thenBy { it.label.lowercase() }
            )
            .toList()
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.per_app_proxy_title)) },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = null)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface
                )
            )
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
        ) {
            // Mode selector + system app toggle
            LazyRow(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                item {
                    FilterChip(
                        selected = mode == "blacklist",
                        onClick = { scope.launch { viewModel.setPerAppProxyMode("blacklist") } },
                        label = { Text(stringResource(R.string.per_app_proxy_chip_bypass)) }
                    )
                }
                item {
                    FilterChip(
                        selected = mode == "whitelist",
                        onClick = { scope.launch { viewModel.setPerAppProxyMode("whitelist") } },
                        label = { Text(stringResource(R.string.per_app_proxy_chip_only)) }
                    )
                }
                item {
                    FilterChip(
                        selected = effectiveShowSystem,
                        onClick = {
                            val next = !effectiveShowSystem
                            pendingShowSystem = next
                            scope.launch { viewModel.setPerAppShowSystem(next) }
                        },
                        label = { Text(stringResource(R.string.per_app_proxy_chip_show_system)) }
                    )
                }
            }

            OutlinedTextField(
                value = searchQuery,
                onValueChange = { searchQuery = it },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 8.dp),
                placeholder = { Text(stringResource(R.string.per_app_proxy_search_hint)) },
                leadingIcon = {
                    Icon(Icons.Filled.Search, contentDescription = null)
                },
                trailingIcon = {
                    if (searchQuery.isNotEmpty()) {
                        IconButton(onClick = { searchQuery = "" }) {
                            Icon(Icons.Filled.Close, contentDescription = null)
                        }
                    }
                },
                singleLine = true,
                shape = RoundedCornerShape(16.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    unfocusedBorderColor = MaterialTheme.colorScheme.outlineVariant
                )
            )

            if (filteredApps.isEmpty()) {
                Text(
                    text = stringResource(
                        if (isLoadingApps) {
                            R.string.per_app_proxy_loading
                        } else if (apps.isEmpty()) {
                            R.string.per_app_proxy_empty
                        } else {
                            R.string.per_app_proxy_no_match
                        }
                    ),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 20.dp)
                )
            } else {
                LazyColumn(
                    modifier = Modifier.fillMaxSize(),
                    contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    items(filteredApps, key = { it.packageName }) { app ->
                        val isChecked = selectedPackages.contains(app.packageName)
                        val highlightStyle = SpanStyle(
                            color = MaterialTheme.colorScheme.primary,
                            fontWeight = androidx.compose.ui.text.font.FontWeight.SemiBold
                        )
                        val toggleSelection = {
                            if (initialSelectedPackages == null) {
                                initialSelectedPackages = selectedPackages
                            }
                            val updated = if (!isChecked) {
                                selectedPackages + app.packageName
                            } else {
                                selectedPackages - app.packageName
                            }
                            scope.launch { viewModel.setPerAppProxyPackages(updated) }
                        }
                        val appIcon = remember(app.packageName) {
                            runCatching { packageManager.getApplicationIcon(app.packageName) }.getOrNull()
                        }
                        
                        Surface(
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(16.dp),
                            color = MaterialTheme.colorScheme.surfaceContainerLow,
                            onClick = { toggleSelection() }
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(horizontal = 12.dp, vertical = 8.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Image(
                                    painter = rememberDrawablePainter(appIcon),
                                    contentDescription = null,
                                    modifier = Modifier.size(40.dp)
                                )
                                Spacer(Modifier.width(12.dp))
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = buildHighlightedText(app.label, searchQuery, highlightStyle),
                                        style = MaterialTheme.typography.bodyMedium,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis
                                    )
                                    Text(
                                        text = buildHighlightedText(app.packageName, searchQuery, highlightStyle),
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.outline,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis
                                    )
                                    if (!app.hasInternetPermission) {
                                        Text(
                                            text = stringResource(R.string.per_app_proxy_no_internet),
                                            style = MaterialTheme.typography.bodySmall,
                                            color = MaterialTheme.colorScheme.outline
                                        )
                                    }
                                }
                                Checkbox(
                                    checked = isChecked,
                                    onCheckedChange = null // Handled by Surface click
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}
