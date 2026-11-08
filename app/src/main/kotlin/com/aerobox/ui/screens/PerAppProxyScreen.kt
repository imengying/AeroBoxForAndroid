package com.aerobox.ui.screens

import android.content.Intent
import android.net.Uri
import android.provider.Settings
import android.widget.Toast
import androidx.compose.foundation.Image
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
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
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.Surface
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.activity.compose.BackHandler
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import com.aerobox.viewmodel.AppViewModelFactory
import androidx.lifecycle.viewmodel.compose.viewModel
import com.aerobox.viewmodel.SettingsViewModel
import com.aerobox.data.model.InstalledAppInfo
import com.aerobox.viewmodel.PerAppSelectionViewModel
import com.aerobox.ui.components.AppSnackbarHost
import com.aerobox.R
import com.aerobox.utils.findComponentActivity
import com.google.accompanist.drawablepainter.rememberDrawablePainter
import kotlinx.coroutines.launch


internal fun buildHighlightedText(
    text: String,
    query: String,
    highlightStyle: SpanStyle
): AnnotatedString {
    val keyword = query.trim()
    if (keyword.isBlank()) return AnnotatedString(text)

    var searchStart = 0
    // Case folding can change string length (for example İ), so keep original offsets.
    var matchIndex = text.indexOf(keyword, searchStart, ignoreCase = true)
    if (matchIndex < 0) return AnnotatedString(text)

    return buildAnnotatedString {
        while (matchIndex >= 0) {
            append(text.substring(searchStart, matchIndex))
            withStyle(highlightStyle) {
                append(text.substring(matchIndex, matchIndex + keyword.length))
            }
            searchStart = matchIndex + keyword.length
            matchIndex = text.indexOf(keyword, searchStart, ignoreCase = true)
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
        factory = AppViewModelFactory,
        viewModelStoreOwner = requireNotNull(LocalView.current.context.findComponentActivity()) {
            "PerAppProxyScreen requires a ComponentActivity"
        }
    ),
    selectionViewModel: PerAppSelectionViewModel = viewModel(factory = AppViewModelFactory)
) {
    val context = LocalContext.current
    val packageManager = context.packageManager
    val scope = rememberCoroutineScope()
    val mode by viewModel.perAppProxyMode.collectAsStateWithLifecycle()
    val selection by selectionViewModel.state.collectAsStateWithLifecycle()
    val apps by viewModel.installedApps.collectAsStateWithLifecycle()
    val isLoadingApps by viewModel.isLoadingInstalledApps.collectAsStateWithLifecycle()
    val loadFailed by viewModel.installedAppsLoadFailed.collectAsStateWithLifecycle()
    val showSystem by viewModel.perAppShowSystem.collectAsStateWithLifecycle()
    var searchQuery by rememberSaveable { mutableStateOf("") }
    var pendingShowSystem by rememberSaveable { mutableStateOf<Boolean?>(null) }
    val effectiveShowSystem = pendingShowSystem ?: showSystem
    val effectiveSelectedPackages = selection.draft?.selected.orEmpty()
    val stableSelectedPackages = selection.draft?.original.orEmpty()
    val selectionEnabled = selection.draft != null && !selection.loading && !selection.saving && !selection.completed
    val snackbar = remember { SnackbarHostState() }
    val selectionMessage = selection.message?.let { stringResource(it) }

    LaunchedEffect(selectionMessage) {
        if (selectionMessage != null) {
            snackbar.showSnackbar(selectionMessage)
            selectionViewModel.dismissMessage()
        }
    }
    LaunchedEffect(selection.completed) { if (selection.completed) onNavigateBack() }

    val saveAndNavigateBack = {
        if (!selection.saving) {
            if (selection.draft == null) onNavigateBack() else selectionViewModel.saveAndClose()
        }
    }
    BackHandler(onBack = saveAndNavigateBack)

    LaunchedEffect(showSystem) {
        if (pendingShowSystem == showSystem) {
            pendingShowSystem = null
        }
    }

    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) {
        // Also refresh after returning from system settings or installing/removing apps.
        viewModel.loadInstalledApps(forceRefresh = true)
    }

    val filteredApps = remember(
        apps,
        effectiveShowSystem,
        searchQuery,
        effectiveSelectedPackages,
        stableSelectedPackages
    ) {
        apps
            .asSequence()
            .filter { app ->
                // Always show selected apps (even system apps) so they don't disappear
                if (effectiveSelectedPackages.contains(app.packageName)) return@filter true
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

    val hasHiddenMatches = remember(apps, effectiveShowSystem, effectiveSelectedPackages, searchQuery) {
        !effectiveShowSystem && apps.any { app ->
            app.isSystem && app.packageName !in effectiveSelectedPackages &&
                (app.label.contains(searchQuery.trim(), ignoreCase = true) ||
                    app.packageName.contains(searchQuery.trim(), ignoreCase = true))
        }
    }
    val showSystemApps: () -> Unit = {
        pendingShowSystem = true
        scope.launch { viewModel.setPerAppShowSystem(true) }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.per_app_proxy_title)) },
                navigationIcon = {
                    IconButton(onClick = saveAndNavigateBack, enabled = !selection.saving) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.action_go_back))
                    }
                },
                actions = {
                    IconButton(
                        onClick = { viewModel.loadInstalledApps(forceRefresh = true) },
                        enabled = !isLoadingApps
                    ) {
                        Icon(Icons.Filled.Refresh, contentDescription = stringResource(R.string.refresh))
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface
                )
            )
        },
        snackbarHost = { AppSnackbarHost(hostState = snackbar) }
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
                        enabled = !selection.saving,
                        onClick = { scope.launch { viewModel.setPerAppProxyMode("blacklist") } },
                        label = { Text(stringResource(R.string.per_app_proxy_chip_bypass)) }
                    )
                }
                item {
                    FilterChip(
                        selected = mode == "whitelist",
                        enabled = !selection.saving,
                        onClick = { scope.launch { viewModel.setPerAppProxyMode("whitelist") } },
                        label = { Text(stringResource(R.string.per_app_proxy_chip_only)) }
                    )
                }
                item {
                    FilterChip(
                        selected = effectiveShowSystem,
                        enabled = !selection.saving,
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
                            Icon(Icons.Filled.Close, contentDescription = stringResource(R.string.action_clear_search))
                        }
                    }
                },
                singleLine = true,
                shape = RoundedCornerShape(16.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    unfocusedBorderColor = MaterialTheme.colorScheme.outlineVariant
                )
            )

            if (isLoadingApps || selection.loading || selection.saving) {
                LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            }
            if (!selection.loading && selection.draft == null) {
                Text(
                    stringResource(R.string.per_app_selection_load_failed),
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp)
                )
                TextButton(onClick = selectionViewModel::reload, modifier = Modifier.padding(horizontal = 8.dp)) {
                    Text(stringResource(R.string.per_app_proxy_retry))
                }
            }
            if (loadFailed) {
                Text(
                    text = stringResource(R.string.per_app_proxy_empty),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp)
                )
                Row(modifier = Modifier.padding(horizontal = 8.dp)) {
                    TextButton(onClick = { viewModel.loadInstalledApps(forceRefresh = true) }) {
                        Text(stringResource(R.string.per_app_proxy_retry))
                    }
                    TextButton(onClick = {
                        runCatching {
                            context.startActivity(Intent(
                                Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                                Uri.fromParts("package", context.packageName, null)
                            ))
                        }.onFailure {
                            Toast.makeText(context, R.string.operation_failed, Toast.LENGTH_SHORT).show()
                        }
                    }) {
                        Text(stringResource(R.string.per_app_proxy_app_settings))
                    }
                }
            }

            if (filteredApps.isEmpty() && !loadFailed) {
                Text(
                    text = stringResource(
                        if (isLoadingApps || selection.loading) {
                            R.string.per_app_proxy_loading
                        } else if (apps.isEmpty()) {
                            R.string.per_app_proxy_none
                        } else if (hasHiddenMatches) {
                            if (searchQuery.isBlank()) R.string.per_app_proxy_system_hidden else R.string.per_app_proxy_system_matches_hidden
                        } else {
                            R.string.per_app_proxy_no_match
                        }
                    ),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 20.dp)
                )
                if (!isLoadingApps && !selection.loading && hasHiddenMatches) {
                    TextButton(onClick = showSystemApps, enabled = !selection.saving,
                        modifier = Modifier.padding(horizontal = 8.dp)) {
                        Text(stringResource(R.string.per_app_proxy_chip_show_system))
                    }
                }
            } else if (filteredApps.isNotEmpty() && selection.draft != null && !selection.loading) {
                LazyColumn(
                    modifier = Modifier.fillMaxSize(),
                    contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    items(filteredApps, key = { it.packageName }) { app ->
                        val isChecked = effectiveSelectedPackages.contains(app.packageName)
                        val highlightStyle = SpanStyle(
                            color = MaterialTheme.colorScheme.primary,
                            fontWeight = androidx.compose.ui.text.font.FontWeight.SemiBold
                        )
                        val appIcon = remember(app.packageName) {
                            runCatching { packageManager.getApplicationIcon(app.packageName) }.getOrNull()
                        }
                        
                        Surface(
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(16.dp),
                            color = MaterialTheme.colorScheme.surfaceContainerLow
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .toggleable(
                                        value = isChecked,
                                        enabled = selectionEnabled,
                                        role = Role.Checkbox,
                                        onValueChange = { selectionViewModel.toggle(app.packageName) }
                                    )
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
                                    enabled = selectionEnabled,
                                    onCheckedChange = null // The whole row exposes one checkbox action and state.
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}
