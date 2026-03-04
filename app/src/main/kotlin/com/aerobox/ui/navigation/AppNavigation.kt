package com.aerobox.ui.navigation

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.outlined.Home
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.tooling.preview.Preview
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.aerobox.R
import com.aerobox.ui.screens.HomeScreen
import com.aerobox.ui.screens.LogScreen
import com.aerobox.ui.screens.PerAppProxyScreen
import com.aerobox.ui.screens.SettingsScreen
import com.aerobox.ui.screens.SubscriptionScreen
import com.aerobox.ui.theme.SingBoxVPNTheme
import kotlinx.coroutines.launch

private data class BottomNavItem(
    val selectedIcon: androidx.compose.ui.graphics.vector.ImageVector,
    val unselectedIcon: androidx.compose.ui.graphics.vector.ImageVector,
    val label: Int
)

@OptIn(ExperimentalMaterial3Api::class, ExperimentalFoundationApi::class)
@Composable
fun AppNavigation() {
    val navController = rememberNavController()
    val navBackStackEntry by navController.currentBackStackEntryAsState()
    val currentRoute = navBackStackEntry?.destination?.route

    // Show main scaffold only on Home/Settings, not on sub-pages
    val isMainRoute = currentRoute == null || currentRoute == "main"

    NavHost(
        navController = navController,
        startDestination = "main"
    ) {
        composable("main") {
        MainScreen(
                onNavigateToSubscriptions = {
                    navController.navigate("subscriptions")
                },
                onNavigateToPerAppProxy = {
                    navController.navigate("per_app_proxy")
                },
                onNavigateToLog = {
                    navController.navigate("log")
                }
            )
        }
        composable("subscriptions") {
            SubscriptionScreen(
                onNavigateBack = { navController.popBackStack() }
            )
        }
        composable("per_app_proxy") {
            PerAppProxyScreen(
                onNavigateBack = { navController.popBackStack() }
            )
        }
        composable("log") {
            LogScreen(
                onNavigateBack = { navController.popBackStack() }
            )
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class, ExperimentalFoundationApi::class)
@Composable
private fun MainScreen(
    onNavigateToSubscriptions: () -> Unit,
    onNavigateToPerAppProxy: () -> Unit,
    onNavigateToLog: () -> Unit
) {
    val items = listOf(
        BottomNavItem(
            selectedIcon = Icons.Filled.Home,
            unselectedIcon = Icons.Outlined.Home,
            label = R.string.home
        ),
        BottomNavItem(
            selectedIcon = Icons.Filled.Settings,
            unselectedIcon = Icons.Outlined.Settings,
            label = R.string.settings
        )
    )

    val pagerState = rememberPagerState(pageCount = { items.size })
    val coroutineScope = rememberCoroutineScope()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(text = "AeroBox") },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface
                )
            )
        },
        containerColor = MaterialTheme.colorScheme.surface,
        bottomBar = {
            NavigationBar {
                items.forEachIndexed { index, item ->
                    val selected = pagerState.currentPage == index
                    NavigationBarItem(
                        selected = selected,
                        onClick = {
                            coroutineScope.launch {
                                pagerState.animateScrollToPage(index)
                            }
                        },
                        icon = {
                            Icon(
                                imageVector = if (selected) item.selectedIcon else item.unselectedIcon,
                                contentDescription = null
                            )
                        },
                        label = {
                            Text(stringResource(item.label))
                        }
                    )
                }
            }
        }
    ) { innerPadding ->
        HorizontalPager(
            state = pagerState,
            modifier = Modifier.padding(innerPadding),
            userScrollEnabled = true
        ) { page ->
            when (page) {
                0 -> HomeScreen()
                1 -> SettingsScreen(
                    onNavigateToSubscriptions = onNavigateToSubscriptions,
                    onNavigateToPerAppProxy = onNavigateToPerAppProxy,
                    onNavigateToLog = onNavigateToLog
                )
            }
        }
    }
}

@Preview(showBackground = true)
@Composable
private fun AppNavigationPreview() {
    SingBoxVPNTheme {
        AppNavigation()
    }
}
