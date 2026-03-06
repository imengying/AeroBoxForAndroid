package com.aerobox.ui.navigation

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.layout.fillMaxSize
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
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.tooling.preview.Preview
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.aerobox.R
import com.aerobox.ui.screens.HomeScreen
import com.aerobox.ui.screens.LogScreen
import com.aerobox.ui.screens.PerAppProxyScreen
import com.aerobox.ui.screens.RoutingSettingsScreen
import com.aerobox.ui.screens.SettingsScreen
import com.aerobox.ui.screens.SubscriptionScreen
import androidx.compose.animation.AnimatedContentTransitionScope
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import com.aerobox.ui.theme.SingBoxVPNTheme
import kotlinx.coroutines.launch

private data class BottomNavItem(
    val selectedIcon: androidx.compose.ui.graphics.vector.ImageVector,
    val unselectedIcon: androidx.compose.ui.graphics.vector.ImageVector,
    val label: Int
)

@OptIn(ExperimentalMaterial3Api::class, ExperimentalFoundationApi::class)
@Composable
fun AppNavigation(
    initialMainPage: Int = 0,
    openMainRouteToken: Int = 0
) {
    val navController = rememberNavController()

    val slideDuration = 300

    LaunchedEffect(openMainRouteToken) {
        if (openMainRouteToken <= 0) return@LaunchedEffect
        navController.navigate("main") {
            launchSingleTop = true
            popUpTo(navController.graph.startDestinationId) {
                inclusive = false
            }
        }
    }

    Surface(
        modifier = Modifier.fillMaxSize(),
        color = MaterialTheme.colorScheme.background
    ) {
        NavHost(
            navController = navController,
            startDestination = "main",
            enterTransition = {
                slideIntoContainer(
                    AnimatedContentTransitionScope.SlideDirection.Start, 
                    tween(slideDuration)
                ) + fadeIn(tween(slideDuration))
            },
            exitTransition = {
                slideOutOfContainer(
                    AnimatedContentTransitionScope.SlideDirection.Start, 
                    tween(slideDuration)
                ) + fadeOut(tween(slideDuration))
            },
            popEnterTransition = {
                slideIntoContainer(
                    AnimatedContentTransitionScope.SlideDirection.End, 
                    tween(slideDuration)
                ) + fadeIn(tween(slideDuration))
            },
            popExitTransition = {
                slideOutOfContainer(
                    AnimatedContentTransitionScope.SlideDirection.End, 
                    tween(slideDuration)
                ) + fadeOut(tween(slideDuration))
            }
        ) {
            composable(
                "main",
                enterTransition = { fadeIn(tween(500)) },
                exitTransition = { fadeOut(tween(500)) },
                popEnterTransition = { fadeIn(tween(500)) }
            ) {
                MainScreen(
                    initialPage = initialMainPage,
                    onNavigateToSubscriptions = {
                        navController.navigate("subscriptions")
                    },
                    onNavigateToPerAppProxy = {
                        navController.navigate("per_app_proxy")
                    },
                    onNavigateToRouting = {
                        navController.navigate("routing")
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
            composable("routing") {
                RoutingSettingsScreen(
                    onNavigateBack = { navController.popBackStack() }
                )
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class, ExperimentalFoundationApi::class)
@Composable
private fun MainScreen(
    initialPage: Int,
    onNavigateToSubscriptions: () -> Unit,
    onNavigateToPerAppProxy: () -> Unit,
    onNavigateToRouting: () -> Unit,
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

    val pagerState = rememberPagerState(
        initialPage = initialPage.coerceIn(0, items.lastIndex),
        pageCount = { items.size }
    )
    val coroutineScope = rememberCoroutineScope()

    LaunchedEffect(initialPage) {
        val targetPage = initialPage.coerceIn(0, items.lastIndex)
        if (pagerState.currentPage != targetPage) {
            pagerState.scrollToPage(targetPage)
        }
    }

    Scaffold(
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
                    onNavigateToRouting = onNavigateToRouting,
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
