package com.nxshield.app.ui

import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import com.nxshield.app.ui.pages.FeaturesPage
import com.nxshield.app.ui.pages.HomePage
import com.nxshield.app.ui.pages.LogsPage
import com.nxshield.app.ui.pages.SettingsPage

private data class Tab(val route: String, val title: String, val icon: androidx.compose.ui.graphics.vector.ImageVector)

private val tabs = listOf(
    Tab("home", "主页", Icons.Filled.Home),
    Tab("features", "功能", Icons.Filled.Build),
    Tab("logs", "日志", Icons.Filled.Description),
    Tab("settings", "设置", Icons.Filled.Settings),
)

@Composable
fun NXApp() {
    var current by remember { mutableStateOf("home") }
    Scaffold(
        bottomBar = {
            NavigationBar {
                tabs.forEach { t ->
                    NavigationBarItem(
                        selected = current == t.route,
                        onClick = { current = t.route },
                        icon = { Icon(t.icon, contentDescription = t.title) },
                        label = { Text(t.title) },
                    )
                }
            }
        },
    ) { padding ->
        when (current) {
            "features" -> FeaturesPage(Modifier.padding(padding))
            "logs" -> LogsPage(Modifier.padding(padding))
            "settings" -> SettingsPage(Modifier.padding(padding))
            else -> HomePage(Modifier.padding(padding))
        }
    }
}