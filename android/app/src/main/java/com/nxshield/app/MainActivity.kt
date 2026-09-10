package com.nxshield.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.Modifier
import com.nxshield.app.ui.NXApp
import com.nxshield.app.ui.theme.NXShieldTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        NXAppState.application = application
        val initialDark = getSharedPreferences("nxshield_prefs", MODE_PRIVATE).getBoolean("dark", false)
        NXAppState.darkMode.value = initialDark
        setContent {
            NXShieldTheme(darkTheme = NXAppState.darkMode.value) {
                Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    NXApp()
                }
            }
        }
    }
}

/** 全局单例状态（进程级） */
object NXAppState {
    var application: android.app.Application? = null
    val darkMode = mutableStateOf(false)
    fun ctx(): android.content.Context = application!!
}