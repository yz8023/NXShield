package com.nxshield.app.ui.pages

import android.content.Context
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Slider
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.nxshield.app.NXAppState

@Composable
fun SettingsPage(modifier: Modifier = Modifier) {
    val ctx = NXAppState.ctx()
    val sp = remember { ctx.getSharedPreferences("nxshield_prefs", Context.MODE_PRIVATE) }
    var dark by remember { mutableStateOf(sp.getBoolean("dark", false)) }
    var key by remember { mutableStateOf(sp.getString("nxkey", "NXShield-Default-Key") ?: "") }
    var ratio by remember { mutableStateOf(sp.getInt("ratio", 60)) }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
    ) {
        Text("设置", style = MaterialTheme.typography.headlineMedium, color = MaterialTheme.colorScheme.primary)
        Spacer(Modifier.height(12.dp))

        Card(Modifier.padding(bottom = 12.dp)) {
            Column(Modifier.padding(16.dp)) {
                Text("外观", style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(4.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("深色模式")
                    Spacer(Modifier.width(8.dp))
                    Spacer(Modifier.weight(1f))
                    Switch(
                        checked = dark,
                        onCheckedChange = {
                            dark = it
                            sp.edit().putBoolean("dark", it).apply()
                            NXAppState.darkMode.value = it
                        },
                    )
                }
            }
        }

        Card(Modifier.padding(bottom = 12.dp)) {
            Column(Modifier.padding(16.dp)) {
                Text("保护密钥", style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(4.dp))
                OutlinedTextField(
                    value = key,
                    onValueChange = {
                        key = it
                        sp.edit().putString("nxkey", it).apply()
                        com.nxshield.runtime.NXRuntime.setKey(it)
                    },
                    singleLine = true,
                    label = { Text("NXShield 密钥") },
                )
                Text("用于 NXS 封装加解密 / VM 镜像 / 字符串表。修改后需重新加固。", style = MaterialTheme.typography.bodySmall)
            }
        }

        Card(Modifier.padding(bottom = 12.dp)) {
            Column(Modifier.padding(16.dp)) {
                Text("默认抽取比例: $ratio%", style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(4.dp))
                Slider(
                    value = ratio.toFloat(), valueRange = 10f..100f,
                    onValueChange = { ratio = it.toInt(); sp.edit().putInt("ratio", ratio).apply() },
                )
            }
        }

        Card(Modifier.padding(bottom = 12.dp)) {
            Column(Modifier.padding(16.dp)) {
                Text("关于 NXShield", style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(4.dp))
                Text(
                    "版本 1.0.0\n" +
                        "自研 APK 加固引擎 · 不依赖第三方加固 SDK\n" +
                        "仅用于对您拥有合法授权的应用进行加固保护。\n" +
                        "UI 风格参考 WeKit（Material 3 四栏导航）。",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
    }
}