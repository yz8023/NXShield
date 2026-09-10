package com.nxshield.app.ui.pages

import android.content.Context
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
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
import com.nxshield.engine.NxLogger
import org.json.JSONObject

/** 功能开关：持久化 + 启停记录（写入日志历史） */
private fun loadPrefs(ctx: Context): MutableMap<String, Boolean> {
    val sp = ctx.getSharedPreferences("nxshield_prefs", Context.MODE_PRIVATE)
    val m = HashMap<String, Boolean>()
    m["vm"] = sp.getBoolean("vm", true)
    m["strings"] = sp.getBoolean("strings", true)
    m["assets"] = sp.getBoolean("assets", true)
    m["confuse"] = sp.getBoolean("confuse", true)
    m["logpol"] = sp.getBoolean("logpol", true)
    return m
}

@Composable
fun FeaturesPage(modifier: Modifier = Modifier) {
    val ctx = NXAppState.ctx()
    val logger = remember { NxLogger(ctx) }
    val sp = remember { ctx.getSharedPreferences("nxshield_prefs", Context.MODE_PRIVATE) }
    var prefs by remember { mutableStateOf(loadPrefs(ctx)) }

    fun toggle(key: String, label: String, on: Boolean) {
        prefs[key] = on
        sp.edit().putBoolean(key, on).apply()
        // 功能启停记录进历史日志
        val jobId = "feature_" + System.currentTimeMillis()
        logger.logFeature(jobId, label, on)
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
    ) {
        Text("加固功能", style = MaterialTheme.typography.headlineMedium, color = MaterialTheme.colorScheme.primary)
        Spacer(Modifier.height(12.dp))

        FeatureCard(
            "NX-VM 虚拟化",
            "将选中方法体替换为占位指令，原调用逻辑编译为 NX 字节码镜像（加密存储），运行时由 NXVM 解释执行。",
            prefs["vm"] == true,
        ) { toggle("vm", "NX-VM", it) }

        FeatureCard(
            "敏感字符串保护",
            "识别中文 / vip / premium / 密钥等敏感字符串并原位清空，原文加密写入运行时载荷表，运行期按索引还原。",
            prefs["strings"] == true,
        ) { toggle("strings", "字符串保护", it) }

        FeatureCard(
            "assets 加密",
            "对 assets/ 目录资源做 NX 封装加密（滚动异或 + HMAC 校验），运行时解密，阻止静态提取。",
            prefs["assets"] == true,
        ) { toggle("assets", "assets加密", it) }

        FeatureCard(
            "标识符混淆",
            "对 DEX 类名 / 方法名 / 字段名做不可逆哈希式重命名，降低反向分析可读性。",
            prefs["confuse"] == true,
        ) { toggle("confuse", "标识符混淆", it) }

        FeatureCard(
            "运行日志与历史",
            "任务级 JSONL 日志（含每次功能启停、加固前后对比），历史任务可回溯查看。",
            prefs["logpol"] == true,
        ) { toggle("logpol", "日志策略", it) }

        Spacer(Modifier.height(8.dp))
        Card {
            Column(Modifier.padding(16.dp)) {
                Text("关于", style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(4.dp))
                Text(
                    "NXShield 使用完全自研的加固方案，不依赖第三方加固 SDK。\n" +
                        "仅用于对您拥有合法授权的应用进行加固保护。",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
    }
}

@Composable
private fun FeatureCard(title: String, desc: String, enabled: Boolean, onToggle: (Boolean) -> Unit) {
    Card(modifier = Modifier.fillMaxWidth().padding(bottom = 12.dp)) {
        Row(
            modifier = Modifier.padding(16.dp).fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Column(Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(4.dp))
                Text(desc, style = MaterialTheme.typography.bodySmall)
            }
            Spacer(Modifier.width(12.dp))
            Switch(checked = enabled, onCheckedChange = onToggle)
        }
    }
}