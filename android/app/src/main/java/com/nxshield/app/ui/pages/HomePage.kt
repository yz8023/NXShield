package com.nxshield.app.ui.pages

import android.app.Activity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Slider
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.nxshield.engine.NxLogger
import com.nxshield.engine.Packer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

@Composable
fun HomePage(modifier: Modifier = Modifier) {
    val scope = rememberCoroutineScope()
    val ctx = LocalContext.current
    val logger = remember { NxLogger(ctx) }
    val packer = remember { Packer(ctx, logger) }

    var apkName by remember { mutableStateOf("") }
    var apkBytes by remember { mutableStateOf<ByteArray?>(null) }
    var stdInfo by remember { mutableStateOf<JSONObject?>(null) }
    var running by remember { mutableStateOf(false) }
    var progress by remember { mutableStateOf("等待选择 APK") }
    var lastStats by remember { mutableStateOf("") }
    var exportReady by remember { mutableStateOf(false) }
    var useVm by remember { mutableStateOf(true) }
    var useStrings by remember { mutableStateOf(true) }
    var useAssets by remember { mutableStateOf(true) }
    var drain by remember { mutableStateOf(60) }

    val pickLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            val uri = result.data?.data
            if (uri != null) {
                scope.launch {
                    val bytes = withContext(Dispatchers.IO) { readBytes(ctx, uri) }
                    if (bytes != null) {
                        apkName = displayName(uri)
                        apkBytes = bytes
                        running = false
                        progress = "选择成功: $apkName"
                        stdInfo = runCatching { packer.analyze(bytes) }.getOrNull()
                    } else {
                        progress = "读取文件失败，请重试"
                    }
                }
            }
        }
    }

    val exportLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/vnd.android.package-archive"),
    ) { uri ->
        if (uri != null) {
            scope.launch {
                val ok = withContext(Dispatchers.IO) {
                    val src = latestOutputFile(ctx) ?: return@withContext false
                    runCatching {
                        ctx.contentResolver.openOutputStream(uri)?.use { out ->
                            src.inputStream().use { it.copyTo(out) }
                        }
                    }.isSuccess
                }
                progress = if (ok) "已导出加固 APK" else "导出失败"
            }
        }
    }

    fun openPicker() {
        runCatching { pickLauncher.launch(pickIntent()) }
            .onFailure { progress = "无法打开文件选择器: ${it.message}" }
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
    ) {
        Text("NXShield 加固", style = MaterialTheme.typography.headlineMedium, color = MaterialTheme.colorScheme.primary)
        Spacer(Modifier.height(4.dp))
        Text("自研 APK 加固引擎：抽函数混淆 · NX-VM 虚拟化 · 敏感字符串保护 · assets 加密", style = MaterialTheme.typography.bodyMedium)
        Spacer(Modifier.height(16.dp))

        Card(modifier = Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp)) {
                Text("选择 APK", style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(8.dp))
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = { openPicker() }) {
                        Text(if (apkName.isEmpty()) "选择文件" else apkName)
                    }
                    if (stdInfo != null) {
                        Text(
                            "dex=${stdInfo!!.getInt("dexCount")} 类=${stdInfo!!.getInt("classes")} 字符串=${stdInfo!!.getInt("strings")}",
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
            }
        }

        Spacer(Modifier.height(16.dp))

        Card(modifier = Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp)) {
                Text("加固选项", style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(4.dp))
                ToggleRow("NX-VM 抽函数", useVm) { useVm = it }
                ToggleRow("敏感字符串保护", useStrings) { useStrings = it }
                ToggleRow("assets 加密", useAssets) { useAssets = it }
                Spacer(Modifier.height(12.dp))
                Text("抽取比例: $drain%", style = MaterialTheme.typography.bodySmall)
                Slider(
                    value = drain.toFloat(), valueRange = 10f..100f,
                    onValueChange = { drain = it.toInt() },
                )
            }
        }

        Spacer(Modifier.height(16.dp))

        Button(
            onClick = {
                val bytes = apkBytes
                if (bytes == null) { progress = "请先选择 APK"; return@Button }
                running = true
                exportReady = false
                val jobId = logger.newJob(apkName)
                logger.logFeature(jobId, "NX-VM", useVm)
                logger.logFeature(jobId, "strings", useStrings)
                logger.logFeature(jobId, "assets", useAssets)
                scope.launch {
                    try {
                        val stats = withContext(Dispatchers.Default) {
                            packer.run(
                                jobId, apkName, bytes,
                                Packer.Options(
                                    enableVm = useVm, enableStrings = useStrings,
                                    enableAssets = useAssets, drain = drain,
                                ),
                            ) { progress = it }
                        }
                        lastStats = "完成 · 抽取 ${stats.methodsExtracted} · 字符串 ${stats.stringsProtected} · ${stats.elapsedMs}ms · ${stats.outSize / 1024}KB"
                        progress = "完成"
                        exportReady = latestOutputFile(ctx) != null
                    } catch (e: Exception) {
                        progress = "失败: ${e.message}"
                        logger.log(jobId, "error", "task_error", mapOf("msg" to (e.message ?: "")))
                    } finally {
                        running = false
                    }
                }
            },
            enabled = !running,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(if (running) "加固中..." else "开始加固")
        }

        if (running) {
            Spacer(Modifier.height(16.dp))
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                CircularProgressIndicator(modifier = Modifier.height(24.dp))
                Text(progress)
            }
        } else if (progress.isNotEmpty()) {
            Spacer(Modifier.height(12.dp))
            Text(progress, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary)
        }
        if (lastStats.isNotEmpty()) {
            Spacer(Modifier.height(8.dp))
            HorizontalDivider()
            Spacer(Modifier.height(8.dp))
            Text(lastStats)
            if (exportReady) {
                Spacer(Modifier.height(8.dp))
                Button(onClick = {
                    runCatching { exportLauncher.launch("nxshield_protected.apk") }
                        .onFailure { progress = "无法导出: ${it.message}" }
                }) { Text("导出加固 APK") }
            }
        }
    }
}

@Composable
private fun ToggleRow(label: String, value: Boolean, onChange: (Boolean) -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(label)
        Switch(checked = value, onCheckedChange = onChange)
    }
}