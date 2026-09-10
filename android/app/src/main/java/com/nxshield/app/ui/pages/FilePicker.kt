package com.nxshield.app.ui.pages

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import com.nxshield.engine.NxLogger
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

/**
 * 返回一个打开的 SAF 选择器回调（注册在组合期）。
 * launchPicker(context, scope, onPicked) 必须在谓词中调用（onClick），
 * 真正的注册由 rememberPicker 完成。
 */
fun pickerLauncher(
    ctx: Context,
    scope: CoroutineScope,
    onPicked: (name: String, bytes: ByteArray) -> Unit,
) = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
    if (result.resultCode == Activity.RESULT_OK) {
        val uri = result.data?.data
        if (uri != null) {
            val name = uri.lastPathSegment ?: "selected.apk"
            scope.launch {
                val bytes = withContext(Dispatchers.IO) {
                    ctx.contentResolver.openInputStream(uri)?.use { it.readBytes() }
                }
                if (bytes != null) onPicked(name, bytes)
            }
        }
    }
}

fun pickIntent(): Intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
    addCategory(Intent.CATEGORY_OPENABLE)
    type = "application/vnd.android.package-archive"
}

/** 导出最近一次加固产物 */
fun exporterLauncher(ctx: Context, getFile: () -> File?) =
    rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/vnd.android.package-archive"),
    ) { uri ->
        if (uri != null) {
            val f = getFile() ?: return@rememberLauncherForActivityResult
            runCatching {
                ctx.contentResolver.openOutputStream(uri)?.use { out ->
                    out.write(f.readBytes())
                }
            }
        }
    }

/** 最新加固产物是否存在 / 是否导出 */
fun latestOutput(ctx: Context): Pair<String?, File>? {
    val logger = NxLogger(ctx)
    for (id in logger.listJobs()) {
        val f = File(logger.cacheDir(id), "protected.apk")
        if (f.exists()) return Pair(id, f)
    }
    return null
}