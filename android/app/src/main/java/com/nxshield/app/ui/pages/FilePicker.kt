package com.nxshield.app.ui.pages

import android.content.Context
import android.content.Intent
import android.net.Uri
import com.nxshield.engine.NxLogger
import java.io.File

/**
 * 构造 APK 选择 Intent。
 * MIME 放宽为 * / * 并附带推荐类型，避免部分 ROM 没有
 * application/vnd.android.package-archive 处理器时 launch 抛异常。
 */
fun pickIntent(): Intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
    addCategory(Intent.CATEGORY_OPENABLE)
    type = "*/*"
    putExtra(
        Intent.EXTRA_MIME_TYPES,
        arrayOf(
            "application/vnd.android.package-archive",
            "application/zip",
            "application/octet-stream",
        ),
    )
}

/** 安全读取选中 Uri 的内容，失败返回 null */
fun readBytes(ctx: Context, uri: Uri): ByteArray? = runCatching {
    ctx.contentResolver.openInputStream(uri)?.use { it.readBytes() }
}.getOrNull()

/** 从 Uri 推断文件名 */
fun displayName(uri: Uri): String =
    uri.lastPathSegment?.substringAfterLast('/') ?: "selected.apk"

/** 最近一次加固产物文件 */
fun latestOutputFile(ctx: Context): File? {
    val logger = NxLogger(ctx)
    for (id in logger.listJobs()) {
        val f = File(logger.cacheDir(id), "protected.apk")
        if (f.exists()) return f
    }
    return null
}