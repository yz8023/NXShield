package com.nxshield.engine

import android.content.ContentValues
import android.content.Context
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import java.io.File

/** 导出产物到系统 Download 目录 */
object Export {
    /** 写入 Downloads，返回展示路径；失败返回 null */
    fun saveToDownloads(ctx: Context, fileName: String, data: ByteArray): String? = runCatching {
        if (Build.VERSION.SDK_INT >= 29) {
            val values = ContentValues().apply {
                put(MediaStore.Downloads.DISPLAY_NAME, fileName)
                put(MediaStore.Downloads.MIME_TYPE, "application/vnd.android.package-archive")
                put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
            }
            val uri = ctx.contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                ?: return@runCatching null
            ctx.contentResolver.openOutputStream(uri)?.use { it.write(data) }
                ?: return@runCatching null
            "Download/$fileName"
        } else {
            @Suppress("DEPRECATION")
            val dir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
            val f = File(dir, fileName)
            f.writeBytes(data)
            f.absolutePath
        }
    }.getOrNull()
}