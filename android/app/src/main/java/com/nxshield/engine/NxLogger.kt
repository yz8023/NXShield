package com.nxshield.engine

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * 日志系统：运行日志 JSONL + 历史记录（含功能启停、前后对比）。
 * 存储于 app 专属目录 <files>/nxshield/logs/。
 */
class NxLogger(private val ctx: Context) {
    val logDir: File get() = File(ctx.filesDir, "nxshield/logs").apply { if (!exists()) mkdirs() }

    private fun ts(): String = SimpleDateFormat("yyyyMMdd_HHmmss_SSS", Locale.US).format(Date())

    fun newJob(apkName: String): String {
        val id = ts()
        val cacheDir = File(ctx.cacheDir, "nxshield/$id").apply { mkdirs() }
        val f = File(logDir, "$id.jsonl")
        f.writeText("")
        log(id, "info", "task_start", mapOf("apk" to apkName))
        return id
    }

    fun cacheDir(id: String): File = File(ctx.cacheDir, "nxshield/$id")

    fun log(id: String, level: String, event: String, extra: Map<String, Any?> = emptyMap()) {
        val rec = JSONObject()
        rec.put("ts", System.currentTimeMillis())
        rec.put("level", level)
        rec.put("event", event)
        val e = JSONObject()
        extra.forEach { (k, v) -> e.put(k, if (v == null) JSONObject.NULL else v) }
        rec.put("data", e)
        runCatching { setAppend(File(logDir, "$id.jsonl"), rec.toString() + "\n") }
    }

    fun logFeature(id: String, name: String, enabled: Boolean) {
        log(id, "feature", "toggle", mapOf("feature" to name, "enabled" to enabled))
    }

    fun listJobs(): List<String> =
        logDir.listFiles()?.map { it.nameWithoutExtension }?.sortedDescending() ?: emptyList()

    fun readJob(id: String): List<JSONObject> {
        val f = File(logDir, "$id.jsonl")
        if (!f.exists()) return emptyList()
        val out = ArrayList<JSONObject>()
        f.readLines().forEach { line ->
            runCatching { JSONObject(line) }.onSuccess { out.add(it) }
        }
        return out
    }

    /** 历史记录汇总（供设置页/日志页展示） */
    fun history(): List<JSONObject> {
        val jobs = ArrayList<JSONObject>()
        for (id in listJobs().take(50)) {
            val recs = readJob(id)
            if (recs.isEmpty()) continue
            val first = recs.first()
            val last = recs.last()
            val firstData = first.optJSONObject("data") ?: JSONObject()
            val j = JSONObject()
            j.put("id", id)
            j.put("apk", firstData.optString("apk", "-"))
            j.put("start", first.optLong("ts"))
            j.put("end", last.optLong("ts"))
            j.put("status", last.optString("event"))
            j.put("lines", recs.size)
            jobs.add(j)
        }
        return jobs
    }

    private fun setAppend(f: File, s: String) {
        val fos = java.io.FileOutputStream(f, true)
        fos.write(s.toByteArray(Charsets.UTF_8))
        fos.close()
    }
}