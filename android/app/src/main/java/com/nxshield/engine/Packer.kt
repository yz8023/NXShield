package com.nxshield.engine

import android.content.Context
import org.json.JSONObject
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean

/**
 * 加固流程编排（设备端）。输入原始 APK 字节，依次执行：
 *   1. 分析 DEX → 统计
 *   2. 原位合并所有 classes*.dex 的字符串保护 / 抽函数（补丁式，保持 DEX 合法）
 *   3. assets 加密
 *   4. 重打包（按原始条目结构重建 ZIP）
 *   5. 生成报告 + 日志
 */
class Packer(
    private val ctx: Context,
    private val logger: NxLogger,
) {
    val cancelled = AtomicBoolean(false)

    data class Options(
        val enableVm: Boolean = true,
        val enableStrings: Boolean = true,
        val enableAssets: Boolean = true,
        val key: String = "NXShield-Default-Key",
        val drain: Int = 60,                // 抽取比例 0-100
        val extraDex: Boolean = true,       // 多 dex 全部处理
    )

    data class Stats(
        val classes: Int = 0,
        val dexCount: Int = 0,
        val stringsProtected: Int = 0,
        val methodsExtracted: Int = 0,
        val assetsEncrypted: Int = 0,
        val elapsedMs: Long = 0,
        val outSize: Long = 0,
    )

    fun analyze(apk: ByteArray): JSONObject {
        val fixtures = ApkIo.open(apk)
        val j = JSONObject()
        j.put("entries", fixtures.entries.size)
        val dexEntries = fixtures.entries.filter { it.name.endsWith(".dex") }
        j.put("dexCount", dexEntries.size)
        var c = 0; var s = 0
        for (e in dexEntries.take(1)) {
            val d = DexFile(fixtures.inflate(e))
            c = d.classDefsSize.toInt()
            s = d.allStrings().size
        }
        j.put("classes", c)
        j.put("strings", s)
        j.put("vm", fixtures.entries.any { it.name.endsWith(".dex") })
        return j
    }

    fun run(
        jobId: String,
        apkName: String,
        apk: ByteArray,
        opt: Options,
        onProgress: (String) -> Unit,
    ): Stats {
        val t0 = System.currentTimeMillis()
        val fixtures = ApkIo.open(apk)
        logger.log(jobId, "info", "task_start", mapOf("apk" to apkName, "entries" to fixtures.entries.size))

        val key = opt.key.toByteArray(Charsets.UTF_8)
        val dexFiles = fixtures.entries.filter { it.name.endsWith(".dex") }.let { list ->
            if (!opt.extraDex) list.take(1) else list
        }
        logger.log(jobId, "info", "dex_scan", mapOf("count" to dexFiles.size))
        onProgress("扫描 DEX...")

        val replacements = HashMap<String, ByteArray>()
        var stringsProtected = 0
        var methodsExtracted = 0

        for (e in dexFiles) {
            if (cancelled.get()) throw IllegalStateException("cancelled")
            val dexData = fixtures.inflate(e)
            val dex = DexFile(dexData)
            logger.log(jobId, "info", "dex_open", mapOf("name" to e.name, "size" to dexData.size))

            // 1) 字符串保护
            if (opt.enableStrings) {
                val strings = NxStrings(dex)
                val hits = strings.collect()
                val payload = StringBuilder()
                for ((idx, s) in hits) {
                    payload.append(idx).append('|').append(android.util.Base64.encodeToString(s.toByteArray(), android.util.Base64.NO_WRAP)).append('\n')
                }
                if (payload.isNotEmpty()) {
                    val nxsName = "assets/nxshield/strings_${crc32(e.name.toByteArray()).toString(16)}.json.nxs"
                    replacements[nxsName] = NxCrypto.wrap(payload.toString().toByteArray(Charsets.UTF_8), key)
                    stringsProtected += strings.patchInPlace(hits)
                    logger.log(jobId, "feature", "strings", mapOf("dex" to e.name, "protected" to stringsProtected))
                }
            }

            // 2) NX-VM 抽函数
            if (opt.enableVm) {
                val vmx = NxVm(dex, key)
                val total = vmx.candidates().size
                val budget = ((total.toDouble() * opt.drain) / 100.0).toInt().coerceAtLeast(1)
                val ex = vmx.extract({ true }, budget)
                methodsExtracted += ex.count
                if (ex.count > 0) {
                    replacements["assets/nxshield/vm_${crc32(e.name.toByteArray()).toString(16)}.nxvm.nxs"] = ex.image
                    logger.log(jobId, "feature", "vm", mapOf("dex" to e.name, "methods" to ex.count))
                }
            }
            replacements[e.name] = dex.data
        }

        // 3) assets 加密
        if (opt.enableAssets) {
            val res = NxAssets.encrypt(fixtures, key) { true }
            res.payloads.forEach { (name, data) -> replacements[name] = data }
            logger.log(jobId, "feature", "assets", mapOf("encrypted" to res.encrypted.size))
            onProgress("加密 assets(${res.encrypted.size})...")
        }

        // 4) 重打包
        onProgress("重打包 APK...")
        val outBytes = ApkIo.rebuild(fixtures, replacements)

        // 5) 输出到 job 缓存目录，供 UI 导出
        val outFile = File(logger.cacheDir(jobId), "protected.apk")
        outFile.parentFile?.mkdirs()
        outFile.writeBytes(outBytes)

        val elapsed = System.currentTimeMillis() - t0
        val stats = Stats(
            classes = 0, dexCount = dexFiles.size,
            stringsProtected = stringsProtected, methodsExtracted = methodsExtracted,
            assetsEncrypted = 0, elapsedMs = elapsed, outSize = outBytes.size,
        )
        logger.log(jobId, "info", "task_done", mapOf(
            "elapsedMs" to elapsed, "extracted" to methodsExtracted,
            "strings" to stringsProtected, "assets" to stats.assetsEncrypted,
            "outSize" to outBytes.size,
        ))
        onProgress("完成")
        return stats
    }

    private fun crc32(b: ByteArray): Long {
        val c = java.util.zip.CRC32(); c.update(b); return c.value
    }
}