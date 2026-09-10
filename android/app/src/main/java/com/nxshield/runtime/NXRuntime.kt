package com.nxshield.runtime

import android.content.Context
import com.nxshield.engine.NxCrypto

/**
 * NXShield 运行时：被加固 App 接入用。
 * 负责从 assets/nxshield/ 解密字符串表 / VM 镜像 / 被保护 assets。
 */
object NXRuntime {
    var KEY: String = "NXShield-Default-Key"
        private set

    fun setKey(k: String) { KEY = k }

    private fun keyBytes(): ByteArray = KEY.toByteArray(Charsets.UTF_8)

    /** 读取并解密某个 nxshield 载荷 */
    fun loadAsset(ctx: Context, name: String): ByteArray {
        val raw = ctx.assets.open("nxshield/$name").readBytes()
        return NxCrypto.unwrap(raw, keyBytes())
    }

    /** 字符串保护表（index|b64 行）解析为 Map */
    fun stringTable(ctx: Context, dexName: String = "strings.json"): Map<Int, String> {
        val text = loadAsset(ctx, dexName).toString(Charsets.UTF_8)
        val out = HashMap<Int, String>()
        text.lineSequence().filter { it.isNotBlank() }.forEach { line ->
            val sep = line.indexOf('|')
            if (sep < 0) return@forEach
            val idx = line.substring(0, sep).toIntOrNull() ?: return@forEach
            val b64 = line.substring(sep + 1)
            out[idx] = String(android.util.Base64.decode(b64, android.util.Base64.DEFAULT), Charsets.UTF_8)
        }
        return out
    }

    /** 解密 VM 镜像字节 */
    fun vmImage(ctx: Context, name: String = "vm.nxvm"): ByteArray = loadAsset(ctx, name)
}