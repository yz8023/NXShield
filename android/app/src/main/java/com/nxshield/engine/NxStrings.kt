package com.nxshield.engine

import java.util.regex.Pattern

/**
 * 敏感字符串识别 + 原位替换。
 * 将 DEX 中敏感字符串（中文/账户/vip/premium/付费等）内容原位替换为占位符，
 * 原字符串加密写入运行时载荷表。
 */
class NxStrings(
    private val dex: DexFile,
) {
    companion object {
        val CJK = Pattern.compile("[\\u4e00-\\u9fa5]")
        val SENSITIVE = Pattern.compile(
            "vip|premium|prox|pro_|unlock|premium_|subscri|pay|paid|account|token|secret|password|" +
                "api_key|apikey|用户名|账户|密码|秘钥|密钥|令牌|会员|高级|付费|支付|充值|解锁|开通",
            Pattern.CASE_INSENSITIVE,
        )
        val HARD_SKIP = Pattern.compile(
            "com/nxshield|com\\.nxshield|org/apache|java/|dalvik|android/|kotlin|/META-INF|Landroid|Lcom/android",
        )
    }

    fun isSkiphall(s: String): Boolean =
        s.length < 4 ||
            (s.startsWith("L") && (s.contains('/') || s.endsWith(";"))) ||
            s.startsWith("I/") || s.startsWith("[") || s.startsWith("()") ||
            HARD_SKIP.matcher(s).find()

    fun countSensitive(): Int = dex.allStrings().count { (_, s) -> SENSITIVE.matcher(s).find() && !isSkiphall(s) }

    data class ProtectResult(val records: List<Pair<Int, String>>, val payload: ByteArray)

    /**
     * 找出敏感字符串并返回 {索引->原文} 映射 + 加密载荷。
     * 调用方需结合 AssetsProtect 写入 assets/nxshield/strings.json.nxs。
     */
    fun collect(): Map<Int, String> {
        val hits = LinkedHashMap<Int, String>()
        for ((idx, s) in dex.allStrings()) {
            if (isSkiphall(s)) continue
            if (SENSITIVE.matcher(s).find() || CJK.matcher(s).find()) {
                hits[idx] = s
            }
        }
        return hits
    }

    /** 原位打补丁：把内容字节抹掉为占位（内容长度 ≤ 原内容长度即可） */
    fun patchInPlace(hits: Map<Int, String>): Int {
        var patched = 0
        for (idx in hits.keys) {
            val loc = dex.locateStringData(idx) ?: continue
            // 内容区全部清零（保留 NUL 结尾）
            for (i in 0 until loc.contentLen) {
                dex.data[loc.contentStart + i] = 0x00
            }
            // 写一个最短占位（单个 'x'）+ 0x00
            if (loc.contentLen >= 2) {
                dex.data[loc.contentStart] = 'x'.code.toByte()
                dex.data[loc.contentStart + 1] = 0x00
            } else if (loc.contentLen == 1) {
                // 本身只有 1 字节，置 0x00？占位符可为 0，但为避免 MUTF8 NUL 编码问题保留原值
            }
            patched++
        }
        return patched
    }
}