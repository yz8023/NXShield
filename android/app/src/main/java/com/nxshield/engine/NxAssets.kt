package com.nxshield.engine

/**
 * assets 加密：把 APK 中 assets/ 下的条目加密为 .nxs，
 * 运行时由 NXShieldRuntime 解密。NXS 载荷目录自身不加密。
 */
object NxAssets {
    val SKIP_PREFIXES = listOf("assets/nxshield/", "META-INF/", "res/", "classes", "lib/", "AndroidManifest.xml")
    const val NX_DIR = "assets/nxshield/"

    data class Result(val encrypted: List<String>, val payloads: MutableMap<String, ByteArray>)

    fun encrypt(apk: ApkFixtures, key: ByteArray, filter: (String) -> Boolean): Result {
        val payloads = HashMap<String, ByteArray>()
        val encrypted = ArrayList<String>()
        for (e in apk.entries) {
            if (!e.name.startsWith("assets/")) continue
            if (SKIP_PREFIXES.any { e.name.startsWith(it) }) continue
            if (!filter(e.name)) continue
            val content = apk.inflate(e)
            payloads["${NX_DIR}${crc32(e.name.toByteArray()).toString(16)}_${e.name.removePrefix("assets/").replace('/', '_')}.nxs"] =
                NxCrypto.wrap(content, key)
            encrypted.add(e.name)
        }
        return Result(encrypted, payloads)
    }
}