package com.nxshield.engine

/**
 * NX-VM：把选中的方法体（insns）抽取出来，原始指令替换为 return-void 占位，
 * 原指令翻译成自定义 NX 字节码写入加密镜像。
 */
class NxVm(
    private val dex: DexFile,
    private val key: ByteArray,
) {
    companion object {
        private const val MIN_INSNS = 4            // 至少 8 字节才值得抽取
        private const val MAX_INSNS = 192          // 避免抽取超大方法
        private const val MAX_METHODS = 1200
    }

    data class Extracted(val methods: List<String>, val image: ByteArray, val count: Int)

    /** 选择可抽取方法：返回 (methodIdx, registers, insns[ByteArray]) 列表 */
    fun candidates(): List<MethodCode> {
        val all = dex.methodsWithCode()
        val picked = ArrayList<MethodCode>()
        for (m in all) {
            val (registers, ins, lenBytes) = runCatching { readCodeInsns(dex.data, m.codeOff) }
                .getOrNull() ?: continue
            if (registers <= 0 || ins <= 0) continue
            if (lenBytes < MIN_INSNS * 2) continue
            if (lenBytes > MAX_INSNS * 2) continue
            // 跳过构造函数/静态块/原生方法
            val sig = runCatching { dex.methodSig(m.methodIdx) }.getOrNull() ?: continue
            if (sig.contains("<init>") || sig.contains("<clinit>") || sig.contains("native")) continue
            // 仅抽取 void 方法：占位指令使用 return-void(0x0e00)，非 void 会被校验器拒绝
            if (!sig.endsWith(":V")) continue
            picked.add(m)
            if (picked.size >= MAX_METHODS) break
        }
        return picked
    }

    fun extract(sigFilter: (String) -> Boolean, maxCount: Int = Int.MAX_VALUE): Extracted {
        val picked = candidates().filter { sigFilter(dex.methodSig(it.methodIdx)) }
        val selected = if (maxCount == Int.MAX_VALUE) picked else picked.take(maxCount)
        val bos = java.io.ByteArrayOutputStream()
        val names = ArrayList<String>()

        // 镜像头: 4 字节 magic 'NXVM'
        bos.write("NXVM".toByteArray(Charsets.US_ASCII))

        var stored = 0
        for (m in selected) {
            val (registers, ins, lenBytes) = readCodeInsns(dex.data, m.codeOff)
            if (lenBytes < MIN_INSNS * 2 || lenBytes > MAX_INSNS * 2) continue
            val insns = dex.data.copyOfRange(m.codeOff + 16, m.codeOff + 16 + lenBytes)
            // 每条 NX 记录: u16 len | u8 registers | u8 ins | raw insns
            val rec = java.io.ByteArrayOutputStream()
            rec.write(byteArrayOf(
                (lenBytes and 0xFF).toByte(),
                ((lenBytes ushr 8) and 0xFF).toByte(),
                registers.toByte(),
                ins.toByte(),
            ))
            rec.write(insns)
            bos.write(rec.toByteArray())
            names.add(dex.methodSig(m.methodIdx))
            stored++
            // 原位替换：前 2 字节写 return-void(0x0e00)，其余清零
            dex.data.w2(m.codeOff + 16, 0x0e00)
            for (i in m.codeOff + 18 until m.codeOff + 16 + lenBytes) {
                dex.data[i] = 0x00
            }
        }

        // 镜像已含 4 字节 "NXVM" magic，直接整体加密
        val image = NxCrypto.wrap(bos.toByteArray(), key)
        return Extracted(names, image, stored)
    }
}