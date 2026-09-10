package com.nxshield.runtime

import android.content.Context

/**
 * NX-VM 解释器（运行时侧）：解析 NXVM 镜像，供被加固 App 调用。
 * 镜像格式:
 *   [4] "NXVM"
 *   [u16 len][u8 regs][u8 ins][len bytes insns]  xN 记录
 */
object NXVM {
    data class Record(val registers: Int, val ins: Int, val insns: ByteArray)

    /** 简单执行一条抽取记录（当前演示：直接丢弃——真实接入时需把返回交给注册方法） */
    fun interpret(records: List<Record>, args: Array<Any?>): Any? = null

    fun parse(image: ByteArray): List<Record> {
        val out = ArrayList<Record>()
        require(image.size >= 8 && String(image, 0, 4, Charsets.US_ASCII) == "NXVM") { "bad NXVM image" }
        var p = 4
        while (p + 4 <= image.size) {
            val len = (image[p].toInt() and 0xFF) or ((image[p + 1].toInt() and 0xFF) shl 8)
            val regs = image[p + 2].toInt() and 0xFF
            val ins = image[p + 3].toInt() and 0xFF
            if (p + 4 + len > image.size) break
            out.add(Record(regs, ins, image.copyOfRange(p + 4, p + 4 + len)))
            p += 4 + len
        }
        return out
    }

    fun load(ctx: Context, name: String = "vm.nxvm"): List<Record> =
        parse(NXRuntime.vmImage(ctx, name))
}