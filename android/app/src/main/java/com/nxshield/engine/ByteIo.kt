package com.nxshield.engine

import java.util.zip.CRC32

fun ByteArray.readU1(off: Int): Int = this[off].toInt() and 0xFF
fun ByteArray.readU2(off: Int): Int = ((this[off].toInt() and 0xFF) or ((this[off + 1].toInt() and 0xFF) shl 8))
fun ByteArray.readU4(off: Int): Long = ((this[off].toLong() and 0xFF) or ((this[off + 1].toLong() and 0xFF) shl 8) or ((this[off + 2].toLong() and 0xFF) shl 16) or ((this[off + 3].toLong() and 0xFF) shl 24))
fun ByteArray.readU8(off: Int): Long = (this.readU4(off) and 0xFFFFFFFFL) or (this.readU4(off + 4) shl 32)

/** in-place 写入 */
fun ByteArray.w1(off: Int, v: Int) { this[off] = (v and 0xFF).toByte() }
fun ByteArray.w2(off: Int, v: Int) { this[off] = (v and 0xFF).toByte(); this[off + 1] = ((v ushr 8) and 0xFF).toByte() }
fun ByteArray.w4(off: Int, v: Long) { this[off] = (v and 0xFF).toByte(); this[off + 1] = ((v ushr 8) and 0xFF).toByte(); this[off + 2] = ((v ushr 16) and 0xFF).toByte(); this[off + 3] = ((v ushr 24) and 0xFF).toByte() }

fun utf8len(s: String): Int = s.toByteArray(Charsets.UTF_8).size

fun crc32(data: ByteArray): Long {
    val c = CRC32()
    c.update(data)
    return c.value
}