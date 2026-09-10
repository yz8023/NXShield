package com.nxshield.engine

object Uleb {
    /** 读取 uleb128，返回 (value, nextIndex) */
    fun read(b: ByteArray, off: Int): LongArray {
        var result = 0L
        var shift = 0
        var i = off
        while (true) {
            val byte = b[i].toInt() and 0xFF
            result = result or ((byte and 0x7F).toLong() shl shift)
            if (byte and 0x80 == 0) break
            shift += 7
            i += 1
            require(shift <= 70) { "uleb128 overflow" }
        }
        return longArrayOf(result, (i - off + 1).toLong())
    }

    /** 读取 sleb128（有符号） */
    fun readSigned(b: ByteArray, off: Int): LongArray {
        var result = 0L
        var shift = 0
        var i = off
        var byte: Int
        do {
            byte = b[i].toInt() and 0xFF
            result = result or ((byte and 0x7F).toLong() shl shift)
            shift += 7
            i += 1
        } while (byte and 0x80 != 0)
        if (shift < 64 && byte and 0x40 != 0) {
            result = result or (-1L shl shift)
        }
        return longArrayOf(result, (i - off).toLong())
    }

    fun write(value: Long, out: MutableList<Byte>) {
        var v = value
        while (true) {
            var b = (v and 0x7F).toInt()
            v = v ushr 7
            if (v != 0L) b = b or 0x80
            out.add(b.toByte())
            if (v == 0L) break
        }
    }

    fun write(value: Long): ByteArray {
        val out = ArrayList<Byte>()
        write(value, out)
        return out.toByteArray()
    }
}