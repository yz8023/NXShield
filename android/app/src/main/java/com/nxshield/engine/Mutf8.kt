package com.nxshield.engine

/** MUTF-8 (modified UTF-8) encode/decode，与 DEX 字符串一致 */
object Mutf8 {
    fun encode(s: String): ByteArray {
        val c = CharArray(s.length)
        s.toCharArray(c, 0, s.length)
        val out = ArrayList<Byte>()
        for (ch in c) {
            val cp = ch.code
            when {
                cp == 0 -> {
                    out.add(0xC0.toByte()); out.add(0x80.toByte())
                }
                cp in 1..0x7F -> out.add(cp.toByte())
                cp <= 0x7FF -> {
                    out.add((0xC0 or (cp shr 6)).toByte())
                    out.add((0x80 or (cp and 0x3F)).toByte())
                }
                else -> {
                    out.add((0xE0 or (cp shr 12)).toByte())
                    out.add((0x80 or ((cp shr 6) and 0x3F)).toByte())
                    out.add((0x80 or (cp and 0x3F)).toByte())
                }
            }
        }
        return out.toByteArray()
    }

    fun decode(b: ByteArray, off: Int, len: Int): Pair<String, Int> {
        var i = off
        val sb = StringBuilder()
        while (i < off + len && b[i].toInt() != 0) {
            val first = b[i].toInt() and 0xFF
            when {
                first and 0x80 == 0 -> { sb.append(first.toChar()); i += 1 }
                first and 0xE0 == 0xC0 -> {
                    val v = ((first and 0x1F) shl 6) or (b[i + 1].toInt() and 0x3F)
                    if (v == 0) i += 1 else { sb.append(v.toChar()); i += 2 }
                }
                else -> {
                    val v = ((first and 0x0F) shl 12) or ((b[i + 1].toInt() and 0x3F) shl 6) or (b[i + 2].toInt() and 0x3F)
                    sb.append(v.toChar()); i += 3
                }
            }
        }
        // 跳过结尾 0x00
        return Pair(sb.toString(), if (i < b.size && b[i].toInt() == 0) i else i)
    }

    fun decodeAt(b: ByteArray, off: Int): Pair<String, Int> {
        val (_, len) = Uleb.read(b, off)
        return decode(b, off + len.toInt(), b.size - (off + len.toInt()))
    }

    fun size(s: String): Int = encode(s).size
}