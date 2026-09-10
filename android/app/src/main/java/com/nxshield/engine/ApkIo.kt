package com.nxshield.engine

import java.io.ByteArrayOutputStream

/**
 * APK/ZIP 读写。使用纯原样复制条目数据 + 可替换单个条目。
 * 不依赖第三方库，直接解析 EOCD + 中央目录。
 */
class ZipEntryInfo(
    val name: String,
    val compression: Int,
    val localHeaderOff: Long,
    val dataOff: Long,
    val compressedSize: Long,
    val uncompressedSize: Long,
    var crc: Long,
    val flags: Int,
    val extraOff: Long,
    val extraLen: Int,
)

class ApkFixtures(
    val entries: List<ZipEntryInfo>,    // 中央目录顺序
    val data: ByteArray,                // 整个文件（沿用原结构，补丁时仅改动特定区间）
) {
    val entryMap: Map<String, ZipEntryInfo> by lazy { entries.associateBy { it.name } }

    fun find(name: String): ZipEntryInfo? = entryMap[name]

    /** 提取某个条目的压缩字节 */
    fun rawOf(e: ZipEntryInfo): ByteArray =
        data.copyOfRange(e.dataOff.toInt(), (e.dataOff + e.compressedSize).toInt())

    /** 解压某个条目 */
    fun inflate(e: ZipEntryInfo): ByteArray {
        val input = rawOf(e)
        if (e.compression == 0) {
            return input.copyOf(e.uncompressedSize.toInt())
        }
        val inflater = java.util.zip.Inflater(true)
        val bos = ByteArrayOutputStream()
        try {
            inflater.setInput(input)
            val buf = ByteArray(64 * 1024)
            while (!inflater.finished()) {
                val n = inflater.inflate(buf)
                if (n == 0) break
                bos.write(buf, 0, n)
            }
        } finally {
            inflater.end()
        }
        return bos.toByteArray()
    }
}

object ApkIo {
    const val EOCD_SIG = 0x06054b50L
    const val CENTRAL_SIG = 0x02014b50L
    const val LOCAL_SIG = 0x04034b50L

    fun open(data: ByteArray): ApkFixtures {
        // 从尾部找 EOCD（容忍注释）
        var eocdOff = -1
        val minOff = data.size - 65557
        for (i in data.size - 22 downTo (if (minOff < 0) 0 else minOff)) {
            if (data.readU4(i) == EOCD_SIG) { eocdOff = i; break }
        }
        require(eocdOff >= 0) { "ZIP: EOCD not found" }
        val centralSize = data.readU4(eocdOff + 12)
        val centralOff = data.readU4(eocdOff + 16)
        val entryCount = data.readU2(eocdOff + 10)

        val entries = ArrayList<ZipEntryInfo>()
        var off = centralOff.toInt()
        for (i in 0 until entryCount) {
            require(data.readU4(off) == CENTRAL_SIG) { "ZIP: bad central header at offset $off" }
            val compression = data.readU2(off + 10)
            val crc = data.readU4(off + 16)
            val csize = data.readU4(off + 20)
            val usize = data.readU4(off + 24)
            val nameLen = data.readU2(off + 28)
            val extraLen = data.readU2(off + 30)
            val commentLen = data.readU2(off + 32)
            val localOff = data.readU4(off + 42)
            val flags = data.readU2(off + 8)
            val name = String(data, off + 46, nameLen, Charsets.UTF_8)

            // 定位本地文件头，计算数据偏移
            require(data.readU4(localOff.toInt()) == LOCAL_SIG) { "ZIP: bad local header $name" }
            val localFnameLen = data.readU2(localOff.toInt() + 26)
            val localExtraLen = data.readU2(localOff.toInt() + 28)
            val dataStart = localOff.toInt() + 30 + localFnameLen + localExtraLen

            entries.add(
                ZipEntryInfo(
                    name = name, compression = compression, localHeaderOff = localOff,
                    dataOff = dataStart.toLong(), compressedSize = csize, uncompressedSize = usize,
                    crc = crc, flags = flags, extraOff = dataStart.toLong(), extraLen = localExtraLen,
                ),
            )
            off += 46 + nameLen + extraLen + commentLen
        }
        return ApkFixtures(entries, data)
    }

    /**
     * 用给定条目覆盖写回：重建压缩档，压缩级别与原条目一致（DEFLATED/STORED）。
     * 条目顺序保持原始中央目录顺序（Android 对 classes.dex 位置敏感，尽量保持）；
     * 新增条目（replacements 中不存在的原名）追加到末尾。
     */
    fun rebuild(apk: ApkFixtures, replacements: Map<String, ByteArray>, level: Int = 2): ByteArray {
        val bos = ByteArrayOutputStream()
        val localOffsets = HashMap<String, Long>()

        fun writeLocal(name: String, compression: Int, crc: Int, csize: Int, usize: Int, data: ByteArray) {
            val nameBytes = name.toByteArray(Charsets.UTF_8)
            val header = ByteArray(30 + nameBytes.size)
            header.w4(0, LOCAL_SIG)
            header.w2(4, 20)
            header.w2(6, 0)
            header.w2(8, compression)
            localOffsets[name] = bos.size().toLong()
            header.w2(10, 0); header.w2(12, 0)
            header.w4(14, crc.toLong())
            header.w4(18, usize.toLong())
            header.w4(22, csize.toLong())
            header.w2(26, nameBytes.size)
            header.w2(28, 0)
            nameBytes.copyInto(header, 30)
            bos.write(header)
            bos.write(data)
        }

        // 先算出最终要用的压缩方式，保证本地头与数据一致
        val deflateFor = HashMap<String, Boolean>()
        for (e in apk.entries) {
            deflateFor[e.name] = e.compression != 0
        }
        for (name in replacements.keys) {
            if (name !in deflateFor) deflateFor[name] = true
        }

        for (e in apk.entries) {
            val newData = replacements[e.name]
            if (newData != null) {
                val deflate = deflateFor[e.name] == true
                val comp = if (deflate) deflate(newData, level) else newData
                writeLocal(
                    e.name, if (deflate) 8 else 0,
                    crc32(newData).toInt(), comp.size, newData.size, comp,
                )
            } else {
                val raw = apk.rawOf(e)
                writeLocal(e.name, e.compression, e.crc.toInt(), raw.size, e.uncompressedSize.toInt(), raw)
            }
        }

        // 新增条目（assets/nxshield/* 等），默认 DEFLATED 压缩
        for ((name, data) in replacements) {
            if (name in apk.entryMap) continue
            val deflate = deflateFor[name] == true
            val comp = if (deflate) deflate(data, level) else data
            writeLocal(name, if (deflate) 8 else 0, crc32(data).toInt(), comp.size, data.size, comp)
        }

        // 中央目录
        val allNames = (apk.entries.map { it.name } + replacements.keys).distinct()
        val centralBytes = ByteArray(allNames.sumOf { it.toByteArray(Charsets.UTF_8).size + 46 })
        var centralOff = 0
        for (name in allNames) {
            val nameBytes = name.toByteArray(Charsets.UTF_8)
            val newData = replacements[name]
            val existing = apk.entryMap[name]
            val deflate = deflateFor[name] == true
            val storedCrc: Int
            val storedCsize: Int
            val storedUsize: Int
            val compression: Int
            val cflag: Int
            if (newData != null) {
                storedCrc = crc32(newData).toInt()
                storedUsize = newData.size
                storedCsize = if (deflate) deflate(newData, level).size else newData.size
                compression = if (deflate) 8 else 0
                cflag = if (existing == null) 0x0800 else 0
            } else {
                storedCrc = existing!!.crc.toInt()
                storedCsize = existing.compressedSize.toInt()
                storedUsize = existing.uncompressedSize.toInt()
                compression = existing.compression
                cflag = existing.flags
            }
            centralBytes.w4(centralOff, CENTRAL_SIG)
            centralBytes.w2(centralOff + 4, 20)
            centralBytes.w2(centralOff + 6, 20)
            centralBytes.w2(centralOff + 8, cflag)
            centralBytes.w2(centralOff + 10, compression)
            centralBytes.w2(centralOff + 12, 0); centralBytes.w2(centralOff + 14, 0)
            centralBytes.w4(centralOff + 16, storedCrc.toLong())
            centralBytes.w4(centralOff + 20, storedCsize.toLong())
            centralBytes.w4(centralOff + 24, storedUsize.toLong())
            centralBytes.w2(centralOff + 28, nameBytes.size)
            centralBytes.w2(centralOff + 30, 0)
            centralBytes.w2(centralOff + 32, 0)
            centralBytes.w2(centralOff + 34, 0)
            centralBytes.w2(centralOff + 36, 0)
            centralBytes.w4(centralOff + 38, 0)
            centralBytes.w4(centralOff + 42, localOffsets[name]!!)
            nameBytes.copyInto(centralBytes, centralOff + 46)
            centralOff += 46 + nameBytes.size
        }

        // EOCD
        val output = bos.toByteArray()
        val out = ByteArray(output.size + centralBytes.size + 22)
        output.copyInto(out, 0)
        centralBytes.copyInto(out, output.size)
        val eocd = output.size + centralBytes.size
        out.w4(eocd, EOCD_SIG)
        out.w2(eocd + 4, 0)
        out.w2(eocd + 6, 0)
        out.w2(eocd + 8, allNames.size)
        out.w2(eocd + 10, allNames.size)
        out.w4(eocd + 12, centralBytes.size.toLong())
        out.w4(eocd + 16, output.size.toLong())
        out.w2(eocd + 20, 0)
        return out
    }

    fun deflate(data: ByteArray, level: Int = 2): ByteArray {
        val deflater = java.util.zip.Deflater(level, true)
        try {
            deflater.setInput(data)
            deflater.finish()
            val bos = ByteArrayOutputStream(data.size / 2 + 64)
            val buf = ByteArray(64 * 1024)
            while (!deflater.finished()) {
                val n = deflater.deflate(buf)
                bos.write(buf, 0, n)
            }
            return bos.toByteArray()
        } finally {
            deflater.end()
        }
    }
}