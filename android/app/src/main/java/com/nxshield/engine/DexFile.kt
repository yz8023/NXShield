package com.nxshield.engine

/**
 * 自研轻量 DEX 解析器（只读，用于分析 + 字符串定位 + 方法抽取）。
 * 不做完整重写，采用「原位补丁」策略保证结构合法。
 */
class DexFile(val data: ByteArray) {
    val stringIdsOff: Long
    val stringIdsSize: Long
    val typeIdsOff: Long
    val typeIdsSize: Long
    val protoIdsOff: Long
    val protoIdsSize: Long
    val fieldIdsOff: Long
    val fieldIdsSize: Long
    val methodIdsOff: Long
    val methodIdsSize: Long
    val classDefsOff: Long
    val classDefsSize: Long

    init {
        require(data.size >= 0x78) { "DEX: too small" }
        require(String(data.copyOfRange(0, 8), Charsets.US_ASCII).startsWith("dex\n")) { "DEX: bad magic" }
        // DEX header: string_ids@0x38, type_ids@0x40, proto_ids@0x48,
        // field_ids@0x50, method_ids@0x58, class_defs@0x60（每项 size/off 各 u4）
        stringIdsSize = data.readU4(0x38)
        stringIdsOff = data.readU4(0x3C)
        typeIdsSize = data.readU4(0x40)
        typeIdsOff = data.readU4(0x44)
        protoIdsSize = data.readU4(0x48)
        protoIdsOff = data.readU4(0x4C)
        fieldIdsSize = data.readU4(0x50)
        fieldIdsOff = data.readU4(0x54)
        methodIdsSize = data.readU4(0x58)
        methodIdsOff = data.readU4(0x5C)
        classDefsSize = data.readU4(0x60)
        classDefsOff = data.readU4(0x64)
    }

    fun stringDataOff(idx: Int): Long = data.readU4((stringIdsOff + idx * 4L).toInt())

    fun stringAt(idx: Int): String {
        val off = stringDataOff(idx).toInt()
        return Mutf8.decodeAt(data, off).first
    }

    fun typeString(idx: Int): String {
        val desc = data.readU4((typeIdsOff + idx * 4L).toInt()).toInt()
        return stringAt(desc)
    }

    fun rawTypeString(idx: Int): String {
        val desc = data.readU4((typeIdsOff + idx * 4L).toInt()).toInt()
        val s = stringAt(desc)
        return s.replace('/', '.').removePrefix("L").removeSuffix(";")
    }

    fun methodSig(idx: Int): String {
        val classIdx = data.readU2((methodIdsOff + idx * 8L).toInt())
        val protoIdx = data.readU2((methodIdsOff + idx * 8L + 2).toInt())
        val nameIdx = data.readU4((methodIdsOff + idx * 8L + 4).toInt()).toInt()
        // proto_id_item 紧邻排布于 proto_ids，无需解引用：shorty_idx(u4) return_type_idx(u4) parameters_off(u4)
        val protoItemOff = protoIdsOff + protoIdx * 12L
        val returnIdx = data.readU4((protoItemOff + 4).toInt()).toInt()
        val paramsOff = data.readU4((protoItemOff + 8).toInt())
        val className = rawTypeString(classIdx)
        val methodName = stringAt(nameIdx)
        val params = ArrayList<String>()
        if (paramsOff != 0L) {
            val (count, after) = Uleb.read(data, paramsOff.toInt())
            var p = paramsOff.toInt() + after.toInt()
            for (i in 0 until count) {
                val (tidx, skipped) = Uleb.read(data, p)
                params.add(rawTypeString(tidx.toInt()))
                p += skipped.toInt()
            }
        }
        val ret = rawTypeString(returnIdx)
        return "$className->$methodName(${params.joinToString(",")}):$ret"
    }

    fun fieldSig(idx: Int): String {
        val classIdx = data.readU2((fieldIdsOff + idx * 8L).toInt())
        val nameIdx = data.readU4((fieldIdsOff + idx * 8L + 4).toInt()).toInt()
        return "${rawTypeString(classIdx)}.${stringAt(nameIdx)}"
    }

    /** 遍历所有字符串（仅拉丁可读 + CJK），用于敏感性分析 */
    fun allStrings(): List<Pair<Int, String>> {
        val out = ArrayList<Pair<Int, String>>()
        for (i in 0 until stringIdsSize.toInt()) {
            val off = stringDataOff(i).toInt()
            val (s, _) = Mutf8.decodeAt(data, off)
            if (s.isNotEmpty() && s.length <= 256) out.add(Pair(i, s))
        }
        return out
    }

    /**
     * 遍历类 → 方法。返回 (methodIdx, codeOff)
     * class_data_item 布局：4 个 uleb 计数 → 静态字段 → 实例字段 → 直接方法 → 虚方法。
     * 必须完整跳过字段列表，且 direct/virtual 的 method_idx_diff 各自从 0 累加。
     */
    fun methodsWithCode(): List<MethodCode> {
        val out = ArrayList<MethodCode>()
        for (c in 0 until classDefsSize.toInt()) {
            val cd = classDefsOff + c * 32L
            val classDataOff = data.readU4((cd + 24).toInt())
            if (classDataOff == 0L) continue
            runCatching {
                var p = classDataOff.toInt()
                val (staticFields, a1) = Uleb.read(data, p); p += a1.toInt()
                val (instFields, a2) = Uleb.read(data, p); p += a2.toInt()
                val (directMethods, a3) = Uleb.read(data, p); p += a3.toInt()
                val (virtualMethods, a4) = Uleb.read(data, p); p += a4.toInt()

                // 跳过 encoded_field: field_idx_diff(u) + access_flags(u)
                repeat(staticFields.toInt()) {
                    val (_, s) = Uleb.read(data, p); p += s.toInt()
                    val (_, s2) = Uleb.read(data, p); p += s2.toInt()
                }
                repeat(instFields.toInt()) {
                    val (_, s) = Uleb.read(data, p); p += s.toInt()
                    val (_, s2) = Uleb.read(data, p); p += s2.toInt()
                }

                // encoded_method: method_idx_diff(u) + access_flags(u) + code_off(u)
                var last = 0L
                repeat(directMethods.toInt()) {
                    val (d, s) = Uleb.read(data, p); p += s.toInt(); last += d
                    val (_, s2) = Uleb.read(data, p); p += s2.toInt()
                    val (codeOff, s3) = Uleb.read(data, p); p += s3.toInt()
                    if (codeOff != 0L) out.add(MethodCode(last.toInt(), codeOff.toInt()))
                }
                last = 0L
                repeat(virtualMethods.toInt()) {
                    val (d, s) = Uleb.read(data, p); p += s.toInt(); last += d
                    val (_, s2) = Uleb.read(data, p); p += s2.toInt()
                    val (codeOff, s3) = Uleb.read(data, p); p += s3.toInt()
                    if (codeOff != 0L) out.add(MethodCode(last.toInt(), codeOff.toInt()))
                }
            }
        }
        return out
    }

    /** 在 DEX 二进制中定位字符串内容（编码 + 长度 uleb），供原位替换 */
    fun locateStringData(idx: Int): StringLocation? {
        val off = stringDataOff(idx).toInt()
        val (len, lenBytes) = Uleb.read(data, off)
        val contentStart = off + lenBytes.toInt()
        // 计算截至字符串结尾（包括 0x00）
        val (_, decodedTotal) = Mutf8.decode(data, contentStart, data.size - contentStart)
        val contentLen = decodedTotal - contentStart
        return StringLocation(contentStart, contentLen, lenBytes.toInt())
    }
}

class StringLocation(val contentStart: Int, val contentLen: Int, val lebLen: Int)

class MethodCode(val methodIdx: Int, val codeOff: Int)

/** 解析 code_item：registers_size(u2@0) ins_size(u2@2) outs_size(u2@4) tries_size(u2@6) debug_info_off(u4@8) insns_size(u4@12) insns@16 */
fun readCodeInsns(data: ByteArray, codeOff: Int): Triple<Int, Int, Int> /* registers, ins, insnsLenBytes */ {
    val registers = data.readU2(codeOff)
    val ins = data.readU2(codeOff + 2)
    val insnsSize = data.readU4(codeOff + 12).toInt()
    return Triple(registers, ins, insnsSize * 2)
}