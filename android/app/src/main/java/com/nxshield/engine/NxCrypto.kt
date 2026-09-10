package com.nxshield.engine

import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** NXS1 安全封装：MAGIC + salt + HMAC 摘要 + 自逆滚动 XOR */
object NxCrypto {
    val MAGIC = "NXS1".toByteArray(Charsets.US_ASCII)

    private fun mode(b: Byte): Int = (b.toInt() and 0xFF) % 7 + 2

    /** 累加器滚动 XOR，只依赖 key/位置，自逆 */
    fun rollingXor(data: ByteArray, key: ByteArray): ByteArray {
        val out = ByteArray(data.size)
        var acc = 0
        for (i in data.indices) {
            val m = mode(key[i % key.size])
            acc = (acc + key[i % key.size].toInt()) and 0xFF
            out[i] = (((data[i].toInt() xor acc) and 0xFF) xor ((acc * m) and 0xFF)).toByte()
        }
        return out
    }

    fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)

    fun deriveKey(pass: ByteArray, salt: ByteArray): ByteArray {
        var k = sha256(pass + salt)
        repeat(8192) { k = sha256(k) }
        return k.copyOf(32)
    }

    fun hmac(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(sha256(key), "HmacSHA256"))
        return mac.doFinal(data)
    }

    /** 封装：[NXS1]+salt(8)+hmac(16)+payload(滚动XOR)。tag=HMAC  前16字节 */
    fun wrap(payload: ByteArray, password: ByteArray): ByteArray {
        val salt = ByteArray(8).also { SecureRandom().nextBytes(it) }
        val key = deriveKey(password, salt)
        val body = rollingXor(payload, key)
        val tag = hmac(key, MAGIC + salt + body).copyOf(16)
        return MAGIC + salt + tag + body
    }

    fun unwrap(data: ByteArray, password: ByteArray): ByteArray {
        require(data.size >= 8 + 8 + 16) { "NXS1: payload too short" }
        require(data.copyOf(4).contentEquals(MAGIC)) { "NXS1: bad magic" }
        val salt = data.copyOfRange(4, 12)
        val tag = data.copyOfRange(12, 28)
        val body = data.copyOfRange(28, data.size)
        val key = deriveKey(password, salt)
        val expect = hmac(key, MAGIC + salt + body).copyOf(16)
        require(MessageDigest.isEqual(expect, tag)) { "NXS1: HMAC mismatch (wrong key / tampered)" }
        return rollingXor(body, key)
    }
}