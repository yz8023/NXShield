package com.nxshield.engine

import android.content.Context
import com.android.apksig.ApkSigner
import com.android.apksig.KeyConfig
import java.io.File
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate

/**
 * 内置签名器：用打包进 assets 的 nxshield.keystore 对重打包后的 APK 做 v1+v2 签名。
 * 产出可直接安装。
 */
object NxApkSigner {
    private const val KEYSTORE_ASSET = "nxshield.keystore"
    private const val ALIAS = "nxshield"
    private val PASSWORD = "nxshield123".toCharArray()

    /** 对 [unsigned] 签名，返回已签名 APK 字节 */
    fun sign(ctx: Context, unsigned: ByteArray, workDir: File): ByteArray {
        val ks = KeyStore.getInstance("PKCS12")
        ctx.assets.open(KEYSTORE_ASSET).use { ks.load(it, PASSWORD) }
        val entry = ks.getEntry(ALIAS, KeyStore.PasswordProtection(PASSWORD)) as KeyStore.PrivateKeyEntry
        val privateKey: PrivateKey = entry.privateKey
        val cert = entry.certificate as X509Certificate

        val signerConfig = ApkSigner.SignerConfig.Builder(
            ALIAS, KeyConfig.Jca(privateKey), listOf(cert),
        ).build()

        workDir.mkdirs()
        val inFile = File(workDir, "unsigned.apk")
        val outFile = File(workDir, "signed.apk")
        inFile.writeBytes(unsigned)
        if (outFile.exists()) outFile.delete()

        ApkSigner.Builder(listOf(signerConfig))
            .setInputApk(inFile)
            .setOutputApk(outFile)
            .setV1SigningEnabled(true)
            .setV2SigningEnabled(true)
            .setV3SigningEnabled(false)
            .setMinSdkVersion(26)
            .build()
            .sign()
        return outFile.readBytes()
    }
}