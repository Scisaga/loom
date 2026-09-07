package io.github.scisaga.loom.security

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.io.FileOutputStream
import java.nio.file.StandardCopyOption
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class EncryptedStore(context: Context) {
    private val directory = context.filesDir.resolve("protected").apply { mkdirs() }
    private val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    fun put(name: String, plaintext: ByteArray) {
        validateName(name)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, encryptionKey())
        val ciphertext = cipher.doFinal(plaintext)
        val encoded = byteArrayOf(FORMAT_VERSION, cipher.iv.size.toByte()) + cipher.iv + ciphertext
        val target = directory.resolve(name)
        val temporary = File(directory, ".$name.tmp")
        FileOutputStream(temporary).use {
            it.write(encoded)
            it.fd.sync()
        }
        java.nio.file.Files.move(
            temporary.toPath(),
            target.toPath(),
            StandardCopyOption.ATOMIC_MOVE,
            StandardCopyOption.REPLACE_EXISTING,
        )
    }

    fun get(name: String): ByteArray? {
        validateName(name)
        val file = directory.resolve(name)
        if (!file.exists()) return null
        val encoded = file.readBytes()
        require(encoded.size >= 2 + 12 + 16 && encoded[0] == FORMAT_VERSION) { "受保护数据格式无效" }
        val ivSize = encoded[1].toInt() and 0xff
        require(ivSize in 12..16 && encoded.size > 2 + ivSize + 15) { "受保护数据 IV 无效" }
        val iv = encoded.copyOfRange(2, 2 + ivSize)
        val ciphertext = encoded.copyOfRange(2 + ivSize, encoded.size)
        return Cipher.getInstance(TRANSFORMATION).run {
            init(Cipher.DECRYPT_MODE, encryptionKey(), GCMParameterSpec(128, iv))
            doFinal(ciphertext)
        }
    }

    fun remove(name: String) {
        validateName(name)
        val file = directory.resolve(name)
        if (file.exists()) check(file.delete()) { "无法清除受保护数据" }
    }

    internal fun fileForTest(name: String): File = directory.resolve(name)

    private fun encryptionKey(): SecretKey {
        if (!keyStore.containsAlias(STORAGE_ALIAS)) {
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE).run {
                init(
                    KeyGenParameterSpec.Builder(
                        STORAGE_ALIAS,
                        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                    ).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setRandomizedEncryptionRequired(true)
                        .build(),
                )
                generateKey()
            }
        }
        return keyStore.getKey(STORAGE_ALIAS, null) as SecretKey
    }

    private fun validateName(name: String) {
        require(name.matches(Regex("[a-z0-9][a-z0-9.-]{0,63}"))) { "受保护数据名称无效" }
    }

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val STORAGE_ALIAS = "loom-private-storage-v1"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val FORMAT_VERSION: Byte = 1
    }
}
