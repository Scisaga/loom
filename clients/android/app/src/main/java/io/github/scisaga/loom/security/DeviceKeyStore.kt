package io.github.scisaga.loom.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import io.github.scisaga.loomcore.Loomcore
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.spec.ECGenParameterSpec

class DeviceKeyStore {
    private val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    fun ensureIdentity(): ByteArray {
        if (!keyStore.containsAlias(IDENTITY_ALIAS)) {
            val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
            generator.initialize(
                KeyGenParameterSpec.Builder(
                    IDENTITY_ALIAS,
                    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
                ).setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .build(),
            )
            generator.generateKeyPair()
        }
        val entry = keyStore.getEntry(IDENTITY_ALIAS, null) as KeyStore.PrivateKeyEntry
        check(entry.privateKey.encoded == null) { "Android Keystore 身份私钥竟可导出" }
        return entry.certificate.publicKey.encoded
    }

    fun sign(message: ByteArray): ByteArray {
        ensureIdentity()
        val entry = keyStore.getEntry(IDENTITY_ALIAS, null) as KeyStore.PrivateKeyEntry
        return Signature.getInstance("SHA256withECDSA").run {
            initSign(entry.privateKey)
            update(message)
            sign()
        }
    }

    fun proveBinding(): String {
        val publicKey = ensureIdentity()
        val message = "loom-keystore-proof-v1".encodeToByteArray()
        Loomcore.verifyP256Signature(publicKey, message, sign(message))
        return "P-256 / SHA256withECDSA / non-exportable"
    }

    fun createCSR(requestID: String): ByteArray {
        val info = Loomcore.prepareCSR(requestID, ensureIdentity())
        return Loomcore.assembleCSR(info, sign(info))
    }

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val IDENTITY_ALIAS = "loom-device-identity-v1"
    }
}
