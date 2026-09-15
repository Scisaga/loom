package io.github.scisaga.loom.security

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import io.github.scisaga.loomcore.Loomcore
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.MGF1ParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

data class WrappingPublicKey(
    val profile: String,
    val subjectPublicKeyInfo: ByteArray,
)

class DeviceKeyStore(private val namespace: String = "") {
    private val identityAlias = "loom-device-identity-v1" + namespace
    private val p256WrappingAlias = "loom-device-wrapping-ecdh-v1" + namespace
    private val rsaWrappingAlias = "loom-device-wrapping-rsa2048-decrypt-v1" + namespace

    /** §7.2：只在该配置的任务停止后移除其本机密钥。 */
    fun deleteIdentity() {
        listOf(identityAlias, p256WrappingAlias, rsaWrappingAlias).forEach { alias ->
            if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)
        }
    }

    private val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    /** 诊断路径只读既有 alias，不能在 v2 token-free preflight 前创建 identity。 */
    fun identityStatus(): String {
        if (!keyStore.containsAlias(identityAlias)) return "尚未生成（等待 v2 preflight）"
        val entry = keyStore.getEntry(identityAlias, null) as KeyStore.PrivateKeyEntry
        check(entry.privateKey.encoded == null) { "Android Keystore identity 私钥竟可导出" }
        return "non-exportable P-256"
    }

    fun ensureIdentity(): ByteArray {
        if (!keyStore.containsAlias(identityAlias)) {
            val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
            generator.initialize(
                KeyGenParameterSpec.Builder(
                    identityAlias,
                    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
                ).setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .build(),
            )
            generator.generateKeyPair()
        }
        val entry = keyStore.getEntry(identityAlias, null) as KeyStore.PrivateKeyEntry
        check(entry.privateKey.encoded == null) { "Android Keystore 身份私钥竟可导出" }
        return entry.certificate.publicKey.encoded
    }

    fun sign(message: ByteArray): ByteArray {
        ensureIdentity()
        val entry = keyStore.getEntry(identityAlias, null) as KeyStore.PrivateKeyEntry
        return Signature.getInstance("SHA256withECDSA").run {
            initSign(entry.privateKey)
            update(message)
            sign()
        }
    }

    fun signCanonicalV2(message: ByteArray): ByteArray =
        Loomcore.normalizeP256Signature(ensureIdentity(), message, sign(message))

    /** #14：TLS 只能取得 AndroidKeyStore handle；private key bytes 永远不跨进 Go 或应用存储。 */
    internal fun identityPrivateKey(): PrivateKey {
        ensureIdentity()
        val entry = keyStore.getEntry(identityAlias, null) as KeyStore.PrivateKeyEntry
        check(entry.privateKey.encoded == null) { "Android Keystore identity 私钥竟可导出" }
        return entry.privateKey
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

    fun createCSRDER(requestID: String): ByteArray {
        val identity = ensureIdentity()
        val info = Loomcore.prepareCSR(requestID, identity)
        return Loomcore.assembleCSRDER(info, sign(info)).also { csr ->
            Loomcore.verifyCSRIdentity(csr, identity)
        }
    }

    /** #14：wrapping key 与 identity alias 分离，不能被 Device identity/operation signer 调用。 */
    fun ensureWrapping(): WrappingPublicKey = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        ensureP256Wrapping()
    } else {
        ensureRSAWrapping()
    }

    fun deriveWrappingSharedSecret(ephemeralSubjectPublicKeyInfo: ByteArray): ByteArray {
        check(Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) { "API 26–30 必须使用 RSA-OAEP wrapping fallback" }
        val wrapping = ensureP256Wrapping()
        val peer = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC)
            .generatePublic(X509EncodedKeySpec(ephemeralSubjectPublicKeyInfo))
        check(peer.algorithm == KeyProperties.KEY_ALGORITHM_EC) { "封装方 ephemeral key 不是 P-256 EC key" }
        val entry = keyStore.getEntry(p256WrappingAlias, null) as KeyStore.PrivateKeyEntry
        check(entry.privateKey.encoded == null) { "Android Keystore wrapping 私钥竟可导出" }
        check(entry.certificate.publicKey.encoded.contentEquals(wrapping.subjectPublicKeyInfo)) {
            "Android Keystore wrapping public key 在派生前发生变化"
        }
        return KeyAgreement.getInstance("ECDH").run {
            init(entry.privateKey)
            doPhase(peer, true)
            generateSecret()
        }.also { check(it.isNotEmpty()) { "Android Keystore ECDH 未产生 shared secret" } }
    }

    fun decryptWrappingRSAOAEP(ciphertext: ByteArray): ByteArray {
        check(Build.VERSION.SDK_INT < Build.VERSION_CODES.S) { "API 31+ 必须使用独立 P-256 ECDH wrapping key" }
        ensureRSAWrapping()
        val entry = keyStore.getEntry(rsaWrappingAlias, null) as KeyStore.PrivateKeyEntry
        check(entry.privateKey.encoded == null) { "Android Keystore wrapping 私钥竟可导出" }
        return Cipher.getInstance(RSA_TRANSFORMATION).run {
            init(
                Cipher.DECRYPT_MODE,
                entry.privateKey,
                OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT),
            )
            doFinal(ciphertext)
        }
    }

    /** #14：由 AndroidKeyStore 返回的授权用途证明 wrapping alias 没有签名权限。 */
    fun wrappingHasSigningPurpose(): Boolean {
        ensureWrapping()
        val alias = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) p256WrappingAlias else rsaWrappingAlias
        val entry = keyStore.getEntry(alias, null) as KeyStore.PrivateKeyEntry
        val factory = KeyFactory.getInstance(entry.privateKey.algorithm, ANDROID_KEYSTORE)
        val info = factory.getKeySpec(entry.privateKey, KeyInfo::class.java)
        return info.purposes and KeyProperties.PURPOSE_SIGN != 0
    }

    private fun ensureP256Wrapping(): WrappingPublicKey {
        check(Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) { "P-256 Keystore ECDH 需要 API 31+" }
        if (!keyStore.containsAlias(p256WrappingAlias)) {
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE).run {
                initialize(
                    KeyGenParameterSpec.Builder(
                        p256WrappingAlias,
                        KeyProperties.PURPOSE_AGREE_KEY,
                    )
                        .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                        .build(),
                )
                generateKeyPair()
            }
        }
        val entry = keyStore.getEntry(p256WrappingAlias, null) as KeyStore.PrivateKeyEntry
        check(entry.privateKey.encoded == null) { "Android Keystore wrapping 私钥竟可导出" }
        check(entry.privateKey.algorithm == KeyProperties.KEY_ALGORITHM_EC) { "wrapping key algorithm 被替换" }
        return WrappingPublicKey(P256_WRAPPING_PROFILE, entry.certificate.publicKey.encoded)
    }

    private fun ensureRSAWrapping(): WrappingPublicKey {
        check(Build.VERSION.SDK_INT in Build.VERSION_CODES.O until Build.VERSION_CODES.S) {
            "RSA-OAEP wrapping fallback 只允许 API 26–30"
        }
        if (!keyStore.containsAlias(rsaWrappingAlias)) {
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE).run {
                initialize(
                    KeyGenParameterSpec.Builder(
                        rsaWrappingAlias,
                        KeyProperties.PURPOSE_DECRYPT,
                    )
                        .setKeySize(2048)
                        .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA1)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                        .build(),
                )
                generateKeyPair()
            }
        }
        val entry = keyStore.getEntry(rsaWrappingAlias, null) as KeyStore.PrivateKeyEntry
        check(entry.privateKey.encoded == null) { "Android Keystore wrapping 私钥竟可导出" }
        check(entry.privateKey.algorithm == KeyProperties.KEY_ALGORITHM_RSA) { "wrapping key algorithm 被替换" }
        return WrappingPublicKey(RSA_WRAPPING_PROFILE, entry.certificate.publicKey.encoded)
    }

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val P256_WRAPPING_PROFILE = "p256-keystore-ecdh-v1"
        private const val RSA_WRAPPING_PROFILE = "rsa2048-keystore-decrypt-v1"
        private const val RSA_TRANSFORMATION = "RSA/ECB/OAEPPadding"
    }
}
