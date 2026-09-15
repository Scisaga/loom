package io.github.scisaga.loom.enrollment

import android.util.Base64
import io.github.scisaga.loom.security.DeviceKeyStore
import io.github.scisaga.loom.security.WrappingPublicKey
import io.github.scisaga.loomcore.Loomcore
import org.json.JSONObject
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** #14：共享 Go 核心解释 wire；Kotlin callback 只调用不可导出的 Keystore key。 */
internal class V2EnrollmentCrypto(
    private val keys: DeviceKeyStore = DeviceKeyStore(),
) {
    fun identitySubjectPublicKeyInfo(): ByteArray = keys.ensureIdentity()

    fun wrappingPublicKey(): WrappingPublicKey = keys.ensureWrapping()

    fun createCSRDER(requestID: String): ByteArray = keys.createCSRDER(requestID)

    fun claimCoreHash(canonicalCore: ByteArray): String = Loomcore.enrollmentClaimCoreHashV2(canonicalCore)

    fun preparePreflight(
        canonicalDescriptor: ByteArray,
        canonicalProofBundle: ByteArray,
        trustedTime: String,
    ): ByteArray = Loomcore.prepareAndroidEnrollmentV2Preflight(
        canonicalDescriptor,
        canonicalProofBundle,
        trustedTime,
    )

    /** #14：这个验证返回成功之前不得调用 ensureIdentity/ensureWrapping。 */
    fun verifyPreflightBeforeKeys(
        canonicalDescriptor: ByteArray,
        canonicalProofBundle: ByteArray,
        canonicalResponse: ByteArray,
        trustedTime: String,
    ): ByteArray = Loomcore.verifyAndroidEnrollmentV2Preflight(
        canonicalDescriptor,
        canonicalProofBundle,
        canonicalResponse,
        trustedTime,
    )

    fun prepareStableClaimCore(
        canonicalDescriptor: ByteArray,
        canonicalProofBundle: ByteArray,
        canonicalPreflightResponse: ByteArray,
        requestID: String,
        clientNonce: ByteArray,
        trustedTime: String,
    ): ByteArray {
        // 先单独复验 token-free opening，再创建不可导出 key。
        verifyPreflightBeforeKeys(
            canonicalDescriptor,
            canonicalProofBundle,
            canonicalPreflightResponse,
            trustedTime,
        )
        val identity = keys.ensureIdentity()
        val wrapping = keys.ensureWrapping()
        val csr = keys.createCSRDER(requestID)
        return Loomcore.prepareAndroidEnrollmentV2ClaimCore(
            canonicalDescriptor,
            canonicalProofBundle,
            canonicalPreflightResponse,
            requestID,
            identity,
            csr,
            wrapping.subjectPublicKeyInfo,
            wrapping.profile,
            clientNonce,
            trustedTime,
        )
    }

    fun preparePoPBody(
        canonicalDescriptor: ByteArray,
        canonicalProofBundle: ByteArray,
        canonicalPreflightResponse: ByteArray,
        canonicalClaimCore: ByteArray,
        canonicalChallenge: ByteArray,
        trustedTime: String,
    ): ByteArray = Loomcore.prepareAndroidEnrollmentV2PoPBody(
        canonicalDescriptor,
        canonicalProofBundle,
        canonicalPreflightResponse,
        canonicalClaimCore,
        canonicalChallenge,
        trustedTime,
    )

    fun assembleClaimSubmission(
        canonicalDescriptor: ByteArray,
        canonicalProofBundle: ByteArray,
        canonicalPreflightResponse: ByteArray,
        canonicalClaimCore: ByteArray,
        canonicalChallenge: ByteArray,
        trustedTime: String,
    ): ByteArray {
        val pop = preparePoPBody(
            canonicalDescriptor,
            canonicalProofBundle,
            canonicalPreflightResponse,
            canonicalClaimCore,
            canonicalChallenge,
            trustedTime,
        )
        return Loomcore.assembleAndroidEnrollmentV2ClaimSubmission(
            canonicalDescriptor,
            canonicalProofBundle,
            canonicalPreflightResponse,
            canonicalClaimCore,
            canonicalChallenge,
            pop,
            signPoP(pop),
            trustedTime,
        )
    }

    fun verifyClaimResult(
        canonicalDescriptor: ByteArray,
        canonicalProofBundle: ByteArray,
        canonicalPreflightResponse: ByteArray,
        canonicalClaimCore: ByteArray,
        canonicalResult: ByteArray,
        trustedTime: String,
    ): ByteArray = Loomcore.verifyAndroidEnrollmentV2ClaimResult(
        canonicalDescriptor,
        canonicalProofBundle,
        canonicalPreflightResponse,
        canonicalClaimCore,
        canonicalResult,
        trustedTime,
    )

    fun signPoP(canonicalPoPBody: ByteArray): String {
        val exactMessage = Loomcore.enrollmentPoPMessageV2(canonicalPoPBody)
        val signature = keys.signCanonicalV2(exactMessage)
        return Base64.encodeToString(signature, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
    }

    fun signPreflightMessage(exactMessage: ByteArray): String =
        Base64.encodeToString(
            keys.signCanonicalV2(exactMessage),
            Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP,
        )

    /** #14：ref/envelope 先由共享 verifier 绑定，Kotlin 只负责调用不可导出的 wrapping key。 */
    fun unsealSecret(
        canonicalRef: ByteArray,
        canonicalEnvelope: ByteArray,
        recipientID: String,
        recipientKeyGeneration: Long = 1,
    ): ByteArray {
        val wrapping = keys.ensureWrapping()
        return when (wrapping.profile) {
            P256_WRAPPING_PROFILE -> unsealP256(
                canonicalRef,
                canonicalEnvelope,
                recipientID,
                recipientKeyGeneration,
                wrapping,
            )

            RSA_WRAPPING_PROFILE -> unsealRSA(
                canonicalRef,
                canonicalEnvelope,
                recipientID,
                recipientKeyGeneration,
                wrapping,
            )

            else -> error("未获 v2 sealing policy 授权的 wrapping profile")
        }
    }

    /** 解封明文只在此栈帧存活；持久格式由 Go 重新绑定 exact ref/envelope 后生成。 */
    fun unsealInstalledSecret(
        canonicalRef: ByteArray,
        canonicalEnvelope: ByteArray,
        recipientID: String,
        recipientKeyGeneration: Long = 1,
    ): ByteArray {
        val secret = unsealSecret(
            canonicalRef,
            canonicalEnvelope,
            recipientID,
            recipientKeyGeneration,
        )
        return try {
            Loomcore.prepareAndroidInstalledSecretV2(canonicalRef, canonicalEnvelope, secret)
        } finally {
            secret.fill(0)
        }
    }

    private fun unsealP256(
        ref: ByteArray,
        envelope: ByteArray,
        recipientID: String,
        generation: Long,
        wrapping: WrappingPublicKey,
    ): ByteArray {
        val prepared = Loomcore.prepareSealedSecretP256UnsealV2(
            ref,
            envelope,
            recipientID,
            generation,
            wrapping.subjectPublicKeyInfo,
        )
        val root = JSONObject(prepared.decodeToString())
        val shared = keys.deriveWrappingSharedSecret(decodeURL(root.getString("ephemeral_spki_der")))
        val normalizedShared = when {
            shared.size == 32 -> shared
            shared.size in 1..31 -> ByteArray(32 - shared.size) + shared
            else -> error("Android Keystore ECDH shared secret 长度无效")
        }
        val key = Loomcore.deriveSealedSecretP256KEKV2(
            normalizedShared,
            root.getJSONObject("wrap_context").toString().encodeToByteArray(),
        )
        return try {
            val cek = openAESGCM(
                key,
                decodeURL(root.getString("wrap_nonce")),
                decodeURL(root.getString("wrapped_cek_and_tag")),
                decodeURL(root.getString("wrap_aad")),
            )
            try {
                finishPayload(root, cek)
            } finally {
                cek.fill(0)
            }
        } finally {
            key.fill(0)
            normalizedShared.fill(0)
            if (normalizedShared !== shared) shared.fill(0)
        }
    }

    private fun unsealRSA(
        ref: ByteArray,
        envelope: ByteArray,
        recipientID: String,
        generation: Long,
        wrapping: WrappingPublicKey,
    ): ByteArray {
        val prepared = Loomcore.prepareSealedSecretRSAUnsealV2(
            ref,
            envelope,
            recipientID,
            generation,
            wrapping.subjectPublicKeyInfo,
        )
        val root = JSONObject(prepared.decodeToString())
        val cek = keys.decryptWrappingRSAOAEP(decodeURL(root.getString("wrapped_cek")))
        require(cek.size == 32) { "Android Keystore RSA-OAEP 返回的 CEK 长度无效" }
        return try {
            finishPayload(root, cek)
        } finally {
            cek.fill(0)
        }
    }

    private fun finishPayload(root: JSONObject, cek: ByteArray): ByteArray {
        val plaintext = openAESGCM(
            cek,
            decodeURL(root.getString("content_nonce")),
            decodeURL(root.getString("ciphertext_and_tag")),
            decodeURL(root.getString("payload_aad")),
        )
        return try {
            Loomcore.finishSealedSecretPlaintextV2(
                plaintext,
                root.getJSONObject("context").toString().encodeToByteArray(),
            )
        } finally {
            plaintext.fill(0)
        }
    }

    private fun openAESGCM(key: ByteArray, nonce: ByteArray, ciphertextAndTag: ByteArray, aad: ByteArray): ByteArray {
        require(key.size == 32 && nonce.size == 12 && ciphertextAndTag.size >= 16) {
            "v2 AES-GCM key/nonce/ciphertext 长度无效"
        }
        return Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            updateAAD(aad)
            doFinal(ciphertextAndTag)
        }
    }

    private fun decodeURL(value: String): ByteArray = Base64.decode(
        value,
        Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP,
    ).also {
        require(Base64.encodeToString(it, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP) == value) {
            "v2 sealed secret 字段不是 canonical base64url"
        }
    }

    private companion object {
        const val P256_WRAPPING_PROFILE = "p256-keystore-ecdh-v1"
        const val RSA_WRAPPING_PROFILE = "rsa2048-keystore-decrypt-v1"
    }
}
