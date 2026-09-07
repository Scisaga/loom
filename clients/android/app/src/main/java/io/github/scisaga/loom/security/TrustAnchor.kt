package io.github.scisaga.loom.security

import io.github.scisaga.loom.BuildConfig
import io.github.scisaga.loomcore.Loomcore
import java.security.MessageDigest
import java.util.Base64

/** The deployment signing key embedded in this exact APK build. */
internal object TrustAnchor {
    fun validateEnrollmentInvite(inviteJSON: ByteArray) {
        Loomcore.validateEnrollmentInvitePlatformKey(inviteJSON, platformPublicKey())
    }

    /**
     * Re-anchor a stored bootstrap in the trust root compiled into the currently
     * running APK. The returned bytes always come from the APK, never from the
     * enrollment response.
     */
    fun platformPublicKeyForBootstrap(encodedBootstrapKey: String): ByteArray =
        matchBootstrapPlatformKey(platformPublicKey(), encodedBootstrapKey)

    internal fun platformPublicKey(): ByteArray {
        val encoded = BuildConfig.LOOM_PLATFORM_PUBLIC_KEY_B64.trim()
        check(encoded.isNotEmpty()) {
            "此 APK 未内建中控验签公钥；不会发送一次性加入凭据"
        }
        val decoded = runCatching { Base64.getDecoder().decode(encoded) }
            .getOrElse { error("此 APK 内建的中控验签公钥无效") }
        check(decoded.size == ED25519_PUBLIC_KEY_BYTES && Base64.getEncoder().encodeToString(decoded) == encoded) {
            "此 APK 内建的中控验签公钥无效"
        }
        return decoded
    }

    private const val ED25519_PUBLIC_KEY_BYTES = 32
}

internal fun matchBootstrapPlatformKey(
    pinnedPlatformKey: ByteArray,
    encodedBootstrapKey: String,
): ByteArray {
    check(pinnedPlatformKey.size == 32) { "APK 平台验签公钥长度无效" }
    val bootstrapKey = runCatching { Base64.getDecoder().decode(encodedBootstrapKey) }
        .getOrElse { error("bootstrap 平台验签公钥无效") }
    check(
        bootstrapKey.size == 32 &&
            Base64.getEncoder().encodeToString(bootstrapKey) == encodedBootstrapKey,
    ) { "bootstrap 平台验签公钥不是规范 Ed25519 base64" }
    check(MessageDigest.isEqual(pinnedPlatformKey, bootstrapKey)) {
        "bootstrap 平台验签公钥与当前 APK 信任根不匹配"
    }
    return pinnedPlatformKey.copyOf()
}
