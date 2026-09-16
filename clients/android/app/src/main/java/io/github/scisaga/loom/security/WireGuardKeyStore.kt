package io.github.scisaga.loom.security

import android.content.Context
import io.github.scisaga.loomcore.Loomcore

/** 独立于不可导出的身份/封装 key；X25519 原始值只留在本机加密存储与 VPN 内存。 */
internal class WireGuardKeyStore(context: Context) {
    private val storage = EncryptedStore(context.applicationContext)

    fun existing(): ByteArray? = storage.get(NAME)?.also { require(it.size == 32) { "本机 WireGuard 密钥损坏" } }

    fun publicKeyForEnrollment(): ByteArray = synchronized(lock) {
        val private = existing() ?: Loomcore.generateLocalWireGuardKey().also { storage.put(NAME, it) }
        try { Loomcore.localWireGuardPublicKey(private) } finally { private.fill(0) }
    }

    companion object {
        private const val NAME = "wireguard-v2.key"
        private val lock = Any()
    }
}
