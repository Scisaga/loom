package io.github.scisaga.loom.enrollment

import android.content.Context
import io.github.scisaga.loom.security.EncryptedStore
import io.github.scisaga.loomcore.Loomcore

/** #14：view 与四组 floor 放进同一个 Keystore-wrapped 原子 blob。首次 latch 与后续更新严格分路。 */
class V2DeviceStateStore(context: Context) {
    private val protected = EncryptedStore(context.applicationContext)

    @Synchronized
    fun acceptInitialFromInvite(
        envelope: ByteArray,
        controlSet: ByteArray,
        descriptor: ByteArray,
        proofBundle: ByteArray,
        deviceID: String,
        identitySPKIHash: String,
        trustedTime: String,
    ): ByteArray {
        check(protected.get(STATE) == null) { "v2 Device 已 latch；首次 Invite proof 不能重放为更新" }
        val next = Loomcore.prepareInitialV2DeviceStateFromInvite(
            envelope,
            controlSet,
            descriptor,
            proofBundle,
            deviceID,
            identitySPKIHash,
            trustedTime,
        )
        return commitExact(next)
    }

    @Synchronized
    fun acceptUpdate(
        envelope: ByteArray,
        controlSet: ByteArray,
        deviceID: String,
        identitySPKIHash: String,
        previousControlSet: ByteArray = ByteArray(0),
    ): ByteArray {
        val current = checkNotNull(protected.get(STATE)) { "首次 v2 latch 必须绑定 verified Invite proof" }
        val next = Loomcore.prepareV2DeviceStateWithPrevious(
            envelope,
            controlSet,
            previousControlSet,
            deviceID,
            identitySPKIHash,
            current,
        )
        return commitExact(next)
    }

    @Synchronized
    fun installCompletion(next: ByteArray, clearPending: () -> Unit): ByteArray {
        Loomcore.validateAndroidV2DeviceState(next)
        val existing = protected.get(STATE)
        val durable = when {
            existing == null -> commitExact(next)
            existing.contentEquals(next) -> existing.also(Loomcore::validateAndroidV2DeviceState)
            else -> error("另一份 v2 Device state 已 latch；completion 不得覆盖")
        }
        // 删除 pending 是提交后的清理；若进程在此之前崩溃，启动时只允许
        // exact core/result 与 durable installation 匹配后继续清理（D130）。
        clearPending()
        return durable
    }

    @Synchronized
    fun current(): ByteArray? = protected.get(STATE)?.also(Loomcore::validateAndroidV2DeviceState)

    @Synchronized
    fun floors(): ByteArray? = protected.get(STATE)?.let(Loomcore::v2DeviceStateFloors)

    private fun commitExact(next: ByteArray): ByteArray {
        Loomcore.validateAndroidV2DeviceState(next)
        protected.put(STATE, next)
        val replay = checkNotNull(protected.get(STATE)) { "v2 Device state 未能持久保存" }
        check(replay.contentEquals(next)) { "v2 Device state 持久化回读不一致" }
        Loomcore.validateAndroidV2DeviceState(replay)
        return replay
    }

    companion object {
        private const val STATE = "device-v2-state"
    }
}
