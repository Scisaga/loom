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
        protected.put(STATE, next)
        return next
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
        protected.put(STATE, next)
        return next
    }

    @Synchronized
    fun current(): ByteArray? = protected.get(STATE)

    @Synchronized
    fun floors(): ByteArray? = protected.get(STATE)?.let(Loomcore::v2DeviceStateFloors)

    companion object {
        private const val STATE = "device-v2-state"
    }
}
