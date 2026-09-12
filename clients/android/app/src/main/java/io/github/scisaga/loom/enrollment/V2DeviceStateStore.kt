package io.github.scisaga.loom.enrollment

import android.content.Context
import io.github.scisaga.loom.security.EncryptedStore
import io.github.scisaga.loom.security.DeviceKeyStore
import io.github.scisaga.loomcore.Loomcore
import org.json.JSONObject

/** #14：view 与四组 floor 放进同一个 Keystore-wrapped 原子 blob。首次 latch 与后续更新严格分路。 */
class V2DeviceStateStore(context: Context) {
    private val protected = EncryptedStore(context.applicationContext)
    private val keys = DeviceKeyStore()

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

    /** #14 / D131：只从 protected state 投影当前获权的 private overlay replicas。 */
    @Synchronized
    internal fun privateControlPlans(role: String, trustedTime: String): List<V2PrivateControlPlan> {
        val state = checkNotNull(protected.get(STATE)) { "[D131 Android control] v2 Device state 尚未安装" }
        Loomcore.validateAndroidV2DeviceState(state)
        return V2PrivateControlClient.decodePlans(
            Loomcore.prepareAndroidV2PrivateControlPlans(state, keys.ensureIdentity(), role, trustedTime),
            role,
        )
    }

    /** #14 / D105：private device_config 的响应经共享 QC/Merkle/floor verifier 后才原子替换 LKG。 */
    @Synchronized
    internal fun acceptPrivateView(envelope: ByteArray): ByteArray {
        val current = checkNotNull(protected.get(STATE)) { "[D131 Android config] v2 Device state 尚未安装" }
        val next = Loomcore.prepareAndroidV2PrivateDeviceViewUpdate(current, envelope, keys.ensureIdentity())
        return commitExact(next)
    }

    /** Issue #14：hydrate 后秘密只作为同一 VpnService 的内存启动参数。 */
    @Synchronized
    fun runtimeProfile(): ManagedProfile? = protected.get(STATE)?.let { state ->
        Loomcore.validateAndroidV2DeviceState(state)
        val persisted = JSONObject(state.decodeToString())
        if (persisted.getJSONObject("envelope").getJSONObject("payload").getString("state") != "active") {
            return@let null
        }
        val runtime = JSONObject(Loomcore.prepareAndroidV2Runtime(state).decodeToString())
        check(runtime.getInt("schema") == 1) { "v2 Android runtime projection schema 无效" }
        val headHash = runtime.getString("head_hash")
        ManagedProfile(
            nodeID = runtime.getString("device_id"),
            snapshot = headHash,
            generation = runtime.getLong("device_generation"),
            config = runtime.getString("sing_box_config"),
            routePlan = runtime.optString("route_plan").takeIf(String::isNotBlank),
            certificatePEM = ByteArray(0),
            caPEM = ByteArray(0),
            reportEndpoint = "",
            recordID = "v2:$headHash",
            protocol = 2,
        )
    }

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
