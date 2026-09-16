package io.github.scisaga.loom.enrollment

import io.github.scisaga.loom.profiles.ProfileContext
import android.content.Context
import android.util.AtomicFile
import io.github.scisaga.loom.security.EncryptedStore
import io.github.scisaga.loom.security.DeviceKeyStore
import io.github.scisaga.libbox.Libbox
import io.github.scisaga.loomcore.Loomcore
import org.json.JSONObject
import java.security.MessageDigest

internal data class V2InstalledDeviceState(
    val encoded: ByteArray,
    val lifecycleState: String,
    val nodeID: String,
    val generation: Long,
    val runtimeProfile: ManagedProfile?,
)

/** view 与四组 floor 放进同一个 Keystore-wrapped 原子 blob。首次 latch 与后续更新严格分路。 */
class V2DeviceStateStore(context: Context) {
    private val protected = EncryptedStore(context.applicationContext)
    private val keys = DeviceKeyStore(ProfileContext.keySuffix(context))
    private val wireGuard = io.github.scisaga.loom.security.WireGuardKeyStore(context)
    private val runtimeDirectory = libboxWorkingDirectory(context.filesDir)

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
        // exact core/result 与 durable installation 匹配后继续清理。
        clearPending()
        return durable
    }

    @Synchronized
    internal fun installMigration(next: ByteArray): ManagedProfile {
        Loomcore.validateAndroidV2DeviceState(next)
        val parsed = JSONObject(next.decodeToString())
        check(parsed.has("migration") && !parsed.has("enrollment")) { "设备迁移缺少独立认证证明" }
        val profile = checkNotNull(runtimeProfile(next)) { "迁移包没有可运行的 v2 配置" }
        val existing = protected.get(STATE)
        check(existing == null || existing.contentEquals(next)) { "已安装的 v2 身份不能由迁移包覆盖" }
        if (existing == null) commitExact(next)
        return profile
    }

    @Synchronized
    fun current(): ByteArray? = protected.get(STATE)?.also(Loomcore::validateAndroidV2DeviceState)

    /** 生命周期与 runtime 必须来自同一个 protected blob；tombstone 仍保持 v2 latch。 */
    @Synchronized
    internal fun installed(): V2InstalledDeviceState? = protected.get(STATE)?.let { state ->
        Loomcore.validateAndroidV2DeviceState(state)
        val payload = JSONObject(state.decodeToString()).getJSONObject("envelope").getJSONObject("payload")
        val lifecycleState = payload.getString("state")
        val profile = runtimeProfile(state)
        check((lifecycleState == "active") == (profile != null)) {
            "[Android runtime] Device lifecycle 与 runtime 投影不一致"
        }
        V2InstalledDeviceState(
            encoded = state,
            lifecycleState = lifecycleState,
            nodeID = payload.getString("device_id"),
            generation = payload.getLong("device_generation"),
            runtimeProfile = profile,
        )
    }

    /** Verify a delivery without moving the durable current pointer. */
    @Synchronized
    internal fun preparePrivateDelivery(delivery: ByteArray): ByteArray {
        val current = checkNotNull(protected.get(STATE)) { "[Android config] v2 Device state 尚未安装" }
        return Loomcore.prepareAndroidV2PrivateDeviceConfigUpdate(current, delivery, keys.ensureIdentity())
            .also(Loomcore::validateAndroidV2DeviceState)
    }

    /** 配置与解封凭据先与对应 final view 组成候选，不直接推进 current。 */
    @Synchronized
    internal fun preparePrivateDeliveryWithArtifacts(
        delivery: ByteArray,
        configs: ByteArray,
        credentials: ByteArray,
    ): ByteArray {
        val current = checkNotNull(protected.get(STATE)) { "[Android config] v2 Device state 尚未安装" }
        return Loomcore.prepareAndroidV2PrivateDeviceConfigUpdateWithArtifacts(
            current,
            delivery,
            configs,
            credentials,
            keys.ensureIdentity(),
        ).also(Loomcore::validateAndroidV2DeviceState)
    }

    /**
     * Persist an active candidate without changing current. libbox structural
     * preflight happens before the candidate slot becomes eligible for service
     * activation; a crash therefore restarts from the unchanged current LKG.
     */
    @Synchronized
    internal fun stageRuntimeCandidate(next: ByteArray): ManagedProfile {
        Loomcore.validateAndroidV2DeviceState(next)
        val current = checkNotNull(protected.get(STATE)) { "[Android config] v2 Device state 尚未安装" }
        if (current.contentEquals(next)) {
            runCatching { protected.remove(CANDIDATE_STATE) }
            return checkNotNull(runtimeProfile(next)) { "[Android runtime] active state 缺 runtime" }
        }
        val profile = checkNotNull(runtimeProfile(next)) { "[Android runtime] tombstone 不能进入 runtime candidate" }
        protected.put(CANDIDATE_STATE, next)
        val replay = checkNotNull(protected.get(CANDIDATE_STATE)) { "[Android runtime] candidate 未持久保存" }
        check(replay.contentEquals(next)) { "[Android runtime] candidate 持久化回读不一致" }
        check(runtimeProfile(replay)?.recordID == profile.recordID) { "[Android runtime] candidate 回读不一致" }
        return profile
    }

    /** Move only the exact candidate that has already started successfully. */
    @Synchronized
    internal fun commitRuntimeCandidate(recordID: String): ManagedProfile {
        val candidate = checkNotNull(protected.get(CANDIDATE_STATE)) { "[Android runtime] candidate 已不存在" }
        val profile = checkNotNull(runtimeProfile(candidate)) { "[Android runtime] candidate 已变为 tombstone" }
        check(profile.recordID == recordID) { "[Android runtime] candidate 在启动期间发生变化" }
        protected.put(STATE, candidate)
        val replay = checkNotNull(protected.get(STATE)) { "[Android runtime] current 提交失败" }
        check(replay.contentEquals(candidate)) { "[Android runtime] current 提交回读不一致" }
        runCatching { protected.remove(CANDIDATE_STATE) }
        return profile
    }

    @Synchronized
    internal fun discardRuntimeCandidate(recordID: String): Boolean {
        val candidate = try {
            protected.get(CANDIDATE_STATE)
        } catch (_: Throwable) {
            runCatching { protected.remove(CANDIDATE_STATE) }
            return false
        } ?: return true
        val profile = runCatching { runtimeProfile(candidate) }.getOrNull()
        if (profile?.recordID != recordID) {
            if (profile == null) runCatching { protected.remove(CANDIDATE_STATE) }
            return false
        }
        protected.remove(CANDIDATE_STATE)
        return true
    }

    /** Tombstone has no process candidate to start, so its verified state is terminally committed. */
    @Synchronized
    internal fun commitTombstone(next: ByteArray) {
        Loomcore.validateAndroidV2DeviceState(next)
        val payload = JSONObject(next.decodeToString()).getJSONObject("envelope").getJSONObject("payload")
        check(payload.getString("state") != "active") { "[Android runtime] active state 不能走 tombstone commit" }
        commitExact(next)
        runCatching { protected.remove(CANDIDATE_STATE) }
    }

    /** Issue #14：hydrate 后秘密只作为同一 VpnService 的内存启动参数。 */
    @Synchronized
    fun runtimeProfile(): ManagedProfile? = protected.get(STATE)?.let(::runtimeProfile)

    private fun runtimeProfile(state: ByteArray): ManagedProfile? {
        Loomcore.validateAndroidV2DeviceState(state)
        val persisted = JSONObject(state.decodeToString())
        if (persisted.getJSONObject("envelope").getJSONObject("payload").getString("state") != "active") {
            return null
        }
        val localKey = wireGuard.existing() ?: ByteArray(0)
        val runtime = try {
            JSONObject(Loomcore.prepareAndroidV2RuntimeWithLocalKey(state, localKey).decodeToString())
        } finally { localKey.fill(0) }
        check(runtime.getInt("schema") == 1) { "v2 Android runtime projection schema 无效" }
        val headHash = runtime.getString("head_hash")
        val ca = runtime.optString("observation_ca").encodeToByteArray()
        val config = runtime.getString("sing_box_config")
        val profile = ManagedProfile(
            nodeID = runtime.getString("device_id"),
            snapshot = headHash,
            generation = runtime.getLong("device_generation"),
            config = bindRuntimeCA(config, ca),
            routePlan = runtime.optString("route_plan").takeIf(String::isNotBlank),
            caPEM = ca,
            recordID = "v2:$headHash",
            protocol = 2,
        )
        Libbox.checkConfig(profile.config)
        return profile
    }

    /** libbox 在进程文件系统预检；CA 独立按内容寻址，不能覆盖仍在使用的配置。 */
    private fun bindRuntimeCA(config: String, ca: ByteArray): String {
        if (!config.contains("\"certificate_path\"")) return config
        check(ca.isNotEmpty()) { "v2 配置引用了尚未认证安装的节点 CA" }
        val digest = MessageDigest.getInstance("SHA-256").digest(ca)
            .joinToString("") { "%02x".format(it) }
        val directory = runtimeDirectory.resolve("tls")
        check(directory.isDirectory || directory.mkdirs()) { "无法准备本机 CA 目录" }
        val file = directory.resolve("ca-$digest.crt")
        val atomic = AtomicFile(file)
        if (file.exists()) {
            check(atomic.readFully().contentEquals(ca)) { "已安装 CA 内容与摘要不符" }
        } else {
            val output = atomic.startWrite()
            try {
                output.write(ca)
                atomic.finishWrite(output)
            } catch (error: Throwable) {
                atomic.failWrite(output)
                throw error
            }
        }
        return Loomcore.relocateAndroidCA(config.encodeToByteArray(), file.absolutePath).decodeToString()
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
        private const val CANDIDATE_STATE = "device-v2-state-candidate"
    }
}
