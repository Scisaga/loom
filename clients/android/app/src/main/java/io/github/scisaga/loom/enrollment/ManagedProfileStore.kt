package io.github.scisaga.loom.enrollment

import android.content.Context
import android.util.Log
import io.github.scisaga.loom.profiles.ProfileByteStore
import io.github.scisaga.loom.profiles.ProfileStorage
import io.github.scisaga.loom.security.EncryptedStore
import io.github.scisaga.loomcore.Loomcore
import org.json.JSONObject
import java.io.File

internal fun libboxWorkingDirectory(filesDir: File): File = filesDir.resolve("libbox")

data class ManagedProfile(
    val nodeID: String,
    val deviceName: String,
    val viewDigest: String,
    val factFrontier: String,
    val config: String,
    val routes: String,
    internal val recordID: String,
    val dns: List<String> = emptyList(),
    val businessProbeTargets: List<ServiceProbeTargets> = emptyList(),
    internal val hasWebsite: Boolean = false,
    val possiblePermissionRestoration: Boolean = false,
)

data class ServiceProbeTargets(val serviceID: String, val targets: List<String>)

/** One protected record owns identity, authenticated LKG and its anti-rollback floor. */
internal class ManagedProfileStore internal constructor(
    private val protected: ProfileByteStore,
    profileId: String,
    private val validate: (ByteArray) -> Unit,
    private val checkAdvance: (ByteArray, ByteArray) -> Unit,
    private val authenticatedView: (ByteArray) -> String,
    private val project: (ByteArray) -> ManagedProfile?,
    private val restorationRisk: (ByteArray) -> Boolean = { false },
    private val replaceTransport: (ByteArray, ByteArray) -> ByteArray = { original, replacement ->
        Loomcore.replaceAndroidTransport(original, replacement)
    },
) {
    constructor(context: Context, profileId: String) : this(
        object : ProfileByteStore {
            private val encrypted = EncryptedStore(context.applicationContext)
            override fun get(key: String) = encrypted.get(key)
            override fun put(key: String, value: ByteArray) = encrypted.put(key, value)
            override fun remove(key: String) = encrypted.remove(key)
            override fun preserve(source: String, target: String) = encrypted.preserve(source, target)
        },
        profileId,
        Loomcore::validateAndroidDeviceState,
        { next, previous ->
            Loomcore.checkAndroidDeviceStateAdvance(next, previous)
            val review = JSONObject(Loomcore.androidMemberReview(next, previous).decodeToString())
            if (review.getBoolean("possible_permission_restoration")) {
                Log.w("Loom", "成员变更待写入，可能复权；可见差异并非完整审计：$review")
            }
        },
        { body -> JSONObject(Loomcore.androidEnrollmentState(body).decodeToString()).getString("view_digest") },
        { body ->
            val status = JSONObject(Loomcore.androidEnrollmentState(body).decodeToString())
            if (status.getBoolean("ready")) decodeManagedProfile(body) else null
        },
        { body -> JSONObject(Loomcore.androidEnrollmentState(body).decodeToString()).getBoolean("possible_permission_restoration") },
    )

    private val stateKey = ProfileStorage.state(profileId)
    private val candidateKey = ProfileStorage.candidate(profileId)
    private val transportEvidenceKey = ProfileStorage.transportEvidence(profileId)

    // Only explicit certified-file import reaches this path. Ordinary state(),
    // background sync and startup continue to reject the historical runtime.
    fun replaceTransport(replacement: ByteArray): ManagedProfile = synchronized(stateLock) {
        check(protected.get(candidateKey) == null) { "存在待核对的旧材料，不能替换认证配置" }
        val original = checkNotNull(protected.get(stateKey)) { "设备身份不存在" }
        val next = replaceTransport(original, replacement)
        validate(next)
        protected.preserve(stateKey, transportEvidenceKey)
        check(protected.get(transportEvidenceKey)?.contentEquals(original) == true) { "原认证材料保全回读不一致" }
        protected.put(stateKey, next)
        check(protected.get(stateKey)?.contentEquals(next) == true) { "认证配置持久化回读不一致" }
        checkNotNull(project(next)) { "认证配置已保存；没有可执行的 access 配置" }
    }

    fun state(): ByteArray? = synchronized(stateLock) {
        // Preserve pre-change pending bytes as evidence. They cannot silently become a
        // second LKG or be discarded when they may contain a later revocation floor.
        check(protected.get(candidateKey) == null) { "存在旧待激活材料；须先验证前向迁移，原始资料已保留" }
        protected.get(stateKey)?.also(validate)
    }

    fun saveState(body: ByteArray) = synchronized(stateLock) {
        val previous = state()
        validate(body)
        if (previous != null) checkAdvance(body, previous)
        protected.put(stateKey, body)
        check(protected.get(stateKey)?.contentEquals(body) == true) { "设备状态持久化回读不一致" }
    }

    fun acceptCertified(body: ByteArray): ManagedProfile = synchronized(stateLock) {
        certifiedViewDigest(body)
        saveState(body)
        // Removing access can legitimately remove RuntimeProfile. Authentication
        // remains durable even when this host has nothing it can execute.
        checkNotNull(project(body)) { "认证配置已保存；没有可执行的 access 配置" }
    }

    fun loadCurrent(): ManagedProfile? = synchronized(stateLock) { state()?.let(project) }

    // Caller holds the VPN lifecycle lock; network I/O must not run while
    // holding the encrypted identity store lock or during a UI projection.
    fun prepareRuntime(): ManagedProfile {
        val body = checkNotNull(state()) { "设备身份不存在" }
        val profile = decodeAndroidProfile(Loomcore.prepareAndroidDeviceProfile(body))
        check(acceptedViewDigest() == profile.viewDigest) { "准备运行时认证配置已变化" }
        return profile
    }

    fun updateState(transform: (ByteArray) -> ByteArray): ByteArray = synchronized(stateLock) {
        val current = checkNotNull(state()) { "设备身份不存在" }
        transform(current).also(::saveState)
    }

    fun acceptedViewDigest(): String = synchronized(stateLock) { state()?.let(authenticatedView).orEmpty() }
    fun possiblePermissionRestoration(): Boolean = synchronized(stateLock) { state()?.let(restorationRisk) ?: false }

    fun certifiedViewDigest(body: ByteArray): String {
        validate(body)
        return authenticatedView(body).also { check(it.isNotEmpty()) { "缺少完整认证配置" } }
    }

    fun clearUncompletedIdentity() = synchronized(stateLock) {
        check(acceptedViewDigest().isEmpty()) { "设备已有正式 LKG，不会删除身份" }
        protected.remove(stateKey)
    }

    fun clear() = synchronized(stateLock) {
        protected.remove(candidateKey)
        protected.remove(stateKey)
    }

    fun decodeProfile(body: ByteArray): ManagedProfile {
        validate(body)
        return checkNotNull(project(body)) { "缺少完整认证配置" }
    }

    companion object {
        // All handles address the same encrypted records. Instance locks cannot
        // prevent a report reservation from being overwritten by an older refresh.
        private val stateLock = Any()
    }
}

private fun decodeManagedProfile(body: ByteArray): ManagedProfile {
    return decodeAndroidProfile(Loomcore.androidDeviceProfile(body))
}

private fun decodeAndroidProfile(body: ByteArray): ManagedProfile {
    val root = JSONObject(body.decodeToString())
    check(root.getInt("schema") == 3) { "运行投影 schema 无效" }
    val config = root.getString("config")
    return ManagedProfile(
        nodeID = root.getString("node_id"),
        deviceName = root.getString("name"),
        viewDigest = root.getString("view_digest"),
        factFrontier = root.getJSONArray("fact_frontier").toString(),
        config = config,
        hasWebsite = root.getBoolean("has_website"),
        possiblePermissionRestoration = root.getBoolean("possible_permission_restoration"),
        routes = root.getJSONArray("routes").toString(),
        recordID = root.getString("record_id"),
        dns = root.optJSONArray("dns")?.let { values -> (0 until values.length()).map(values::getString) }.orEmpty(),
        businessProbeTargets = root.optJSONArray("business_probe_targets")
            ?.let { values -> (0 until values.length()).map { index ->
                val service = values.getJSONObject(index)
                val targets = service.getJSONArray("targets")
                ServiceProbeTargets(service.getString("service_id"), (0 until targets.length()).map(targets::getString))
            } }.orEmpty(),
    )
}
