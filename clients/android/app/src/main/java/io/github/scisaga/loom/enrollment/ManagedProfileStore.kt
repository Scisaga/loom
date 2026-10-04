package io.github.scisaga.loom.enrollment

import android.content.Context
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
) {
    constructor(context: Context, profileId: String) : this(
        object : ProfileByteStore {
            private val encrypted = EncryptedStore(context.applicationContext)
            override fun get(key: String) = encrypted.get(key)
            override fun put(key: String, value: ByteArray) = encrypted.put(key, value)
            override fun remove(key: String) = encrypted.remove(key)
        },
        profileId,
        Loomcore::validateAndroidDeviceState,
        Loomcore::checkAndroidDeviceStateAdvance,
        { body -> JSONObject(Loomcore.androidEnrollmentState(body).decodeToString()).getString("view_digest") },
        { body ->
            val status = JSONObject(Loomcore.androidEnrollmentState(body).decodeToString())
            if (status.getBoolean("ready")) decodeManagedProfile(body) else null
        },
    )

    private val stateKey = ProfileStorage.state(profileId)
    private val candidateKey = ProfileStorage.candidate(profileId)

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

    fun updateState(transform: (ByteArray) -> ByteArray): ByteArray = synchronized(stateLock) {
        val current = checkNotNull(state()) { "设备身份不存在" }
        transform(current).also(::saveState)
    }

    fun acceptedViewDigest(): String = synchronized(stateLock) { state()?.let(authenticatedView).orEmpty() }

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
    val root = JSONObject(Loomcore.androidDeviceProfile(body).decodeToString())
    check(root.getInt("schema") == 3) { "运行投影 schema 无效" }
    val config = root.getString("config")
    return ManagedProfile(
        nodeID = root.getString("node_id"),
        deviceName = root.getString("name"),
        viewDigest = root.getString("view_digest"),
        factFrontier = root.getJSONArray("fact_frontier").toString(),
        config = config,
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
