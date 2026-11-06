package io.github.scisaga.loom.enrollment

import android.content.Context
import android.util.Log
import io.github.scisaga.loom.profiles.ProfileByteStore
import io.github.scisaga.loom.profiles.ProfileStorage
import io.github.scisaga.loom.security.EncryptedStore
import io.github.scisaga.loomcore.Loomcore
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest

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
    val resourceCacheIdentity: String = "",
    val executionDigest: String = "",
    val serviceCatalog: String = "[]",
    val policyCatalog: String = "[]",
    val serviceScopes: String = "[]",
) {
    internal val hasLocalNetwork: Boolean
        get() = JSONArray(routes).let { values ->
            (0 until values.length()).any { values.getJSONObject(it).getString("scope").startsWith("local_network:") }
        }
    internal val requiresUnderlayReadback: Boolean get() = hasWebsite || hasLocalNetwork
}

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
    private val replacePolicy: (ByteArray, ByteArray, ByteArray) -> ByteArray = Loomcore::replaceAndroidPolicySelection,
    private val acceptImportedView: (ByteArray, ByteArray) -> ByteArray = Loomcore::acceptAndroidCertifiedView,
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
    private val policyIdentityEvidenceKey = ProfileStorage.policyIdentityEvidence(profileId)
    private val policyPreferenceEvidenceKey = ProfileStorage.policyPreferenceEvidence(profileId)
    private val preferenceKey = ProfileStorage.routePreference(profileId)

    // Disposable reads only. Every use first re-reads the encrypted record and
    // compares all bytes, including report sequence and authentication floor.
    private var cachedBytes: ByteArray? = null
    private var cachedProfile: ManagedProfile? = null
    private var profileRead = false
    private var cachedDigest: String? = null
    private var cachedRisk: Boolean? = null

    private fun forgetRead() {
        cachedBytes?.fill(0)
        cachedBytes = null
        cachedProfile = null
        profileRead = false
        cachedDigest = null
        cachedRisk = null
    }

    // Explicit import supports ordinary current Views and the finite one-time
    // cutover. Startup and background refresh use only the current decoder.
    fun importCertifiedView(replacement: ByteArray): ManagedProfile = synchronized(stateLock) {
        check(protected.get(candidateKey) == null) { "存在待核对的旧材料，不能替换认证配置" }
        val original = checkNotNull(protected.get(stateKey)) { "设备身份不存在" }
        if (runCatching { validate(original) }.isFailure) {
            return@synchronized replacePolicySelection(replacement)
        }
        val next = acceptImportedView(original, replacement)
        if (protected.get(preferenceKey) != null) {
            preserveEvidence(preferenceKey, policyPreferenceEvidenceKey)
            protected.remove(preferenceKey)
            check(protected.get(preferenceKey) == null) { "旧偏好记录尚未删除" }
        }
        acceptCertified(next)
    }

    // Called only while explicit file import holds the VPN lifecycle lock.
    // The two evidence slots are immutable originals, never startup authorities.
    fun replacePolicySelection(replacement: ByteArray): ManagedProfile = synchronized(stateLock) {
        check(protected.get(candidateKey) == null) { "存在待核对的旧材料，不能替换认证配置" }
        val current = checkNotNull(protected.get(stateKey)) { "设备身份不存在" }
        val previousPreference = protected.get(preferenceKey) ?: ByteArray(0)
        val next = replacePolicy(current, replacement, previousPreference)
        validate(next)
        preserveEvidence(stateKey, policyIdentityEvidenceKey)
        if (protected.get(preferenceKey) != null) preserveEvidence(preferenceKey, policyPreferenceEvidenceKey)
        protected.put(stateKey, next)
        check(protected.get(stateKey)?.contentEquals(next) == true) { "认证配置持久化回读不一致" }
        protected.remove(preferenceKey)
        check(protected.get(preferenceKey) == null) { "旧偏好记录尚未删除" }
        forgetRead()
        checkNotNull(project(next)) { "认证配置已保存；没有可执行的 access 配置" }
    }

    private fun preserveEvidence(source: String, prefix: String) {
        val original = checkNotNull(protected.get(source))
        val hash = MessageDigest.getInstance("SHA-256")
        hash.update(prefix.encodeToByteArray())
        hash.update(0.toByte())
        val target = hash.digest(original).joinToString("") { "%02x".format(it) }
        protected.preserve(source, target)
        check(protected.get(target)?.contentEquals(original) == true) { "原始材料保全回读不一致" }
    }

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
        try {
            check(protected.get(candidateKey) == null) { "存在旧待激活材料；须先验证前向迁移，原始资料已保留" }
            check(protected.get(preferenceKey) == null) { "存在旧服务偏好，须经显式认证配置前向替换" }
            val body = protected.get(stateKey)
            if (body == null || cachedBytes?.contentEquals(body) != true) {
                forgetRead()
                if (body != null) {
                    validate(body)
                    cachedBytes = body.copyOf()
                }
            }
            body
        } catch (error: Throwable) {
            forgetRead()
            throw error
        }
    }

    fun saveState(body: ByteArray) = synchronized(stateLock) {
        val previous = state()
        validate(body)
        if (previous != null) checkAdvance(body, previous)
        protected.put(stateKey, body)
        check(protected.get(stateKey)?.contentEquals(body) == true) { "设备状态持久化回读不一致" }
        if (cachedBytes?.contentEquals(body) != true) {
            forgetRead()
            cachedBytes = body.copyOf()
        }
    }

    fun acceptCertified(body: ByteArray): ManagedProfile = synchronized(stateLock) {
        certifiedViewDigest(body)
        saveState(body)
        // Removing access can legitimately remove RuntimeProfile. Authentication
        // remains durable even when this host has nothing it can execute.
        checkNotNull(loadCurrent()) { "认证配置已保存；没有可执行的 access 配置" }
    }

    fun loadCurrent(): ManagedProfile? = synchronized(stateLock) {
        val body = state() ?: return@synchronized null
        if (!profileRead) {
            cachedProfile = project(body)
            profileRead = true
        }
        cachedProfile
    }

    // Caller holds the VPN lifecycle lock; network I/O must not run while
    // holding the encrypted identity store lock or during a UI projection.
    fun prepareRuntime(interfaceAddresses: ByteArray): ManagedProfile {
        val body = checkNotNull(state()) { "设备身份不存在" }
        val profile = decodeAndroidProfile(Loomcore.prepareAndroidDeviceProfile(body, interfaceAddresses))
        check(acceptedViewDigest() == profile.viewDigest) { "准备运行时认证配置已变化" }
        return profile
    }

    fun updateState(transform: (ByteArray) -> ByteArray): ByteArray = synchronized(stateLock) {
        val current = checkNotNull(state()) { "设备身份不存在" }
        transform(current).also(::saveState)
    }

    fun acceptedViewDigest(): String = synchronized(stateLock) {
        val body = state() ?: return@synchronized ""
        cachedDigest ?: authenticatedView(body).also { cachedDigest = it }
    }
    fun possiblePermissionRestoration(): Boolean = synchronized(stateLock) {
        val body = state() ?: return@synchronized false
        cachedRisk ?: restorationRisk(body).also { cachedRisk = it }
    }

    fun certifiedViewDigest(body: ByteArray): String {
        validate(body)
        return authenticatedView(body).also { check(it.isNotEmpty()) { "缺少完整认证配置" } }
    }

    fun clearUncompletedIdentity() = synchronized(stateLock) {
        check(acceptedViewDigest().isEmpty()) { "设备已有正式 LKG，不会删除身份" }
        protected.remove(stateKey)
        forgetRead()
    }

    fun clear() = synchronized(stateLock) {
        forgetRead()
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
        private val readers = LinkedHashMap<String, ManagedProfileStore>(4, 0.75f, true)

        fun get(context: Context, profileId: String): ManagedProfileStore = synchronized(stateLock) {
            readers[profileId] ?: ManagedProfileStore(context, profileId).also { store ->
                readers[profileId] = store
                if (readers.size > 4) {
                    val oldest = readers.entries.first()
                    oldest.value.forgetRead()
                    readers.remove(oldest.key)
                }
            }
        }
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
        serviceCatalog = root.getJSONArray("services").toString(),
        policyCatalog = root.getJSONArray("policies").toString(),
        serviceScopes = root.getJSONArray("scopes").toString(),
        resourceCacheIdentity = root.getString("resource_cache_identity"),
        executionDigest = root.getString("execution_digest"),
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
