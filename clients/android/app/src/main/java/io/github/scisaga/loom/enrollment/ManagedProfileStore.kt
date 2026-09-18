package io.github.scisaga.loom.enrollment

import android.content.Context
import io.github.scisaga.libbox.Libbox
import io.github.scisaga.loom.security.EncryptedStore
import io.github.scisaga.loomcore.Loomcore
import org.json.JSONObject
import java.io.File

internal fun libboxWorkingDirectory(filesDir: File): File = filesDir.resolve("libbox")

data class ManagedProfile(
    val nodeID: String,
    val snapshot: String,
    val generation: Long,
    val viewDigest: String,
    val config: String,
    val routes: String,
    internal val recordID: String,
)

/** Stores one protected identity/LKG and at most one certified candidate. */
internal class ManagedProfileStore(context: Context) {
    private val protected = EncryptedStore(context)

    @Synchronized
    fun state(): ByteArray? = protected.get(DEVICE_STATE)?.also(Loomcore::validateAndroidDeviceState)

    @Synchronized
    fun saveState(body: ByteArray) {
        Loomcore.validateAndroidDeviceState(body)
        protected.put(DEVICE_STATE, body)
        check(protected.get(DEVICE_STATE)?.contentEquals(body) == true) { "设备状态持久化回读不一致" }
    }

    @Synchronized
    fun loadCurrent(): ManagedProfile? = state()?.let(::decodeProfileOrNull)

    @Synchronized
    fun loadCandidate(): ManagedProfile? = protected.get(CANDIDATE)?.let(::decodeProfile)

    @Synchronized
    fun stageCandidate(body: ByteArray): ManagedProfile {
        Loomcore.validateAndroidDeviceState(body)
        val profile = decodeProfile(body)
        protected.put(CANDIDATE, body)
        check(protected.get(CANDIDATE)?.contentEquals(body) == true) { "候选 LKG 持久化回读不一致" }
        return profile
    }

    @Synchronized
    fun commitCandidate(recordID: String): ManagedProfile {
        val body = checkNotNull(protected.get(CANDIDATE)) { "待激活候选已不存在" }
        val profile = decodeProfile(body)
        check(profile.recordID == recordID) { "待激活候选在验证期间发生变化" }
        protected.put(DEVICE_STATE, body)
        check(protected.get(DEVICE_STATE)?.contentEquals(body) == true) { "LKG 提交回读不一致" }
        protected.remove(CANDIDATE)
        return profile
    }

    @Synchronized
    fun discardCandidate(recordID: String): Boolean {
        val body = protected.get(CANDIDATE) ?: return true
        if (decodeProfile(body).recordID != recordID) return false
        protected.remove(CANDIDATE)
        return true
    }

    @Synchronized
    fun clearUncompletedIdentity() {
        check(loadCurrent() == null) { "设备已有正式 LKG，不会删除身份" }
        protected.remove(CANDIDATE)
        protected.remove(DEVICE_STATE)
    }

    fun decodeProfile(body: ByteArray): ManagedProfile {
        val root = JSONObject(Loomcore.androidDeviceProfile(body).decodeToString())
        check(root.getInt("schema") == 1) { "运行投影 schema 无效" }
        val config = root.getString("config")
        Libbox.checkConfig(config)
        return ManagedProfile(
            nodeID = root.getString("node_id"),
            snapshot = root.getString("head"),
            generation = root.getLong("generation"),
            viewDigest = root.getString("view_digest"),
            config = config,
            routes = root.getJSONArray("routes").toString(),
            recordID = root.getString("record_id"),
        )
    }

    private fun decodeProfileOrNull(body: ByteArray): ManagedProfile? = runCatching { decodeProfile(body) }.getOrNull()

    companion object {
        private const val DEVICE_STATE = "device-state-v2"
        private const val CANDIDATE = "device-candidate-v2"
    }
}
