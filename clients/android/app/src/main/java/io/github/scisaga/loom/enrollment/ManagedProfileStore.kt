package io.github.scisaga.loom.enrollment

import android.content.Context
import android.util.Base64
import io.github.scisaga.libbox.Libbox
import io.github.scisaga.loom.security.EncryptedStore
import io.github.scisaga.loom.security.TrustAnchor
import io.github.scisaga.loomcore.Loomcore
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.MessageDigest

data class ManagedProfile(
    val nodeID: String,
    val snapshot: String,
    val generation: Long,
    val config: String,
    val routePlan: String?,
    val certificatePEM: ByteArray,
    val caPEM: ByteArray,
    val reportEndpoint: String,
    internal val recordID: String,
)

internal fun validateAndroidRuntimeComponents(
    singBox: String,
    wireGuard: String,
    tailscale: String,
    agent: String,
    embeddedSingBox: String,
) {
    check(singBox.isNotBlank()) { "签名 manifest 未声明 Android sing-box 运行时" }
    check(wireGuard.isBlank() && tailscale.isBlank() && agent.isBlank()) {
        "签名 manifest 含 Android 不可执行的服务器组件"
    }
    check(singBox == embeddedSingBox) {
        "签名 manifest 要求 sing-box $singBox，但 APK 内置版本为 $embeddedSingBox"
    }
}

/** Keep certificate slots under the same root libbox uses for relative paths. */
internal fun libboxWorkingDirectory(filesDir: File): File = filesDir.resolve("libbox")

/**
 * Owns the durable transaction between a verified pull and VpnService. Every
 * profile retains the exact signed inputs, so process restart replays the full
 * current -> manifest -> node bundle chain instead of treating local
 * encryption as a replacement for platform signatures.
 */
internal class ManagedProfileStore(private val context: Context) {
    private val protected = EncryptedStore(context)

    @Synchronized
    fun loadCurrent(): ManagedProfile? = protected.get(CURRENT)?.let(::decodeAndPreflight)

    @Synchronized
    fun currentRecord(): ByteArray? = protected.get(CURRENT)

    @Synchronized
    fun loadPrevious(): ManagedProfile? = protected.get(PREVIOUS)?.let(::decodeAndPreflight)

    @Synchronized
    fun loadCandidate(): ManagedProfile? {
        val candidate = try {
            protected.get(CANDIDATE)
        } catch (error: Exception) {
            protected.remove(CANDIDATE)
            throw error
        } ?: return null
        return try {
            decodeAndPreflight(candidate)
        } catch (error: Exception) {
            // Candidate is not active. Isolate the exact bad bytes under the
            // same monitor so a concurrently staged replacement cannot be
            // deleted by an older failed read.
            val stillCurrent = protected.get(CANDIDATE)
            if (stillCurrent?.contentEquals(candidate) == true) protected.remove(CANDIDATE)
            throw error
        }
    }

    /**
     * Stage without touching the active pointer. VpnService commits this exact
     * record only after libbox starts and both end-to-end probes succeed.
     */
    @Synchronized
    fun stageCandidate(
        enrollment: ByteArray,
        currentJSON: ByteArray,
        manifestJSON: ByteArray,
        snapshotSignature: ByteArray,
        bundleJSON: ByteArray,
        releaseFloor: ByteArray,
    ): ManagedProfile {
        val record = JSONObject()
            .put("schema", RECORD_SCHEMA)
            .put("enrollment", JSONObject(enrollment.decodeToString()))
            .put(
                "artifacts",
                JSONObject()
                    .put("current_json", currentJSON.decodeToString())
                    .put("manifest_json", manifestJSON.decodeToString())
                    .put("snapshot_signature", Base64.encodeToString(snapshotSignature, Base64.NO_WRAP))
                    .put("bundle_json", bundleJSON.decodeToString())
                    .put("release_floor", JSONObject(releaseFloor.decodeToString())),
            )
            .toString()
            .encodeToByteArray()
        decodeAndPreflight(record)
        protected.put(CANDIDATE, record)
        val replay = checkNotNull(protected.get(CANDIDATE)) { "候选配置未能持久保存" }
        check(replay.contentEquals(record)) { "候选配置持久化回读不一致" }
        return decodeAndPreflight(replay)
    }

    /** Commit only the candidate that VpnService proved healthy. */
    @Synchronized
    fun commitCandidate(recordID: String): ManagedProfile {
        val candidate = checkNotNull(protected.get(CANDIDATE)) { "待激活候选已不存在" }
        check(sha256Hex(candidate) == recordID) { "待激活候选在运行验证期间发生变化" }
        val candidateProfile = decodeAndPreflight(candidate)
        val current = protected.get(CURRENT)
        if (current == null || !current.contentEquals(candidate)) {
            current?.let { protected.put(PREVIOUS, it) }
            protected.put(CURRENT, candidate)
            val replay = checkNotNull(protected.get(CURRENT)) { "当前配置提交失败" }
            check(replay.contentEquals(candidate)) { "当前配置提交回读不一致" }
            decodeAndPreflight(replay)
        }
        protected.remove(CANDIDATE)
        return candidateProfile
    }

    @Synchronized
    fun discardCandidate(recordID: String): Boolean {
        val candidate = protected.get(CANDIDATE) ?: return true
        if (sha256Hex(candidate) != recordID) return false
        protected.remove(CANDIDATE)
        return true
    }

    @Synchronized
    fun restorePrevious(): ManagedProfile? {
        val previous = protected.get(PREVIOUS) ?: return null
        val profile = decodeAndPreflight(previous)
        protected.put(CURRENT, previous)
        return profile
    }

    @Synchronized
    fun putPending(body: ByteArray) = protected.put(PENDING, body)

    @Synchronized
    fun pending(): ByteArray? = protected.get(PENDING)

    @Synchronized
    fun clearPending() = protected.remove(PENDING)

    @Synchronized
    fun putReady(body: ByteArray) = protected.put(READY, body)

    @Synchronized
    fun ready(): ByteArray? = protected.get(READY)

    @Synchronized
    fun clearReady() = protected.remove(READY)

    @Synchronized
    fun putFloor(body: ByteArray) = protected.put(FLOOR, body)

    @Synchronized
    fun floor(): ByteArray = protected.get(FLOOR) ?: ByteArray(0)

    private fun decodeAndPreflight(body: ByteArray): ManagedProfile {
        val record = JSONObject(body.decodeToString())
        check(record.getInt("schema") == RECORD_SCHEMA) { "本机配置记录 schema 无效" }
        val enrollment = record.getJSONObject("enrollment")
        val response = enrollment.getJSONObject("response")
        check(response.getString("configuration") == "ready") { "本机配置没有 ready bootstrap" }
        val bootstrap = response.getJSONObject("bootstrap")
        val nodeID = bootstrap.getString("node_id")
        val artifacts = record.getJSONObject("artifacts")
        val currentJSON = artifacts.getString("current_json").encodeToByteArray()
        val manifestJSON = artifacts.getString("manifest_json").encodeToByteArray()
        val signature = decodeCanonicalBase64(artifacts.getString("snapshot_signature"))
        val bundleJSON = artifacts.getString("bundle_json").encodeToByteArray()
        // Keep the authenticated selection coordinate in the record for audit,
        // while replay is checked against the separately latched global floor.
        artifacts.getJSONObject("release_floor")
        val releaseFloor = checkNotNull(protected.get(FLOOR)) { "本机 release floor 缺失" }
        val platformKey = TrustAnchor.platformPublicKeyForBootstrap(bootstrap.getString("platform_public_key"))
        val verifiedPull = Loomcore.verifyCachedPull(
            currentJSON,
            manifestJSON,
            signature,
            bundleJSON,
            platformKey,
            nodeID,
            releaseFloor,
        )
        val pull = JSONObject(verifiedPull.decodeToString())
        val components = pull.getJSONObject("components")
        validateAndroidRuntimeComponents(
            singBox = components.optString("sing_box"),
            wireGuard = components.optString("wireguard"),
            tailscale = components.optString("tailscale"),
            agent = components.optString("agent"),
            embeddedSingBox = Libbox.version(),
        )
        val canonicalBundle = pull.getString("canonical_bundle").encodeToByteArray()
        val secrets = bootstrap.getString("secrets_env").encodeToByteArray()
        val ca = bootstrap.getString("ca_cert_pem").encodeToByteArray()
        val caRelativePath = "tls/ca-${sha256Hex(ca)}.crt"
        installImmutableCA(caRelativePath, ca)
        val prepared = JSONObject(Loomcore.prepareAndroidRuntime(canonicalBundle, secrets).decodeToString())
        check(prepared.getInt("schema") == 1) { "Android runtime 准备结果 schema 无效" }
        val routePlan = prepared.optString("route_plan").takeIf(String::isNotBlank)
        val config = Loomcore.relocateAndroidCA(
            prepared.getString("sing_box_config").encodeToByteArray(),
            caRelativePath,
        ).decodeToString()
        Libbox.checkConfig(config)
        return ManagedProfile(
            nodeID = nodeID,
            snapshot = pull.getString("snapshot"),
            generation = pull.getLong("generation"),
            config = config,
            routePlan = routePlan,
            certificatePEM = bootstrap.getString("node_cert_pem").encodeToByteArray(),
            caPEM = ca,
            reportEndpoint = enrollment.getString("report_endpoint"),
            recordID = sha256Hex(body),
        )
    }

    /**
     * Immutable content-addressed CA slots let a candidate be checked while an
     * existing tunnel continues to use its own CA path.
     */
    private fun installImmutableCA(relativePath: String, body: ByteArray) {
        val workingDirectory = libboxWorkingDirectory(context.filesDir)
        val directory = workingDirectory.resolve("tls").apply { mkdirs() }
        val target = workingDirectory.resolve(relativePath)
        check(target.parentFile == directory) { "CA 槽路径越界" }
        if (target.isFile && target.readBytes().contentEquals(body)) return
        val temporary = File.createTempFile(".ca-slot-", ".tmp", directory)
        try {
            FileOutputStream(temporary).use {
                it.write(body)
                it.fd.sync()
            }
            Files.move(
                temporary.toPath(),
                target.toPath(),
                StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING,
            )
        } finally {
            if (temporary.exists()) temporary.delete()
        }
        check(target.readBytes().contentEquals(body)) { "CA 槽写入回读不一致" }
    }

    private fun decodeCanonicalBase64(value: String): ByteArray {
        val decoded = Base64.decode(value, Base64.NO_WRAP)
        check(Base64.encodeToString(decoded, Base64.NO_WRAP) == value) { "受保护记录含非规范 base64" }
        return decoded
    }

    private fun sha256Hex(body: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(body).joinToString("") { "%02x".format(it) }

    companion object {
        private const val RECORD_SCHEMA = 2
        private const val CURRENT = "managed-current"
        private const val PREVIOUS = "managed-previous"
        private const val CANDIDATE = "managed-candidate"
        private const val PENDING = "join-pending"
        private const val READY = "join-ready"
        private const val FLOOR = "release-floor"
    }
}
