package io.github.scisaga.loom.enrollment

import io.github.scisaga.loom.profiles.ProfileContext
import android.content.Context
import io.github.scisaga.loom.BuildConfig
import io.github.scisaga.loom.security.DeviceKeyStore
import io.github.scisaga.loom.security.EncryptedStore
import io.github.scisaga.loomcore.Loomcore
import org.json.JSONArray
import org.json.JSONObject
import java.util.Base64

internal data class V2ConfigurationRefresh(
    val profile: ManagedProfile?,
    val staged: Boolean,
    val requiresRuntimeActivation: Boolean,
)

internal data class V2ReportAccepted(val sequence: Long, val response: V2ReportResponse)

internal fun requiresV2RuntimeActivation(current: ManagedProfile, candidate: ManagedProfile): Boolean {
    check(current.protocol == 2 && candidate.protocol == 2) { "v2 runtime 比较拒绝其他协议" }
    check(current.nodeID == candidate.nodeID) { "v2 runtime candidate 属于另一 Device" }
    return current.config != candidate.config
}

internal fun requiresV2RouteApplication(current: ManagedProfile, candidate: ManagedProfile): Boolean {
    check(current.protocol == 2 && candidate.protocol == 2) { "v2 route 比较拒绝其他协议" }
    check(current.nodeID == candidate.nodeID) { "v2 route candidate 属于另一 Device" }
    return current.routePlan != candidate.routePlan
}

/**
 * pending signed envelope 在网络发送前进入 Keystore-wrapped 原子 journal。
 * HTTP 响应丢失或进程死亡后只能重放 exact bytes；收到有效回执后才推进 sequence。
 */
internal class V2DeviceReporter(
    context: Context,
    private val stateStore: V2DeviceStateStore = V2DeviceStateStore(context.applicationContext),
    private val keys: DeviceKeyStore = DeviceKeyStore(ProfileContext.keySuffix(context)),
    private val client: V2PrivateControlClient = V2PrivateControlClient(keys),
) {
    private val protected = EncryptedStore(context.applicationContext)
    private val mirrorFetcher = V2MirrorFetcher(context.applicationContext)
    private val crypto = V2EnrollmentCrypto(keys)

    @Synchronized
    fun hasPending(deviceID: String): Boolean = loadJournal(deviceID)?.pending != null

    /** 配置响应只在共享 verifier 完成 QC/Merkle/floor 检查后进入 protected LKG。 */
    fun refreshConfiguration(): V2ConfigurationRefresh {
        val now = wireTime()
        val plans = stateStore.privateControlPlans("device_config", now)
        val delivery = client.getFirst(plans)
        val state = checkNotNull(stateStore.current()) { "[Android config] v2 Device state 尚未安装" }
        val currentProfile = checkNotNull(stateStore.runtimeProfile()) { "[Android config] active state 缺 runtime" }
        val fetchPlan = Loomcore.prepareAndroidV2PrivateDeviceConfigFetchPlan(
            state,
            delivery,
            keys.ensureIdentity(),
        )
        val plan = JSONObject(fetchPlan.decodeToString())
        val configState = plan.getString("state")
        val next = when (configState) {
            "unchanged" -> stateStore.preparePrivateDelivery(delivery)
            "tombstone" -> stateStore.preparePrivateDeliveryWithArtifacts(
                delivery, ByteArray(0), ByteArray(0),
            )
            "active" -> {
                val configs = if (plan.getBoolean("config_changed")) {
                    mirrorFetcher.fetchCompletionConfigs(fetchPlan)
                } else {
                    ByteArray(0)
                }
                val credentials = if (plan.getBoolean("secrets_changed")) {
                    unsealRotatedCredentials(plan, state)
                } else {
                    ByteArray(0)
                }
                stateStore.preparePrivateDeliveryWithArtifacts(delivery, configs, credentials)
            }
            else -> error("[Android config] fetch plan state 无效")
        }
        if (configState == "tombstone") {
            stateStore.commitTombstone(next)
            return V2ConfigurationRefresh(profile = null, staged = false, requiresRuntimeActivation = false)
        }
        val candidate = stateStore.stageRuntimeCandidate(next)
        if (candidate.recordID == currentProfile.recordID) {
            return V2ConfigurationRefresh(currentProfile, staged = false, requiresRuntimeActivation = false)
        }
        return V2ConfigurationRefresh(
            candidate,
            staged = true,
            requiresRuntimeActivation = requiresV2RuntimeActivation(currentProfile, candidate),
        )
    }

    fun commitConfigurationCandidate(profile: ManagedProfile): ManagedProfile {
        check(profile.protocol == 2)
        return stateStore.commitRuntimeCandidate(profile.recordID)
    }

    fun discardConfigurationCandidate(profile: ManagedProfile): Boolean {
        check(profile.protocol == 2)
        return stateStore.discardRuntimeCandidate(profile.recordID)
    }

    private fun unsealRotatedCredentials(plan: JSONObject, state: ByteArray): ByteArray {
        val refs = plan.getJSONArray("secret_refs")
        val envelopes = plan.getJSONArray("secret_envelopes")
        check(refs.length() == envelopes.length()) { "[Android config] secret envelope 未 exact 覆盖 refs" }
        val deviceID = JSONObject(state.decodeToString())
            .getJSONObject("envelope").getJSONObject("payload").getString("device_id")
        val installed = JSONArray()
        for (index in 0 until refs.length()) {
            val ref = Loomcore.canonicalizeV2(
                refs.getJSONObject(index).toString().encodeToByteArray(),
            )
            val envelope = Loomcore.canonicalizeV2(
                envelopes.getJSONObject(index).toString().encodeToByteArray(),
            )
            installed.put(JSONObject(crypto.unsealInstalledSecret(ref, envelope, deviceID).decodeToString()))
        }
        return Loomcore.canonicalizeV2(installed.toString().encodeToByteArray())
    }

    @Synchronized
    fun sendHealth(profile: ManagedProfile, healthy: Boolean): V2ReportAccepted {
        check(profile.protocol == 2) { "[Android report] v2 reporter 拒绝 v1 profile" }
        val state = checkNotNull(stateStore.current()) { "[Android report] v2 Device state 尚未安装" }
        val now = wireTime()
        var journal = loadJournal(profile.nodeID) ?: ReportJournal(
            deviceID = profile.nodeID,
            lastAcceptedSequence = 0,
            lastAcceptedEnvelopeHash = null,
            nextSequence = 1,
            pending = null,
        )
        journal.pending?.let { pending ->
            val retired = Loomcore.retireAndroidV2DeviceReport(state, keys.ensureIdentity(), pending, now)
            if (retired.isNotEmpty()) {
                check(journal.nextSequence < Long.MAX_VALUE) { "[Android report] sequence 已耗尽" }
                journal = journal.copy(retired = retired, nextSequence = journal.nextSequence + 1, pending = null)
                persistJournal(journal)
            }
        }
        val envelope = journal.pending?.also {
            Loomcore.validateAndroidV2DeviceReport(state, keys.ensureIdentity(), it, now)
        } ?: prepareEnvelope(state, journal.nextSequence, now, healthy).also { pending ->
            journal = journal.copy(pending = pending)
            persistJournal(journal)
        }

        val plans = stateStore.privateControlPlans("device_report", now)
        val response = client.postFirst(plans, envelope)

        // 服务端可能已经提交而本机尚未落盘；回读并比较 pending，禁止并发发送
        // 用同一 sequence 的另一份正文覆盖它。
        val durable = checkNotNull(loadJournal(profile.nodeID)) { "[Android report] journal 在发送期间消失" }
        check(durable.nextSequence == journal.nextSequence && durable.pending?.contentEquals(envelope) == true) {
            "[Android report] journal 在发送期间发生分叉"
        }
        val envelopeHash = Loomcore.hashCanonicalV2(REPORT_ENVELOPE_HASH_DOMAIN, envelope)
        check(durable.nextSequence < Long.MAX_VALUE) { "[Android report] sequence 已耗尽" }
        persistJournal(
            durable.copy(
                lastAcceptedSequence = durable.nextSequence,
                lastAcceptedEnvelopeHash = envelopeHash,
                nextSequence = durable.nextSequence + 1,
                pending = null,
            ),
        )
        return V2ReportAccepted(durable.nextSequence, response)
    }

    private fun prepareEnvelope(state: ByteArray, sequence: Long, now: String, healthy: Boolean): ByteArray {
        val payload = Loomcore.canonicalizeV2(
            JSONObject()
                .put("healthy", healthy)
                .put("version", "android-${BuildConfig.VERSION_NAME}")
                .toString()
                .encodeToByteArray(),
        )
        val identity = keys.ensureIdentity()
        val draft = Loomcore.prepareAndroidV2DeviceReportDraft(state, identity, "", sequence, now, payload)
        val signingMessage = decodeCanonicalURL(JSONObject(draft.decodeToString()).getString("signing_message"))
        val signature = keys.signCanonicalV2(signingMessage)
        return Loomcore.assembleAndroidV2DeviceReport(state, identity, draft, signature, now)
    }

    private fun loadJournal(deviceID: String): ReportJournal? {
        val raw = protected.get(JOURNAL) ?: return null
        check(raw.contentEquals(Loomcore.canonicalizeV2(raw))) { "[Android report] journal 不是 canonical JSON" }
        val root = JSONObject(raw.decodeToString())
        val allowed = setOf(
            "schema", "device_id", "last_accepted_sequence", "last_accepted_envelope_hash",
            "next_sequence", "pending", "retired",
        )
        check(root.keys().asSequence().toSet().let { it.isNotEmpty() && it.all(allowed::contains) }) {
            "[Android report] journal 含未知字段"
        }
        check(root.getInt("schema") == 1 && root.getString("device_id") == deviceID) {
            "[Android report] journal 属于另一 Device"
        }
        val last = root.getLong("last_accepted_sequence")
        val next = root.getLong("next_sequence")
        val retired = root.optJSONObject("retired")?.let {
            Loomcore.canonicalizeV2(it.toString().encodeToByteArray())
        }
        val retiredSequence = retired?.let { value ->
            JSONObject(value.decodeToString()).getJSONObject("envelope").getJSONObject("body").let { body ->
                check(body.getString("device_id") == deviceID) { "[Android report] 退休记录属于另一 Device" }
                body.getLong("report_sequence").also { check(it > 0) }
            }
        } ?: 0
        check(last in 0 until Long.MAX_VALUE && maxOf(last, retiredSequence) < Long.MAX_VALUE && next == maxOf(last, retiredSequence) + 1) { "[Android report] journal sequence 不连续" }
        val lastHash = root.optString("last_accepted_envelope_hash").takeIf(String::isNotBlank)
        check((last == 0L) == (lastHash == null)) { "[Android report] journal last hash 状态无效" }
        lastHash?.let { check(it.startsWith("sha256:") && it.length == 71) { "[Android report] journal hash 无效" } }
        val pending = root.optString("pending").takeIf(String::isNotBlank)?.let(::decodeCanonicalURL)
        return ReportJournal(deviceID, last, lastHash, next, pending, retired)
    }

    private fun persistJournal(journal: ReportJournal) {
        val retiredSequence = journal.retired?.let {
            JSONObject(it.decodeToString()).getJSONObject("envelope").getJSONObject("body").getLong("report_sequence")
        } ?: 0
        check(journal.nextSequence == maxOf(journal.lastAcceptedSequence, retiredSequence) + 1)
        val value = JSONObject()
            .put("schema", 1)
            .put("device_id", journal.deviceID)
            .put("last_accepted_sequence", journal.lastAcceptedSequence)
            .put("next_sequence", journal.nextSequence)
        journal.lastAcceptedEnvelopeHash?.let { value.put("last_accepted_envelope_hash", it) }
        journal.retired?.let { value.put("retired", JSONObject(it.decodeToString())) }
        journal.pending?.let { value.put("pending", Base64.getUrlEncoder().withoutPadding().encodeToString(it)) }
        val canonical = Loomcore.canonicalizeV2(value.toString().encodeToByteArray())
        protected.put(JOURNAL, canonical)
        check(protected.get(JOURNAL)?.contentEquals(canonical) == true) { "[Android report] journal 持久化回读不一致" }
    }

    private fun decodeCanonicalURL(value: String): ByteArray {
        check(value.isNotBlank() && '=' !in value && !value.any(Char::isWhitespace)) { "[Android report] base64url 编码不规范" }
        val decoded = Base64.getUrlDecoder().decode(value)
        check(Base64.getUrlEncoder().withoutPadding().encodeToString(decoded) == value) { "[Android report] base64url 编码不规范" }
        return decoded
    }

    private data class ReportJournal(
        val deviceID: String,
        val lastAcceptedSequence: Long,
        val lastAcceptedEnvelopeHash: String?,
        val nextSequence: Long,
        val pending: ByteArray?,
        val retired: ByteArray? = null,
    )

    companion object {
        private const val JOURNAL = "device-v2-report-journal"
        private const val REPORT_ENVELOPE_HASH_DOMAIN = "loom-android-device-report-envelope-v1"
    }
}
