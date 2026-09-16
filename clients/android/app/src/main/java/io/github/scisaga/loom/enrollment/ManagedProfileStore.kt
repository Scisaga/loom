package io.github.scisaga.loom.enrollment

import android.content.Context
import io.github.scisaga.loom.security.EncryptedStore
import io.github.scisaga.loom.security.TrustAnchor
import io.github.scisaga.loomcore.Loomcore
import org.json.JSONObject
import java.io.File
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory

data class ManagedProfile(
    val nodeID: String,
    val snapshot: String,
    val generation: Long,
    val config: String,
    val routePlan: String?,
    val caPEM: ByteArray,
    internal val recordID: String,
    val protocol: Int = 2,
)

/** Keep certificate slots under the same root libbox uses for relative paths. */
internal fun libboxWorkingDirectory(filesDir: File): File = filesDir.resolve("libbox")

/** 同一配置的 v2 入网 journal；旧身份与 floor 只保留为迁移输入。 */
internal class ManagedProfileStore(context: Context) {
    private val protected = EncryptedStore(context)

    @Synchronized
    fun hasLegacyIdentity(): Boolean = listOf(CURRENT, PREVIOUS, READY, CANDIDATE).any {
        protected.get(it) != null
    }

    @Synchronized
    fun legacyMigrationSource(): LegacyMigrationSource? {
        val current = protected.get(CURRENT)
        val previous = protected.get(PREVIOUS)
        val ready = protected.get(READY)
        if (current == null && previous == null && ready == null) return null
        return LegacyMigrationSource(current, previous, ready, protected.get(FLOOR))
    }

    @Synchronized
    fun migrationContext(identitySPKI: ByteArray): LegacyMigrationContext {
        val source = checkNotNull(legacyMigrationSource()) { "本机没有可迁移的原设备记录" }
        val record = JSONObject(checkNotNull(source.current ?: source.previous) {
            "本机尚无已安装的原设备配置，不能执行存量迁移"
        }.decodeToString())
        check(record.getInt("schema") == 2) { "原设备记录格式不支持迁移" }
        val response = record.getJSONObject("enrollment").getJSONObject("response")
        check(response.getString("configuration") == "ready") { "原设备没有已完成的加入记录" }
        val bootstrap = response.getJSONObject("bootstrap")
        val certificate = CertificateFactory.getInstance("X.509").generateCertificate(
            ByteArrayInputStream(bootstrap.getString("node_cert_pem").encodeToByteArray()),
        )
        check(certificate.publicKey.encoded.contentEquals(identitySPKI)) {
            "原设备证书与本机身份密钥不匹配"
        }
        return LegacyMigrationContext(
            bootstrap.getString("node_id"),
            checkNotNull(source.floor) { "原设备缺少受保护版本记录，拒绝降低版本后迁移" },
            TrustAnchor.platformPublicKeyForBootstrap(bootstrap.getString("platform_public_key")),
        )
    }

    @Synchronized
    fun pending(): ByteArray? = protected.get(PENDING)

    @Synchronized
    fun putV2Pending(pending: V2PendingEnrollment) {
        putV2PendingLocked(pending, allowResumeReplacement = false)
    }

    /** 只有用户显式导入并经共享 verifier 验证的 carrier 能替换 resume 窗口。 */
    @Synchronized
    fun putV2Resume(pending: V2PendingEnrollment) {
        putV2PendingLocked(pending, allowResumeReplacement = true)
    }

    private fun putV2PendingLocked(
        pending: V2PendingEnrollment,
        allowResumeReplacement: Boolean,
    ) {
        protected.get(PENDING)?.let { previousBytes ->
            val previousJSON = JSONObject(previousBytes.decodeToString())
            check(previousJSON.optInt("schema") == 2) {
                "旧待加入事务不能改写；请先明确放弃该事务，再导入当前加入码"
            }
            run {
                val previous = V2PendingEnrollment.decode(previousBytes)
                check(
                    previous.descriptor.contentEquals(pending.descriptor) &&
                        previous.proofBundle.contentEquals(pending.proofBundle) &&
                        previous.bootstrapCatalog.contentEquals(pending.bootstrapCatalog),
                ) { "v2 pending transaction identity 禁止替换" }
                check(pending.connectionAttempts >= previous.connectionAttempts) {
                    "v2 bootstrap attempt 计数禁止回退"
                }
                check(preservesV2Exact(previous.preflightResponse, pending.preflightResponse) &&
                    preservesV2Exact(previous.clientNonce, pending.clientNonce) &&
                    preservesV2Exact(previous.claimCore, pending.claimCore)) {
                    "v2 pending 已固定阶段禁止回退或替换"
                }
                check(previous.requestID == null || previous.requestID == pending.requestID) {
                    "v2 pending request identity 禁止回退或替换"
                }
                check(previous.claimResult == null || pending.claimResult != null) {
                    "v2 pending claim result 禁止回退"
                }
                validateV2ProgressAdvance(previous, pending)
                validateV2ResultAdvance(previous, pending)
                if (previous.selectedUnderlay == pending.selectedUnderlay) {
                    check(preservesV2Exact(previous.selectedTransport, pending.selectedTransport)) {
                        "同一 underlay 的 bootstrap probe plan 禁止替换"
                    }
                }
                if (allowResumeReplacement) {
                    check(pending.resumeDescriptor != null) { "显式 resume 更新缺少 descriptor" }
                    check(previous.connectionAttempts == pending.connectionAttempts) {
                        "resume carrier 导入不得改写 initial attempt journal"
                    }
                    check(sameV2Exact(previous.selectedTransport, pending.selectedTransport) &&
                        previous.selectedUnderlay == pending.selectedUnderlay &&
                        sameV2Exact(previous.preflightResponse, pending.preflightResponse) &&
                        previous.requestID == pending.requestID &&
                        sameV2Exact(previous.clientNonce, pending.clientNonce) &&
                        sameV2Exact(previous.claimCore, pending.claimCore) &&
                        sameV2Exact(previous.claimResult, pending.claimResult) &&
                        previous.progressStatus == pending.progressStatus &&
                        sameV2Exact(previous.resumeExpected, pending.resumeExpected)) {
                        "resume carrier 导入不得改写 pending transaction"
                    }
                    val replaced = !sameV2Exact(previous.resumeDescriptor, pending.resumeDescriptor) ||
                        !sameV2Exact(previous.resumeProofBundle, pending.resumeProofBundle) ||
                        !sameV2Exact(previous.resumeBootstrapCatalog, pending.resumeBootstrapCatalog)
                    if (replaced) {
                        check(
                            pending.resumeConnectionAttempts == 0L &&
                                pending.resumeSelectedUnderlay == null &&
                                pending.resumeSelectedTransport == null,
                        ) { "新 resume capability 必须从独立 attempt journal 开始" }
                    } else {
                        check(pending.resumeConnectionAttempts >= previous.resumeConnectionAttempts) {
                            "v2 resume attempt 计数禁止回退"
                        }
                        if (previous.resumeSelectedUnderlay == pending.resumeSelectedUnderlay) {
                            check(preservesV2Exact(previous.resumeSelectedTransport, pending.resumeSelectedTransport)) {
                                "同一 underlay 的 resume probe plan 禁止替换"
                            }
                        }
                    }
                } else {
                    check(preservesV2Exact(previous.resumeDescriptor, pending.resumeDescriptor) &&
                        preservesV2Exact(previous.resumeProofBundle, pending.resumeProofBundle) &&
                        preservesV2Exact(previous.resumeBootstrapCatalog, pending.resumeBootstrapCatalog)) {
                        "v2 resume authority 只能由显式 carrier 替换"
                    }
                    check(pending.resumeConnectionAttempts >= previous.resumeConnectionAttempts) {
                        "v2 resume attempt 计数禁止回退"
                    }
                    if (previous.resumeSelectedUnderlay == pending.resumeSelectedUnderlay) {
                        check(preservesV2Exact(previous.resumeSelectedTransport, pending.resumeSelectedTransport)) {
                            "同一 underlay 的 resume probe plan 禁止替换"
                        }
                    }
                }
            }
        }
        val body = pending.encode()
        protected.put(PENDING, body)
        val replay = checkNotNull(protected.get(PENDING)) { "v2 pending transaction 未能持久保存" }
        check(replay.contentEquals(body)) { "v2 pending transaction 持久化回读不一致" }
        V2PendingEnrollment.decode(replay)
    }

    private fun validateV2ProgressAdvance(
        previous: V2PendingEnrollment,
        candidate: V2PendingEnrollment,
    ) {
        candidate.progressStatus?.let { status ->
            Loomcore.validateAndroidV2PendingProgress(
                checkNotNull(candidate.claimCore),
                status,
                checkNotNull(candidate.resumeExpected),
            )
        }
        previous.progressStatus?.let { status ->
            Loomcore.advanceAndroidV2PendingProgress(
                checkNotNull(previous.claimCore),
                status,
                checkNotNull(previous.resumeExpected),
                checkNotNull(candidate.progressStatus) { "v2 pending progress 禁止回退" },
                checkNotNull(candidate.resumeExpected) { "v2 pending expected 禁止回退" },
            )
        }
    }

    private fun validateV2ResultAdvance(
        previous: V2PendingEnrollment,
        candidate: V2PendingEnrollment,
    ) {
        val oldResult = previous.claimResult ?: return
        val newResult = checkNotNull(candidate.claimResult)
        val oldStatus = JSONObject(oldResult.decodeToString()).getString("status")
        val newStatus = JSONObject(newResult.decodeToString()).getString("status")
        if (oldStatus == "completed" || oldStatus == newStatus) {
            check(oldResult.contentEquals(newResult)) {
                "v2 claim result 同阶段必须 exact replay"
            }
            return
        }
        check(oldStatus == "reserved" && newStatus in setOf("issued_provisional", "completed") ||
            oldStatus == "issued_provisional" && newStatus == "completed") {
            "v2 claim result 禁止回退或跨事务改写"
        }
    }

    @Synchronized
    fun recordV2ConnectionAttempt(capabilityID: String, attempt: Long) {
        val current = V2PendingEnrollment.decode(
            checkNotNull(protected.get(PENDING)) { "bootstrap attempt 缺少 pending transaction" },
        )
        putV2Pending(current.advanceAttempt(capabilityID, attempt))
    }

    @Synchronized
    fun clearPending() = protected.remove(PENDING)

    private fun preservesV2Exact(previous: ByteArray?, candidate: ByteArray?): Boolean =
        previous == null || candidate != null && previous.contentEquals(candidate)

    private fun sameV2Exact(left: ByteArray?, right: ByteArray?): Boolean =
        left == null && right == null || left != null && right != null && left.contentEquals(right)

    companion object {
        private const val CURRENT = "managed-current"
        private const val PREVIOUS = "managed-previous"
        private const val CANDIDATE = "managed-candidate"
        private const val PENDING = "join-pending"
        private const val READY = "join-ready"
        private const val FLOOR = "release-floor"
    }
}

/** 只读原始输入，认证迁移必须重新验证签名、身份与 floor；不能作为运行配置。 */
internal data class LegacyMigrationSource(
    val current: ByteArray?,
    val previous: ByteArray?,
    val ready: ByteArray?,
    val floor: ByteArray?,
)

internal data class LegacyMigrationContext(
    val deviceID: String,
    val floor: ByteArray,
    val platformKey: ByteArray,
)
