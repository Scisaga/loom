package io.github.scisaga.loom.enrollment

import io.github.scisaga.loom.security.TrustAnchor
import io.github.scisaga.loomcore.Loomcore
import org.json.JSONObject
import java.security.SecureRandom
import java.util.Base64
import java.util.UUID

/**
 * #14：一次性 descriptor 与 stable core 只进入 EncryptedStore。每次 outer
 * connection attempt 必须先原子推进这个 journal，进程重启不能重置预算。
 */
internal data class V2PendingEnrollment(
    val descriptor: ByteArray,
    val proofBundle: ByteArray,
    val bootstrapCatalog: ByteArray,
    val connectionAttempts: Long = 0,
    val selectedUnderlay: String? = null,
    val selectedTransport: ByteArray? = null,
    val preflightResponse: ByteArray? = null,
    val requestID: String? = null,
    val clientNonce: ByteArray? = null,
    val claimCore: ByteArray? = null,
    val claimResult: ByteArray? = null,
    val progressStatus: String? = null,
    val resumeExpected: ByteArray? = null,
    val resumeDescriptor: ByteArray? = null,
    val resumeProofBundle: ByteArray? = null,
    val resumeBootstrapCatalog: ByteArray? = null,
    val resumeConnectionAttempts: Long = 0,
    val resumeSelectedUnderlay: String? = null,
    val resumeSelectedTransport: ByteArray? = null,
) {
    init {
        require(descriptor.isNotEmpty() && proofBundle.isNotEmpty() && bootstrapCatalog.isNotEmpty()) {
            "v2 pending 缺少已验 bootstrap 输入"
        }
        require(connectionAttempts >= 0) { "v2 pending connection attempt 无效" }
        require((selectedUnderlay == null) == (selectedTransport == null)) {
            "v2 bootstrap underlay/selection 不完整"
        }
        selectedUnderlay?.let {
            require(it.isNotBlank() && it.length <= 256 && it.trim() == it) {
                "v2 bootstrap underlay identity 无效"
            }
        }
        require((requestID == null) == (clientNonce == null)) { "v2 stable coordinates 不完整" }
        clientNonce?.let { require(it.size == 32) { "v2 client nonce 必须是 32 bytes" } }
        require(claimCore == null || preflightResponse != null && requestID != null) {
            "v2 claim core 缺少 preflight/stable coordinates"
        }
        require(claimResult == null || claimCore != null) { "v2 claim result 缺少 stable core" }
        require((progressStatus == null) == (resumeExpected == null)) {
            "v2 pending progress status/expected 不完整"
        }
        require(progressStatus == null || claimCore != null && claimResult != null) {
            "v2 pending progress 缺少 stable core/result"
        }
        val resumeParts = listOf(resumeDescriptor, resumeProofBundle, resumeBootstrapCatalog)
        require(resumeParts.all { it == null } || resumeParts.all { it != null }) {
            "v2 resume descriptor/proof/catalog 不完整"
        }
        require(resumeConnectionAttempts >= 0) { "v2 resume connection attempt 无效" }
        require((resumeSelectedUnderlay == null) == (resumeSelectedTransport == null)) {
            "v2 resume underlay/selection 不完整"
        }
        resumeSelectedUnderlay?.let {
            require(it.isNotBlank() && it.length <= 256 && it.trim() == it) {
                "v2 resume underlay identity 无效"
            }
        }
        if (resumeDescriptor == null) {
            require(
                resumeConnectionAttempts == 0L && resumeSelectedUnderlay == null &&
                    resumeSelectedTransport == null,
            ) { "v2 resume journal 缺少 descriptor" }
        } else {
            require(claimCore != null && progressStatus != null && resumeExpected != null) {
                "v2 resume 缺少已验 pending progress"
            }
        }
    }

    fun withSelection(underlayIdentity: String, selection: ByteArray): V2PendingEnrollment {
        require(underlayIdentity.isNotBlank() && underlayIdentity.length <= 256 && underlayIdentity.trim() == underlayIdentity) {
            "bootstrap underlay identity 无效"
        }
        require(selection.isNotEmpty()) { "bootstrap transport selection 不能为空" }
        if (selectedUnderlay == underlayIdentity) {
            return copy(selectedTransport = bindExact(selectedTransport, selection, "bootstrap transport selection"))
        }
        return copy(selectedUnderlay = underlayIdentity, selectedTransport = selection.copyOf())
    }

    fun withPreflight(response: ByteArray): V2PendingEnrollment =
        copy(preflightResponse = bindExact(preflightResponse, response, "preflight response"))

    fun withStableCoordinates(): V2PendingEnrollment {
        if (requestID != null) return this
        return copy(
            requestID = UUID.randomUUID().toString(),
            clientNonce = ByteArray(32).also(SecureRandom()::nextBytes),
        )
    }

    fun withClaimCore(core: ByteArray): V2PendingEnrollment =
        copy(claimCore = bindExact(claimCore, core, "stable claim core"))

    fun withVerifiedClaimResult(result: ByteArray, projection: ByteArray): V2PendingEnrollment {
        require(result.isNotEmpty()) { "v2 claim result 不能为空" }
        val verified = JSONObject(projection.decodeToString())
        check(verified.getInt("schema") == 1) { "v2 claim result projection schema 无效" }
        val status = verified.getString("status")
        val canonicalResult = Loomcore.canonicalizeV2(result)
        val projectedResult = Loomcore.canonicalizeV2(
            verified.getJSONObject("exact_result").toString().encodeToByteArray(),
        )
        check(canonicalResult.contentEquals(result) && projectedResult.contentEquals(result)) {
            "v2 claim result 未绑定 verifier 的 exact result"
        }
        check(JSONObject(result.decodeToString()).getString("status") == status) {
            "v2 claim result/projection status 不匹配"
        }
        val previousCompleted = claimResult?.let {
            JSONObject(it.decodeToString()).optString("status") == "completed"
        } == true
        if (status == "completed") {
            if (previousCompleted) check(checkNotNull(claimResult).contentEquals(result)) {
                "v2 completed result exact replay 发生冲突"
            }
            return copy(claimResult = result.copyOf())
        }
        check(!previousCompleted && status in setOf("reserved", "issued_provisional")) {
            "v2 pending result 状态无效或发生回退"
        }
        val expected = Loomcore.canonicalizeV2(
            verified.getJSONObject("resume_expected").toString().encodeToByteArray(),
        )
        Loomcore.validateAndroidV2PendingProgress(checkNotNull(claimCore), status, expected)
        if (progressStatus != null) {
            Loomcore.advanceAndroidV2PendingProgress(
                checkNotNull(claimCore),
                progressStatus,
                checkNotNull(resumeExpected),
                status,
                expected,
            )
        }
        return copy(
            claimResult = result.copyOf(),
            progressStatus = status,
            resumeExpected = expected,
        )
    }

    /** D130：显式导入可替换旧 resume 窗口，但不能改变本机 transaction floor。 */
    fun withResume(
        descriptor: ByteArray,
        proofBundle: ByteArray,
        bootstrapCatalog: ByteArray,
        trustedTime: String,
    ): V2PendingEnrollment {
        val core = checkNotNull(claimCore) { "v2 resume 缺少 stable core" }
        val status = checkNotNull(progressStatus) { "v2 resume 缺少 verified progress" }
        val expected = checkNotNull(resumeExpected) { "v2 resume 缺少 expected transaction" }
        Loomcore.validateAndroidV2ResumeInputs(
            descriptor,
            proofBundle,
            bootstrapCatalog,
            core,
            expected,
            TrustAnchor.platformPublicKey(),
            status,
            trustedTime,
        )
        val exactReplay = resumeDescriptor?.contentEquals(descriptor) == true &&
            resumeProofBundle?.contentEquals(proofBundle) == true &&
            resumeBootstrapCatalog?.contentEquals(bootstrapCatalog) == true
        if (exactReplay) return this
        return copy(
            resumeDescriptor = descriptor.copyOf(),
            resumeProofBundle = proofBundle.copyOf(),
            resumeBootstrapCatalog = bootstrapCatalog.copyOf(),
            resumeConnectionAttempts = 0,
            resumeSelectedUnderlay = null,
            resumeSelectedTransport = null,
        )
    }

    fun withResumeSelection(underlayIdentity: String, selection: ByteArray): V2PendingEnrollment {
        check(resumeDescriptor != null) { "v2 resume selection 缺少 descriptor" }
        require(underlayIdentity.isNotBlank() && underlayIdentity.length <= 256 && underlayIdentity.trim() == underlayIdentity) {
            "v2 resume underlay identity 无效"
        }
        require(selection.isNotEmpty()) { "v2 resume transport selection 不能为空" }
        if (resumeSelectedUnderlay == underlayIdentity) {
            return copy(
                resumeSelectedTransport = bindExact(
                    resumeSelectedTransport,
                    selection,
                    "v2 resume transport selection",
                ),
            )
        }
        return copy(
            resumeSelectedUnderlay = underlayIdentity,
            resumeSelectedTransport = selection.copyOf(),
        )
    }

    fun withResumeConnectionAttempts(observed: Long): V2PendingEnrollment {
        check(resumeDescriptor != null) { "v2 resume attempt 缺少 descriptor" }
        check(observed >= resumeConnectionAttempts) { "v2 resume attempt 计数禁止回退" }
        return copy(resumeConnectionAttempts = observed)
    }

    fun withConnectionAttempts(observed: Long): V2PendingEnrollment {
        check(observed >= connectionAttempts) { "bootstrap attempt 计数禁止回退" }
        return copy(connectionAttempts = observed)
    }

    fun advanceAttempt(capabilityID: String, attempt: Long): V2PendingEnrollment {
        val initialCapability = JSONObject(descriptor.decodeToString())
            .getJSONObject("bootstrap_tunnel_capability")
            .getString("capability_id")
        if (capabilityID == initialCapability) {
            check(attempt == connectionAttempts + 1) { "bootstrap attempt journal 必须严格单调" }
            return copy(connectionAttempts = attempt)
        }
        val resumeCapability = resumeDescriptor?.let {
            JSONObject(it.decodeToString())
                .getJSONObject("resume_tunnel_capability")
                .getString("capability_id")
        }
        check(capabilityID == resumeCapability) { "bootstrap attempt capability 已切换" }
        check(attempt == resumeConnectionAttempts + 1) { "resume attempt journal 必须严格单调" }
        return copy(resumeConnectionAttempts = attempt)
    }

    fun encode(): ByteArray {
        val root = JSONObject()
            .put("schema", SCHEMA)
            .put("kind", KIND)
            .put("descriptor", descriptor.decodeToString())
            .put("proof_bundle", proofBundle.decodeToString())
            .put("bootstrap_catalog", bootstrapCatalog.decodeToString())
            .put("connection_attempts", connectionAttempts)
        selectedUnderlay?.let { root.put("selected_underlay", it) }
        selectedTransport?.let { root.put("selected_transport", it.decodeToString()) }
        preflightResponse?.let { root.put("preflight_response", it.decodeToString()) }
        requestID?.let { root.put("request_id", it) }
        clientNonce?.let { root.put("client_nonce", Base64.getUrlEncoder().withoutPadding().encodeToString(it)) }
        claimCore?.let { root.put("claim_core", it.decodeToString()) }
        claimResult?.let { root.put("claim_result", it.decodeToString()) }
        progressStatus?.let { root.put("progress_status", it) }
        resumeExpected?.let { root.put("resume_expected", it.decodeToString()) }
        resumeDescriptor?.let { root.put("resume_descriptor", it.decodeToString()) }
        resumeProofBundle?.let { root.put("resume_proof_bundle", it.decodeToString()) }
        resumeBootstrapCatalog?.let { root.put("resume_bootstrap_catalog", it.decodeToString()) }
        if (resumeDescriptor != null) root.put("resume_connection_attempts", resumeConnectionAttempts)
        resumeSelectedUnderlay?.let { root.put("resume_selected_underlay", it) }
        resumeSelectedTransport?.let { root.put("resume_selected_transport", it.decodeToString()) }
        return root.toString().encodeToByteArray()
    }

    private fun bindExact(existing: ByteArray?, candidate: ByteArray, name: String): ByteArray {
        require(candidate.isNotEmpty()) { "$name 不能为空" }
        if (existing != null) check(existing.contentEquals(candidate)) { "$name 在重试中发生变化" }
        return candidate.copyOf()
    }

    companion object {
        private const val SCHEMA = 2
        private const val KIND = "v2_initial"
        private val OPTIONAL_FIELDS = setOf(
            "selected_transport",
            "selected_underlay",
            "preflight_response",
            "request_id",
            "client_nonce",
            "claim_core",
            "claim_result",
            "progress_status",
            "resume_expected",
            "resume_descriptor",
            "resume_proof_bundle",
            "resume_bootstrap_catalog",
            "resume_connection_attempts",
            "resume_selected_underlay",
            "resume_selected_transport",
        )
        private val FIELDS = OPTIONAL_FIELDS + setOf(
            "schema",
            "kind",
            "descriptor",
            "proof_bundle",
            "bootstrap_catalog",
            "connection_attempts",
        )

        fun decode(body: ByteArray): V2PendingEnrollment {
            require(body.isNotEmpty() && body.size <= MAXIMUM_RECORD) { "v2 pending record 大小无效" }
            val root = JSONObject(body.decodeToString())
            check(root.getInt("schema") == SCHEMA && root.getString("kind") == KIND) {
                "不是 v2 initial pending record"
            }
            val names = root.keys().asSequence().toSet()
            check(names.all(FIELDS::contains)) { "v2 pending record 含未知字段" }
            val nonce = root.optString("client_nonce").takeIf(String::isNotBlank)?.let(::decodeNonce)
            return V2PendingEnrollment(
                descriptor = root.getString("descriptor").encodeToByteArray(),
                proofBundle = root.getString("proof_bundle").encodeToByteArray(),
                bootstrapCatalog = root.getString("bootstrap_catalog").encodeToByteArray(),
                connectionAttempts = root.getLong("connection_attempts"),
                selectedUnderlay = root.optString("selected_underlay").takeIf(String::isNotBlank),
                selectedTransport = optionalBytes(root, "selected_transport"),
                preflightResponse = optionalBytes(root, "preflight_response"),
                requestID = root.optString("request_id").takeIf(String::isNotBlank),
                clientNonce = nonce,
                claimCore = optionalBytes(root, "claim_core"),
                claimResult = optionalBytes(root, "claim_result"),
                progressStatus = root.optString("progress_status").takeIf(String::isNotBlank),
                resumeExpected = optionalBytes(root, "resume_expected"),
                resumeDescriptor = optionalBytes(root, "resume_descriptor"),
                resumeProofBundle = optionalBytes(root, "resume_proof_bundle"),
                resumeBootstrapCatalog = optionalBytes(root, "resume_bootstrap_catalog"),
                resumeConnectionAttempts = if (root.has("resume_connection_attempts")) {
                    root.getLong("resume_connection_attempts")
                } else {
                    0
                },
                resumeSelectedUnderlay = root.optString("resume_selected_underlay").takeIf(String::isNotBlank),
                resumeSelectedTransport = optionalBytes(root, "resume_selected_transport"),
            )
        }

        private fun optionalBytes(root: JSONObject, name: String): ByteArray? =
            root.optString(name).takeIf(String::isNotBlank)?.encodeToByteArray()

        private fun decodeNonce(value: String): ByteArray {
            val decoded = Base64.getUrlDecoder().decode(value)
            check(Base64.getUrlEncoder().withoutPadding().encodeToString(decoded) == value) {
                "v2 pending nonce 不是 canonical base64url"
            }
            return decoded
        }

        private const val MAXIMUM_RECORD = 40 * 1024 * 1024
    }
}
