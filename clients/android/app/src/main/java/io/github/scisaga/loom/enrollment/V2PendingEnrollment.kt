package io.github.scisaga.loom.enrollment

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

    fun withClaimResult(result: ByteArray): V2PendingEnrollment {
        require(result.isNotEmpty()) { "v2 claim result 不能为空" }
        return copy(claimResult = result.copyOf())
    }

    fun withConnectionAttempts(observed: Long): V2PendingEnrollment {
        check(observed >= connectionAttempts) { "bootstrap attempt 计数禁止回退" }
        return copy(connectionAttempts = observed)
    }

    fun advanceAttempt(capabilityID: String, attempt: Long): V2PendingEnrollment {
        val expectedCapability = JSONObject(descriptor.decodeToString())
            .getJSONObject("bootstrap_tunnel_capability")
            .getString("capability_id")
        check(capabilityID == expectedCapability) { "bootstrap attempt capability 已切换" }
        check(attempt == connectionAttempts + 1) { "bootstrap attempt journal 必须严格单调" }
        return copy(connectionAttempts = attempt)
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
