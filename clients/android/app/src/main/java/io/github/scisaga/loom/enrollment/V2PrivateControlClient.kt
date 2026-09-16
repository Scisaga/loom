package io.github.scisaga.loom.enrollment

import io.github.scisaga.loom.security.DeviceKeyStore
import io.github.scisaga.loomcore.AndroidIdentitySigner
import io.github.scisaga.loomcore.Loomcore
import org.json.JSONObject

internal data class V2ReportResponse(val statusCode: Int, val observations: ByteArray?)

/** 私有 TLS 在共享核心校验；原 Keystore 只签完整消息，socket 仍经过当前 VPN/WG。 */
internal class V2PrivateControlClient(private val keys: DeviceKeyStore = DeviceKeyStore()) {
    private val signer = object : AndroidIdentitySigner {
        override fun signP256(message: ByteArray): ByteArray = keys.sign(message)
    }

    fun getFirst(state: ByteArray, trustedTime: String): ByteArray =
        Loomcore.fetchAndroidV2DeviceConfig(state, keys.ensureIdentity(), signer, trustedTime)

    fun postFirst(state: ByteArray, body: ByteArray, trustedTime: String): V2ReportResponse {
        val accepted = JSONObject(
            Loomcore.postAndroidV2DeviceReport(state, keys.ensureIdentity(), body, signer, trustedTime)
                .decodeToString(),
        )
        val status = accepted.getInt("status_code")
        check(status == 200 || status == 204) { "[Android report] private report 未被接受" }
        val observations = accepted.optJSONArray("observations")?.let {
            Loomcore.canonicalizeV2(it.toString().encodeToByteArray())
        }
        return V2ReportResponse(status, observations)
    }
}
