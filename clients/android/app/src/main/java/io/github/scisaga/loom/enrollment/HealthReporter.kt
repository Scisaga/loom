package io.github.scisaga.loom.enrollment

import android.content.Context
import io.github.scisaga.loom.security.DeviceKeyStore
import io.github.scisaga.loom.route.RouteManager
import io.github.scisaga.loomcore.Loomcore
import org.json.JSONArray
import java.time.Instant

internal data class HealthReportResult(
    val status: Int,
    val observations: ByteArray?,
    val observationError: String? = null,
)

internal class HealthReporter(
    private val context: Context,
    private val keys: DeviceKeyStore = DeviceKeyStore(),
) {
    fun send(profile: ManagedProfile, problems: List<String>): HealthReportResult {
        val timestamp = Instant.now().toString()
        val normalized = problems.distinct().sorted()
        val problemsJSON = JSONArray(normalized).toString().encodeToByteArray()
        val agentState = RouteManager.get(context).agentState(profile.nodeID, timestamp)
        val attestMessage = Loomcore.prepareObservationAttestationWithAgent(
            profile.nodeID,
            profile.snapshot,
            timestamp,
            agentState ?: ByteArray(0),
        )
        val selfCheckMessage = Loomcore.prepareSelfCheckAttestation(profile.nodeID, timestamp, problemsJSON)
        val observation = Loomcore.assembleObservationWithAgent(
            profile.nodeID,
            profile.snapshot,
            timestamp,
            problemsJSON,
            agentState ?: ByteArray(0),
            profile.certificatePEM,
            profile.caPEM,
            keys.sign(attestMessage),
            keys.sign(selfCheckMessage),
        )
        val result = HttpTransport.postJSONWithObservations(context, profile.reportEndpoint, observation, MAX_RESPONSE)
        return when (result.status) {
            204 -> {
                check(result.body.isEmpty()) { "可信健康上报 204 携带了意外正文" }
                HealthReportResult(status = 204, observations = null)
            }
            200 -> {
                val json = result.contentType?.substringBefore(';')?.trim()?.equals("application/json", ignoreCase = true) == true
                if (json) {
                    HealthReportResult(status = 200, observations = result.body)
                } else {
                    HealthReportResult(
                        status = 200,
                        observations = null,
                        observationError = "服务器返回的观测正文不是 application/json",
                    )
                }
            }
            else -> error("可信健康上报被拒绝（HTTP ${result.status}）")
        }
    }

    companion object {
        private const val MAX_RESPONSE = 1024 * 1024
    }
}
