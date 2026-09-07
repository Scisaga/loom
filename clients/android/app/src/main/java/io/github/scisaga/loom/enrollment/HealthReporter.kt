package io.github.scisaga.loom.enrollment

import android.content.Context
import io.github.scisaga.loom.security.DeviceKeyStore
import io.github.scisaga.loomcore.Loomcore
import org.json.JSONArray
import java.time.Instant

internal class HealthReporter(
    private val context: Context,
    private val keys: DeviceKeyStore = DeviceKeyStore(),
) {
    fun send(profile: ManagedProfile, problems: List<String>) {
        val timestamp = Instant.now().toString()
        val normalized = problems.distinct().sorted()
        val problemsJSON = JSONArray(normalized).toString().encodeToByteArray()
        val attestMessage = Loomcore.prepareObservationAttestation(profile.nodeID, profile.snapshot, timestamp)
        val selfCheckMessage = Loomcore.prepareSelfCheckAttestation(profile.nodeID, timestamp, problemsJSON)
        val observation = Loomcore.assembleObservation(
            profile.nodeID,
            profile.snapshot,
            timestamp,
            problemsJSON,
            profile.certificatePEM,
            profile.caPEM,
            keys.sign(attestMessage),
            keys.sign(selfCheckMessage),
        )
        val result = HttpTransport.postJSON(context, profile.reportEndpoint, observation, MAX_RESPONSE)
        check(result.status == 204 && result.body.isEmpty()) { "可信健康上报被拒绝（HTTP ${result.status}）" }
    }

    companion object {
        private const val MAX_RESPONSE = 4096
    }
}
