package io.github.scisaga.loom.route

import java.security.MessageDigest
import org.json.JSONObject

private fun measurementDigest(value: String): String = MessageDigest.getInstance("SHA-256")
    .digest(value.encodeToByteArray()).joinToString("") { "%02x".format(it) }

/** Completion-time metadata only; this never logs the sample or its target. */
internal fun emitMeasurementCompletionDiagnostics(body: ByteArray, emit: (String) -> Unit, failed: () -> Unit) {
    try {
        val samples = JSONObject(body.decodeToString()).getJSONArray("observations")
        for (index in 0 until samples.length()) {
            val sample = samples.getJSONObject(index)
            val specification = sample.getString("spec_digest")
            check(specification.matches(Regex("sha256:[0-9a-f]{64}")))
            val result = sample.getString("result")
            check(result in setOf("available", "unavailable", "unknown"))
            val observed = sample.get("observed_at").also { check(it is Long || it is Int) }.toString()
            val until = sample.get("valid_until").also { check(it is Long || it is Int) }.toString()
            check(observed.toLong() > 0 && until.toLong() > observed.toLong())
            val key = listOf(sample.getString("level"), "", sample.optString("resource_id"), sample.optString("link_id"),
                specification, sample.getString("target"), sample.getString("action")).joinToString("\u0000")
            val generation = measurementDigest(sample.getString("network_generation"))
            emit("measurement-completed key_sha256=${measurementDigest(key)} spec_digest=$specification result=$result " +
                "observed_at=$observed valid_until=$until network_generation_sha256=$generation")
        }
    } catch (_: Throwable) {
        // A diagnostic parser/logger cannot cancel or alter the measurement.
        runCatching(failed)
    }
}
