package io.github.scisaga.loom.route

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MeasurementCompletionDiagnosticsTest {
    @Test
    fun echoBindingPreservesOnlyCanonicalHashesAndPurpose() {
        val hash = "a".repeat(64)
        val line = "echo_id=$hash binding resource_id_sha256=$hash spec_digest=sha256:$hash operation=admission_echo network_generation_sha256=$hash policy_id_sha256=$hash"
        val lines = mutableListOf<String>()
        emitEchoDiagnostic(line) { lines += it }
        assertEquals(listOf("echo-diagnostic $line"), lines)
        for (invalid in listOf(
            line.replace("operation=admission_echo", "operation=connect_tcp"),
            line.replace("resource_id_sha256=$hash", "resource_id_sha256=demo-private-resource"),
            line.replace("spec_digest=sha256:$hash", "spec_digest=demo-invalid"),
            "$line target=192.0.2.1",
            "$line\n",
        )) emitEchoDiagnostic(invalid) { lines += it }
        assertEquals(1, lines.size)
        emitEchoDiagnostic(line) { throw IllegalStateException("demo-sink-failure") }
    }

    @Test
    fun echoDebugAcceptsOnlySafeFixedFieldsAndContainsSinkFailures() {
        val id = "a".repeat(64)
        val line = "echo_id=$id phase=response-validate elapsed_ns=123 outcome=denied"
        val lines = mutableListOf<String>()
        emitEchoDiagnostic(line) { lines += it }
        assertEquals(listOf("echo-diagnostic $line"), lines)
        for (invalid in listOf(
            "$line error=demo-private-error",
            line.replace(id, "demo-raw-nonce"),
            line.replace("response-validate", "demo-private-target"),
            line.replace("elapsed_ns=123", "elapsed_ns=-1"),
            line.replace("elapsed_ns=123", "elapsed_ns=9999999999999999999"),
            "$line\n",
        )) emitEchoDiagnostic(invalid) { lines += it }
        assertEquals(1, lines.size)
        emitEchoDiagnostic(line) { throw IllegalStateException("demo-sink-failure") }
    }

    @Test
    fun logsOriginalFailureTimesAndOnlyFixedMetadata() {
        val specification = "sha256:" + "a".repeat(64)
        val body = """{"schema":3,"observations":[{"level":"resource","resource_id":"demo-sensitive-resource","spec_digest":"$specification","target":"192.0.2.10:51820","action":"wireguard_echo","result":"unavailable","observed_at":1893456000123,"valid_until":1893456030123,"network_generation":"demo-network","credential":"demo-private-credential"}]}""".encodeToByteArray()
        val lines = mutableListOf<String>()
        emitMeasurementCompletionDiagnostics(body, { lines += it }) { throw AssertionError("valid metadata rejected") }
        assertEquals(1, lines.size)
        val line = lines.single()
        assertTrue(line.contains("spec_digest=$specification result=unavailable observed_at=1893456000123 valid_until=1893456030123"))
        assertTrue(line.contains(Regex("key_sha256=[0-9a-f]{64}")))
        assertTrue(line.contains(Regex("network_generation_sha256=[0-9a-f]{64}")))
        for (privateValue in listOf("192.0.2.10", "51820", "demo-sensitive-resource", "demo-network", "demo-private-credential")) {
            assertFalse(line.contains(privateValue))
        }
    }

    @Test
    fun malformedDiagnosticCannotInterruptTheMeasurementConsumer() {
        var failures = 0
        emitMeasurementCompletionDiagnostics("invalid".encodeToByteArray(), { throw AssertionError("invalid metadata logged") }) { failures++ }
        assertEquals(1, failures)
    }
}
