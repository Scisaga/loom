package io.github.scisaga.loom.route

import io.github.scisaga.loom.enrollment.ManagedProfile
import io.github.scisaga.loom.enrollment.ServiceProbeTargets
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.assertFalse
import org.junit.Test

class BusinessProbeScopeTest {
    @Test
    fun recoveryProposalsWakeOnlyTheExistingWorkerWhenTheirProofAdvances() {
        fun memory(candidate: String, count: Int, calibrate: Boolean = true) =
            if (calibrate && candidate.isNotBlank()) mapOf("tcp://web.example:443" to (candidate to count)) else emptyMap()
        val first = memory("demo-candidate", 1)
        val confirmed = memory("demo-candidate", 2)
        assertTrue(tcpRecoveryProgressed(emptyMap(), first))
        assertTrue(tcpRecoveryProgressed(first, confirmed))
        assertFalse(tcpRecoveryProgressed(confirmed, confirmed))
        assertFalse(tcpRecoveryProgressed(confirmed, memory("demo-candidate", 3, false)))
        assertFalse(tcpRecoveryProgressed(confirmed, memory("", 0)))
        assertTrue(tcpRecoveryProgressed(confirmed, memory("demo-other", 1)))
    }

    @Test
    fun tcpDiagnosticNamesTheOriginalSourceAndPreservesItsTimes() {
        val observed = "2030-01-02T03:04:05Z"
        val until = "2030-01-02T03:14:05Z"
        val ordinary = tcpObservationDetail("tcp_connect", "web.example:443", "available", 7, observed, until)
        val calibrated = tcpObservationDetail("tcp_calibration", "web.example:443", "available", 7, observed, until)
        assertTrue(ordinary.startsWith("TCP 建连观测 · web.example:443 · 成功 · 7 ms"))
        assertTrue(calibrated.startsWith("后台 TCP 试连 · web.example:443 · 成功 · 7 ms"))
        assertFalse(calibrated.contains("TCP 建连观测"))
        assertTrue(calibrated.endsWith("采样 $observed · 有效至 $until"))
        assertTrue(tcpObservationDetail("tcp_calibration", "web.example:443", "unknown", 8, observed, until).contains(" · 未知 · "))
        assertEquals("尚无本机 TCP 建连观测", tcpObservationDetail("https_request", "web.example:443", "available", 7, observed, until))
    }

    @Test
    fun onlyTheServiceOfTheCurrentPolicySuppliesMeasurementDisplayTargets() {
        val profile = ManagedProfile("demo-device", "Demo", "demo-digest", "[]", "{}", "[]", "demo-record",
            listOf("192.0.2.53"), listOf(ServiceProbeTargets("demo-service", listOf("https://web.example/health"))))
        val selected = AppliedSelector("access", "demo-candidate", listOf("demo-exit"), "demo-exit", policyID = "demo-policy")
        val application = AppliedRoute(mapOf("demo-service" to "demo-policy"), listOf(selected))
        val input = serviceBusinessProbeInputs(profile, application, "demo-network").single()
        assertEquals(selected, input.selector)
        assertEquals("https://web.example/health", input.target)
        assertTrue(serviceBusinessProbeInputs(profile.copy(businessProbeTargets = emptyList()), application, "demo-network").isEmpty())
        assertEquals(listOf("https://web.example/", "https://api.example/"), serviceBusinessProbeInputs(profile.copy(businessProbeTargets = listOf(ServiceProbeTargets("demo-service", listOf("https://web.example/", "https://api.example/")))), application, "demo-network").map { it.target })
        assertTrue(serviceBusinessProbeInputs(profile.copy(businessProbeTargets = listOf(ServiceProbeTargets("demo-other", listOf("https://web.example/health")))), application, "demo-network").isEmpty())
        val otherProfile = profile.copy(businessProbeTargets = profile.businessProbeTargets +
            ServiceProbeTargets("demo-other", listOf("https://api.example/health")))
        assertEquals(listOf(input), serviceBusinessProbeInputs(otherProfile, application, "demo-network"))
        val lan = AppliedSelector("local_network:demo-lan", "demo-lan-candidate", listOf("demo-lan-node"), "demo-lan-node", policyID = "demo-lan-policy")
        val withLAN = application.copy(choices = application.choices + ("demo-lan" to "demo-lan-policy"), selectors = application.selectors + lan)
        val lanProfile = profile.copy(businessProbeTargets = profile.businessProbeTargets + ServiceProbeTargets("demo-lan", listOf("https://lan.example/health")))
        assertEquals(setOf("https://web.example/health", "https://lan.example/health"), serviceBusinessProbeInputs(lanProfile, withLAN, "demo-network").map { it.target }.toSet())
        val blocked = application.copy(selectors=emptyList(), blockedScopes=listOf("access"))
        assertTrue(serviceBusinessProbeInputs(otherProfile, blocked, "demo-network").isEmpty())
        assertEquals("reject", blocked.execution().single().candidate)
        assertEquals(listOf(input), serviceBusinessProbeInputs(profile.copy(dns = emptyList()), application, "demo-network"))
    }
}
