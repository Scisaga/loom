package io.github.scisaga.loom.route

import io.github.scisaga.loom.enrollment.ManagedProfile
import io.github.scisaga.loom.enrollment.ServiceProbeTargets
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class BusinessProbeScopeTest {
    @Test
    fun eachSelectedServiceUsesOnlyItsOwnUniqueTarget() {
        val profile = ManagedProfile("demo-device", "Demo", "demo-digest", "[]", "{}", "[]", "demo-record",
            listOf("192.0.2.53"), listOf(ServiceProbeTargets("demo-service", listOf("https://web.example/health"))))
        val selected = AppliedSelector("service:demo-service", "demo-candidate", listOf("demo-exit"), "demo-exit")
        val application = AppliedRoute(RouteMode.AUTO, "", false, listOf("demo-exit"), listOf(selected))
        val input = serviceBusinessProbeInputs(profile, application, "demo-network").single()
        assertEquals(selected, input.selector)
        assertEquals("192.0.2.53", input.dns)
        assertEquals("https://web.example/health", input.target)
        assertTrue(serviceBusinessProbeInputs(profile.copy(businessProbeTargets = emptyList()), application, "demo-network").isEmpty())
        assertTrue(serviceBusinessProbeInputs(profile.copy(businessProbeTargets = listOf(ServiceProbeTargets("demo-service", listOf("https://web.example/", "https://api.example/")))), application, "demo-network").isEmpty())
        assertTrue(serviceBusinessProbeInputs(profile.copy(businessProbeTargets = listOf(ServiceProbeTargets("demo-other", listOf("https://web.example/health")))), application, "demo-network").isEmpty())
        val other = selected.copy(selector = "service:demo-other", candidate = "demo-other-candidate")
        val two = application.copy(selectors = listOf(other, selected))
        val twoProfile = profile.copy(businessProbeTargets = profile.businessProbeTargets +
            ServiceProbeTargets("demo-other", listOf("https://api.example/health")))
        val inputs = serviceBusinessProbeInputs(twoProfile, two, "demo-network")
        assertEquals(listOf(other, selected), inputs.map { it.selector })
        assertEquals(listOf("https://api.example/health", "https://web.example/health"), inputs.map { it.target })
        assertEquals(listOf(input), serviceBusinessProbeInputs(profile, two, "demo-network"))
        val blocked = application.copy(blockedScopes = listOf("service:demo-other"))
        assertEquals(listOf(input), serviceBusinessProbeInputs(twoProfile, blocked, "demo-network"))
        assertEquals("reject", blocked.execution().last().candidate)
        assertTrue(serviceBusinessProbeInputs(profile.copy(dns = emptyList()), application, "demo-network").isEmpty())
    }
}
