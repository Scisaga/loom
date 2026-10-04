package io.github.scisaga.loom.route

import io.github.scisaga.loom.enrollment.ManagedProfile
import io.github.scisaga.loom.enrollment.ServiceProbeTargets
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class BusinessProbeScopeTest {
    @Test
    fun onlyOneCertifiedTargetAndOneActualScopePermitAnObservation() {
        val profile = ManagedProfile("demo-device", "Demo", "demo-digest", "[]", "{}", "[]", "demo-record",
            listOf("192.0.2.53"), listOf(ServiceProbeTargets("demo-service", listOf("https://web.example/health"))))
        val selected = AppliedSelector("service:demo-service", "demo-candidate", listOf("demo-exit"), "demo-exit")
        val application = AppliedRoute(RouteMode.AUTO, "", false, listOf("demo-exit"), listOf(selected))
        val input = singleBusinessProbeInput(profile, application, "demo-network")!!
        assertEquals(selected, input.selector)
        assertEquals("192.0.2.53", input.dns)
        assertEquals("https://web.example/health", input.target)
        assertNull(singleBusinessProbeInput(profile.copy(businessProbeTargets = emptyList()), application, "demo-network"))
        assertNull(singleBusinessProbeInput(profile.copy(businessProbeTargets = listOf(ServiceProbeTargets("demo-service", listOf("https://web.example/", "https://api.example/")))), application, "demo-network"))
        assertNull(singleBusinessProbeInput(profile.copy(businessProbeTargets = listOf(ServiceProbeTargets("demo-other", listOf("https://web.example/health")))), application, "demo-network"))
        assertNull(singleBusinessProbeInput(profile, application.copy(selectors = listOf(selected, selected.copy(selector = "demo-other"))), "demo-network"))
        assertNull(singleBusinessProbeInput(profile.copy(dns = emptyList()), application, "demo-network"))
    }
}
