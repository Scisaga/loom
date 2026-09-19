package io.github.scisaga.loom

import io.github.scisaga.loom.route.RoutePathStatus
import org.junit.Assert.assertEquals
import org.junit.Test

class RoutePathPresentationTest {
    @Test
    fun directAndRelayedChainsStayOrderedWithoutInventingHopEvidence() {
        val direct = path("svc:web", "direct", emptyList())
        val relayed = path("decl:best-egress", "cand:relay", listOf("demo-entry", "demo-exit"))

        assertEquals("本机 → 目标地址（Direct）", displayRouteChain(direct.serverChain))
        assertEquals("本机 → demo-entry → demo-exit → 目标地址", displayRouteChain(relayed.serverChain))
        assertEquals("web", displayRouteService(direct.service))
        assertEquals("relay", displayRouteCandidate(relayed.candidate))
        assertEquals("可用", displayRouteState(relayed.state))
    }

    private fun path(service: String, candidate: String, chain: List<String>) = RoutePathStatus(
        service = service,
        candidate = candidate,
        serverChain = chain,
        state = "available",
        updatedAt = "2030-01-01T00:00:00Z",
    )
}
