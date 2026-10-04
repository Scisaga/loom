package io.github.scisaga.loom

import io.github.scisaga.loom.route.RoutePathStatus
import org.junit.Assert.assertEquals
import org.junit.Test

class RoutePathPresentationTest {
    @Test
    fun directAndRelayedChainsStayOrderedWithoutInventingHopEvidence() {
        val direct = path("svc:web", "direct", emptyList())
        val relayed = path("decl:best-egress", "cand:relay", listOf("demo-entry", "demo-exit"))

        assertEquals("本机 → 目标地址（Direct）", displayRouteChain(direct.serverChain, direct.finalExit))
        assertEquals("本机 → demo-entry → demo-exit → 目标地址", displayRouteChain(relayed.serverChain, relayed.finalExit))
        assertEquals("web", displayRouteService(direct.service))
        assertEquals("relay", displayRouteCandidate(relayed.candidate))
        assertEquals("可用", displayRouteState(relayed.state))
    }

    @Test
    fun localExitAndDirectRemainSeparateWithTheSameEmptyChain() {
        val direct = path("service:demo-web", "demo-direct", emptyList())
        val local = direct.copy(service = "service:demo-api", candidate = "demo-local", finalExit = "demo-hybrid")
        val summaries = summarizeRoutePaths(listOf(direct, local))

        assertEquals(2, summaries.size)
        assertEquals("本机 → 目标地址（Direct）", summaries[0].chainLabel)
        assertEquals("本机（出口 demo-hybrid）→ 目标地址", summaries[1].chainLabel)
    }

    private fun path(service: String, candidate: String, chain: List<String>) = RoutePathStatus(
        service = service,
        candidate = candidate,
        serverChain = chain,
        finalExit = chain.lastOrNull() ?: "direct",
        state = "available",
        updatedAt = "2030-01-01T00:00:00Z",
    )
}
