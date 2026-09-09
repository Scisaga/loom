package io.github.scisaga.loom.route

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RoutePathDisplayTest {
    @Test
    fun actualPathUsesStructuredLinkEvidenceWithoutWholePathHealth() {
        val application = AppliedRoute(
            planScope = "scope",
            mode = RouteMode.AUTO,
            exit = "",
            blocked = false,
            blockReason = "",
            directAvailable = true,
            exits = listOf("exit"),
            selectors = listOf(AppliedSelector("route:web", "planned", listOf("wrong"))),
        )
        val decision = RouteDecision(
            declaration = "web",
            selector = "route:web",
            current = "actual",
            choice = "actual",
            chain = listOf("entry", "exit"),
            reason = "入口与服务器分段观测；未测整条业务路径",
            updatedAt = "2026-09-09T12:00:00Z",
            candidates = 2,
            measurements = listOf(
                RouteMeasurement(0, "android-a", "entry", "entry", "2026-09-09T12:00:00Z", "", 12, null, null, 1, 0),
                RouteMeasurement(1, "entry", "exit", "public-hysteria2", "2026-09-09T11:59:00Z", "", 25, 7, 800_000.0, 3, 0),
                RouteMeasurement(2, "exit", "https://target.example/", "target", "", "", null, null, null, 0, 0),
            ),
        )

        val row = buildRoutePaths(application, mapOf("route:web" to "actual"), listOf(decision)).single()

        assertEquals("本机 → entry → exit → 目标", row.chain)
        assertEquals("ping 12 ms", row.links[0].label)
        assertEquals("25 ms · Δ7 ms · 800.0 kb/s", row.links[1].label)
        assertEquals("—", row.links[2].label)
        assertTrue(row.links[1].detail.contains("服务器公网 Hy2 单跳"))
        assertFalse(row.reason.contains("P50"))
    }

    @Test
    fun directPathDoesNotInventLinkMeasurements() {
        val application = AppliedRoute(
            planScope = "scope",
            mode = RouteMode.DIRECT,
            exit = "",
            blocked = false,
            blockReason = "",
            directAvailable = true,
            exits = emptyList(),
            selectors = listOf(AppliedSelector("route:web", "direct", emptyList())),
        )

        val row = buildRoutePaths(application, mapOf("route:web" to "direct"), emptyList()).single()

        assertEquals("本机 → 目标（直连）", row.chain)
        assertTrue(row.links.isEmpty())
        assertTrue(row.reason.contains("不执行完整路径测量"))
    }
}
