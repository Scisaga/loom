package io.github.scisaga.loom

import io.github.scisaga.loom.route.RouteLinkStatus
import io.github.scisaga.loom.route.RoutePathStatus
import org.junit.Assert.assertEquals
import org.junit.Test

class RoutePathPresentationTest {
    @Test
    fun identicalActualPathsCollapseWithoutDroppingEvidenceCounts() {
        val paths = listOf(
            path("decl:best-egress", "candidate-a", "本机 → demo-a → 目标", listOf("12 ms", "—")),
            path("svc:web", "candidate-c", "本机 → demo-a → 目标", listOf("13 ms")),
            path("svc:api", "candidate-a", "本机 → demo-a → 目标", emptyList()),
            path("svc:other", "candidate-b", "本机 → demo-b → 目标", emptyList()),
        )

        val summaries = summarizeRoutePaths(paths)

        assertEquals(2, summaries.size)
        assertEquals("best-egress、web 等 3 项", summaries[0].servicesLabel)
        assertEquals("分段证据 2/3 · 缺失保持未知", summaries[0].evidenceLabel)
        assertEquals("other", summaries[1].servicesLabel)
        assertEquals("分段证据尚未就绪", summaries[1].evidenceLabel)
    }

    @Test
    fun directSummaryDoesNotDescribeMissingMeasurementsAsFailure() {
        val summary = summarizeRoutePaths(
            listOf(path("route:web", "direct", "本机 → 目标（直连）", emptyList())),
        ).single()

        assertEquals("web", summary.servicesLabel)
        assertEquals("Direct 不执行路径测量", summary.evidenceLabel)
    }

    private fun path(
        service: String,
        candidate: String,
        chain: String,
        labels: List<String>,
    ) = RoutePathStatus(
        service = service,
        candidate = candidate,
        chain = chain,
        links = labels.mapIndexed { index, label ->
            RouteLinkStatus("demo-$index", "demo-${index + 1}", label, "示例证据")
        },
        reason = "示例原因",
        updatedAt = "",
    )
}
