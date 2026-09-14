package io.github.scisaga.loom

import io.github.scisaga.loom.route.RoutePathStatus

internal data class RoutePathSummary(
    val servicesLabel: String,
    val chain: String,
    val evidenceLabel: String,
)

private data class RoutePathSummaryKey(
    val chain: String,
)

/** 窄屏首页只合并展示相同实际 chain；逐声明候选和证据仍保留在详情层。 */
internal fun summarizeRoutePaths(paths: List<RoutePathStatus>): List<RoutePathSummary> = paths
    .groupBy { RoutePathSummaryKey(it.chain) }
    .map { (key, groupedPaths) ->
        val services = groupedPaths.map { displayRouteService(it.service) }.distinct()
        val totalEvidence = groupedPaths.sumOf { it.links.size }
        val knownEvidence = groupedPaths.sumOf { path -> path.links.count { it.label != "—" } }
        val allDirect = groupedPaths.all { it.candidate == "direct" }
        RoutePathSummary(
            servicesLabel = when {
                services.isEmpty() -> "未命名规则"
                services.size <= 2 -> services.joinToString("、")
                else -> "${services.take(2).joinToString("、")} 等 ${services.size} 项"
            },
            chain = key.chain,
            evidenceLabel = when {
                allDirect -> "Direct 不执行路径测量"
                totalEvidence == 0 -> "分段证据尚未就绪"
                knownEvidence == totalEvidence -> "分段证据 $knownEvidence/$totalEvidence"
                else -> "分段证据 $knownEvidence/$totalEvidence · 缺失保持未知"
            },
        )
    }

internal fun displayRouteService(service: String): String = when {
    service.startsWith("decl:") -> service.removePrefix("decl:")
    service.startsWith("svc:") -> service.removePrefix("svc:")
    service.startsWith("route:") -> service.removePrefix("route:")
    else -> service
}
