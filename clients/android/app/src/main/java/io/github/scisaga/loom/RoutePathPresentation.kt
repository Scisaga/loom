package io.github.scisaga.loom

import io.github.scisaga.loom.route.RoutePathStatus

internal data class RoutePathSummary(
    val servicesLabel: String,
    val chainLabel: String,
    val stateLabel: String,
)

/** Groups selectors only when their applied, read-back server chain is identical. */
internal fun summarizeRoutePaths(paths: List<RoutePathStatus>): List<RoutePathSummary> = paths
    .groupBy { it.serverChain }
    .map { (serverChain, groupedPaths) ->
        val services = groupedPaths.map { displayRouteService(it.service) }.distinct()
        val states = groupedPaths.map { displayRouteState(it.state) }.distinct()
        RoutePathSummary(
            servicesLabel = when {
                services.isEmpty() -> "未命名服务"
                services.size <= 2 -> services.joinToString("、")
                else -> "${services.take(2).joinToString("、")} 等 ${services.size} 项"
            },
            chainLabel = displayRouteChain(serverChain),
            stateLabel = "业务结果：${states.joinToString(" / ")}",
        )
    }

internal fun displayRouteChain(serverChain: List<String>): String = if (serverChain.isEmpty()) {
    "本机 → 目标地址（Direct）"
} else {
    (listOf("本机") + serverChain + "目标地址").joinToString(" → ")
}

internal fun displayRouteService(service: String): String = when {
    service.startsWith("decl:") -> service.removePrefix("decl:")
    service.startsWith("svc:") -> service.removePrefix("svc:")
    service.startsWith("route:") -> service.removePrefix("route:")
    service.isBlank() -> "未命名服务"
    else -> service
}

internal fun displayRouteCandidate(candidate: String): String = candidate
    .removePrefix("cand:")
    .ifBlank { "Direct" }

internal fun displayRouteState(state: String): String = when (state) {
    "available" -> "可用"
    "unavailable" -> "不可用"
    "unknown" -> "未知"
    else -> "未知"
}
