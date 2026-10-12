package io.github.scisaga.loom.route

import java.time.Instant

/** A disposable UI projection of an original business sample; never persisted. */
data class RouteBusinessStatus(
    val scope: String,
    val target: String,
    val candidate: String = "",
    val networkGeneration: String = "",
    val result: String = "unknown",
    val observedAt: String = "",
    val validUntil: String = "",
    val metricMillis: Long? = null,
    val current: Boolean = false,
)

internal fun RouteBusinessStatus.currentAt(now: Instant): Boolean = current && runCatching {
    val sampled = Instant.parse(observedAt)
    val expiry = Instant.parse(validUntil)
    !sampled.isAfter(now) && expiry.isAfter(now) && expiry.isAfter(sampled)
}.getOrDefault(false)

internal fun projectBusinessEvidence(
    targets: Map<String, List<String>>,
    candidates: Map<String, String>,
    selected: Map<String, String>,
    samples: List<RouteBusinessStatus>,
    generation: String,
    now: Instant,
    running: Boolean,
): List<RouteBusinessStatus> = targets.toSortedMap().flatMap { (scope, urls) ->
    urls.distinct().sorted().map { target ->
        val matching = samples.filter { sample ->
            sample.scope == scope && sample.target == target && sample.networkGeneration == generation &&
                candidates[sample.candidate] == scope && sample.result in setOf("available", "unavailable") &&
                (sample.metricMillis == null || sample.metricMillis >= 0) && runCatching {
                    val observed = Instant.parse(sample.observedAt)
                    val expiry = Instant.parse(sample.validUntil)
                    !observed.isAfter(now) && expiry.isAfter(observed)
                }.getOrDefault(false)
        }
        val chosen = matching.filter { it.candidate == selected[scope] }.ifEmpty { matching }
        val latest = chosen.maxOfOrNull { Instant.parse(it.observedAt) }
        val sample = chosen.filter { Instant.parse(it.observedAt) == latest }.distinct().singleOrNull()
        sample?.copy(current = running && sample.candidate == selected[scope] && Instant.parse(sample.validUntil).isAfter(now))
            ?: RouteBusinessStatus(scope, target, selected[scope].orEmpty(), generation)
    }
}
