package io.github.scisaga.loom.route

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Instant

class BusinessEvidencePresentationTest {
    private val now = Instant.parse("2030-01-01T00:00:20Z")
    private val targets = mapOf("service:demo-a" to listOf("https://web.example/"), "service:demo-b" to listOf("https://api.example/"))
    private val candidates = mapOf("demo-a" to "service:demo-a", "demo-b" to "service:demo-b")
    private fun sample(candidate: String, result: String) = RouteBusinessStatus(
        scope = candidates.getValue(candidate),
        target = targets.getValue(candidates.getValue(candidate)).single(),
        candidate = candidate,
        networkGeneration = "demo-network",
        result = result,
        observedAt = "2030-01-01T00:00:00Z",
        validUntil = "2030-01-01T00:00:30Z",
        metricMillis = if (result == "available") 123 else null,
    )

    @Test
    fun failedScopeRetainsOriginalEvidenceWhileOtherSelectedServiceWorks() {
        val values = projectBusinessEvidence(targets, candidates, mapOf("service:demo-a" to "demo-a"),
            listOf(sample("demo-a", "available"), sample("demo-b", "unavailable")), "demo-network", now, true)
        assertEquals(2, values.size)
        assertTrue(values[0].current)
        assertTrue(values[0].currentAt(now))
        assertFalse(values[0].currentAt(Instant.parse(values[0].validUntil)))
        assertEquals(123L, values[0].metricMillis)
        assertEquals("unavailable", values[1].result)
        assertEquals("2030-01-01T00:00:00Z", values[1].observedAt)
        assertEquals("2030-01-01T00:00:30Z", values[1].validUntil)
        assertFalse(values[1].current)
    }

    @Test
    fun missingExpiredForeignOrRevokedSamplesCannotCreateCurrentSuccess() {
        val selected = mapOf("service:demo-a" to "demo-a", "service:demo-b" to "demo-b")
        val a = sample("demo-a", "available")
        for (rows in listOf(emptyList(), listOf(a.copy(target = "https://other.example/")),
            listOf(a.copy(networkGeneration = "demo-other")), listOf(a.copy(candidate = "demo-revoked")),
            listOf(a.copy(observedAt = "2030-01-01T00:00:21Z")), listOf(a.copy(validUntil = now.toString())))) {
            val values = projectBusinessEvidence(targets, candidates, selected, rows, "demo-network", now, true)
            assertFalse(values.any { it.current })
            assertEquals("unknown", values[1].result)
        }
        val stopped = projectBusinessEvidence(targets, candidates, selected, listOf(a), "demo-network", now, false)
        assertFalse(stopped.any { it.current })
        assertEquals(a.observedAt, stopped[0].observedAt)
    }

    @Test
    fun selectedCandidateHasPriorityAndAmbiguousSameTimeDoesNotChooseWinner() {
        val alternate = candidates + ("demo-alt" to "service:demo-a")
        val a = sample("demo-a", "available")
        val newer = a.copy(candidate = "demo-alt", result = "unavailable", observedAt = "2030-01-01T00:00:10Z", metricMillis = null)
        val selected = projectBusinessEvidence(targets, alternate, mapOf("service:demo-a" to "demo-a"),
            listOf(newer, a), "demo-network", now, true)
        assertEquals(a.candidate, selected[0].candidate)
        assertTrue(selected[0].current)
        val conflict = projectBusinessEvidence(targets, alternate, emptyMap(), listOf(a, a.copy(result = "unavailable", metricMillis = null)), "demo-network", now, true)
        assertEquals("unknown", conflict[0].result)
        assertFalse(conflict[0].current)
        assertEquals(selected, projectBusinessEvidence(targets.toSortedMap(compareByDescending { it }), alternate, mapOf("service:demo-a" to "demo-a"), listOf(a, newer), "demo-network", now, true))
    }
}
