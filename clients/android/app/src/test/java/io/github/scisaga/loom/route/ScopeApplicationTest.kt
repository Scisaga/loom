package io.github.scisaga.loom.route

import io.github.scisaga.loom.vpn.ConnectionPhase
import io.github.scisaga.loom.vpn.confirmInitialSelection
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.sync.Mutex
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ScopeApplicationTest {
    @Test
    fun reportKeepsOnlyTheIndependentlyConfirmedScopeDuringAnotherScopeCAS() {
        val access = AppliedSelector("access", "demo-access", emptyList(), "demo-exit", policyID = "demo-internet-policy")
        val lan = AppliedSelector("local_network:demo-lan", "demo-lan", emptyList(), "demo-gateway", policyID = "demo-lan-policy")
        val route = AppliedRoute(emptyMap(), listOf(access, lan))
        val candidates = mapOf(access.selector to access.candidate, lan.selector to lan.candidate)
        val policies = mapOf(access.selector to access.policyID, lan.selector to lan.policyID)
        val targets = candidates.mapValues { emptyMap<String, String>() }
        val choices = candidates.mapValues { emptyMap<String, Map<String, String>>() }
        val revisions = candidates.mapValues { "demo-revision" }
        fun report(pending: Set<String>, actualPolicies: Map<String, String> = policies,
            actualTargets: Map<String, Map<String, String>> = targets,
            actualChoices: Map<String, RouteChoices> = choices,
            actualRevisions: Map<String, String> = revisions) = route.confirmedReportSelectors(
                policies, pending, candidates, actualTargets, actualPolicies, actualChoices, actualRevisions)
        assertTrue(report(candidates.keys).isEmpty())
        assertEquals(listOf(access), report(setOf(lan.selector)))
        assertEquals(listOf(lan), report(setOf(access.selector)))
        assertEquals(listOf(access, lan), report(emptySet()))
        assertTrue(report(setOf(lan.selector), policies + (access.selector to "demo-old-policy")).isEmpty())
        assertTrue(report(setOf(lan.selector), actualTargets = targets + (access.selector to mapOf("demo-target" to "demo-stale"))).isEmpty())
        assertTrue(report(setOf(lan.selector), actualChoices = choices + (access.selector to mapOf("demo-stale" to emptyMap()))).isEmpty())
        assertTrue(report(setOf(lan.selector), actualRevisions = revisions - access.selector).isEmpty())
        assertFalse(route.hasCompleteReadback(candidates.keys, candidates - lan.selector,
            targets, policies, choices))
    }

    @Test
    fun accessReadPrepareCasAndReadbackFinishBeforeLanInitialGetReturns() = runBlocking {
        val scopes = SelectorCallScopes().apply { plan(listOf("access", "local_network:demo-lan")) }
        val lanReading = CompletableDeferred<Unit>()
        val releaseLan = CompletableDeferred<Unit>()
        val steps = mutableListOf<String>()
        var phase = ConnectionPhase.STARTING
        val lifecycle = Mutex()
        val call = async {
            applyScopesIndependently(listOf("local_network:demo-lan", "access"), apply = { scope ->
                if (scope != "access") { lanReading.complete(Unit); releaseLan.await() }
                steps += "$scope GET"
                steps += "$scope prepare"
                scopes.wrote(scope)
                steps += "$scope CAS"
                steps += "$scope readback"
                scopes.confirmed(scope)
                if (scope == "access") {
                    val choices = mapOf("demo-candidate" to mapOf("entry_node_id" to "demo-entry",
                        "first_resource_id" to "demo-wg", "final_exit" to "demo-exit"))
                    val route = AppliedRoute(mapOf("demo-service" to "demo-policy"), listOf(
                        AppliedSelector("access", "demo-candidate", listOf("demo-entry"), "demo-exit", policyID = "demo-policy", choices = choices)))
                    confirmInitialSelection(lifecycle, ready = {
                        route.hasInitialSelection("demo-policy", mapOf("access" to "demo-candidate"),
                            mapOf("access" to emptyMap()), mapOf("access" to "demo-policy"), mapOf("access" to choices),
                            selectionInFlight = scopes.mayWrite("access"))
                    }, isCurrent = { phase == ConnectionPhase.STARTING }, connected = { phase = ConnectionPhase.CONNECTED })
                }
            }, failed = { _, error -> throw error })
        }
        withTimeout(1_000) { lanReading.await() }
        assertEquals(listOf("access GET", "access prepare", "access CAS", "access readback"), steps)
        assertEquals(ConnectionPhase.CONNECTED, phase)
        assertFalse(scopes.mayWrite("access"))
        assertTrue(scopes.mayWrite("local_network:demo-lan"))
        releaseLan.complete(Unit)
        call.await()
    }

    @Test
    fun partialIoFailureDoesNotDiscardSuccessfulScopeOrSkipLaterScope() = runBlocking {
        val all = setOf("access", "local_network:demo-lan-1", "local_network:demo-lan-2")
        for (pending in listOf("access", "local_network:demo-lan-1")) {
            val confirmed = mutableSetOf<String>()
            val failed = mutableSetOf<String>()
            applyScopesIndependently(all.reversed(), apply = {
                if (it == pending) throw RuntimeResourcesPending()
                confirmed += it
            }, failed = { scope, error ->
                assertTrue(error is RuntimeResourcesPending)
                failed += scope
            })
            assertEquals(all - pending, confirmed)
            assertEquals(setOf(pending), failed)
        }
    }

    @Test
    fun cancellationInvalidatesOnlyUnconfirmedWritesAndDoesNotBecomeNetworkFailure() = runBlocking {
        val scopes = SelectorCallScopes().apply { plan(listOf("access", "local_network:demo-lan-1", "local_network:demo-lan-2")) }
        var failures = 0
        var cancelled = false
        try {
            applyScopesIndependently(listOf("access", "local_network:demo-lan-1", "local_network:demo-lan-2"), apply = {
                scopes.wrote(it)
                if (it != "access") throw CancellationException("demo cancel")
                scopes.confirmed(it)
            }, failed = { _, _ -> failures++ })
        } catch (_: CancellationException) { cancelled = true }
        assertTrue(cancelled)
        assertEquals(0, failures)
        assertEquals(setOf("local_network:demo-lan-1"), scopes.uncertain())
        assertFalse(scopes.mayWrite("access"))
        assertTrue(scopes.mayWrite("local_network:demo-lan-2"))
    }

    @Test
    fun newSameScopeAttemptFencesOldReadbackEvenWhenSelectionReturnsToSameValue() {
        val scopes = SelectorCallScopes()
        scopes.plan(listOf("access")); scopes.wrote("access"); scopes.confirmed("access")
        assertFalse(scopes.mayWrite("access"))
        scopes.plan(listOf("access"))
        assertTrue(scopes.mayWrite("access"))
        assertTrue(scopes.uncertain().isEmpty())
    }

    @Test
    fun endingLocalReadFailureDoesNotInventAWriteOrHoldAccessBehindLan() {
        val scopes = SelectorCallScopes()
        scopes.plan(listOf("access", "local_network:demo-lan"))
        scopes.finished("access")
        assertFalse(scopes.mayWrite("access"))
        assertTrue(scopes.mayWrite("local_network:demo-lan"))
        assertTrue(scopes.uncertain().isEmpty())
    }

    @Test
    fun onlyConfirmedScopeMemoryIsMergedAndPartialReadbackIsNotWholeApplicationProof() {
        val confirmations = mutableListOf<String>()
        val memory = confirmScopeMemory(mapOf("access" to "old-access", "local_network:demo-lan" to "old-lan"),
            mapOf("access" to "new-access", "local_network:demo-lan" to "unapplied-lan"), listOf("access")) { scope, proposal ->
            confirmations += scope
            "$proposal-confirmed"
        }
        assertEquals(listOf("access"), confirmations)
        assertEquals("new-access-confirmed", memory["access"])
        assertEquals("old-lan", memory["local_network:demo-lan"])
        val route = AppliedRoute(emptyMap(), emptyList(), blockedScopes = listOf("access"))
        val candidates = mapOf("access" to "reject")
        val targets = mapOf("access" to emptyMap<String, String>())
        val policies = mapOf("access" to "")
        val choices = mapOf("access" to emptyMap<String, Map<String, String>>())
        assertTrue(route.matchesReadback(candidates, targets, policies, choices))
        assertFalse(route.hasCompleteReadback(setOf("access", "local_network:demo-lan"), candidates, targets, policies, choices))
        assertTrue(route.hasCompleteReadback(setOf("access"), candidates, targets, policies, choices))
    }

    @Test
    fun permissionAndSupersessionErrorsAreNotResourcePending() = runBlocking {
        for (error in listOf(IllegalStateException("demo permission"), SelectionSuperseded())) {
            var failures = 0
            var caught = false
            try {
                applyScopesIndependently(listOf("access"), apply = { throw error }, failed = { _, _ -> failures++ })
            } catch (actual: IllegalStateException) { caught = actual === error }
            assertTrue(caught)
            assertEquals(0, failures)
        }
    }
}
