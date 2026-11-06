package io.github.scisaga.loom.route

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SelectorReadbackTest {
    @Test
    fun sameCandidateDoesNotConfirmDifferentPolicyTargetOrConnectionContext() {
        val context = mapOf("entry_node_id" to "demo-entry", "first_resource_id" to "demo-wg", "final_exit" to "demo-exit")
        val choice = mapOf("demo-candidate" to context)
        val targets = mapOf("example.com:443" to "demo-candidate")
        val route = AppliedRoute(mapOf("demo-service" to "demo-policy"), listOf(
            AppliedSelector("access", "demo-candidate", listOf("demo-entry", "demo-exit"), "demo-exit",
                targets = targets, policyID = "demo-policy", choices = choice),
        ))
        val candidates = mapOf("access" to "demo-candidate")
        assertTrue(route.matchesReadback(candidates, mapOf("access" to targets), mapOf("access" to "demo-policy"), mapOf("access" to choice)))
        assertFalse(route.matchesReadback(candidates, mapOf("access" to emptyMap()), mapOf("access" to "demo-policy"), mapOf("access" to choice)))
        assertFalse(route.matchesReadback(candidates, mapOf("access" to targets), mapOf("access" to "demo-old-policy"), mapOf("access" to choice)))
        val differentExit = mapOf("demo-candidate" to (context + ("final_exit" to "demo-other-exit")))
        assertFalse(route.matchesReadback(candidates, mapOf("access" to targets), mapOf("access" to "demo-policy"),
            mapOf("access" to differentExit)))
    }

    @Test
    fun partialApplicationCannotConfirmInternetAndLanTogether() {
        val route = AppliedRoute(emptyMap(), emptyList(), blockedScopes = listOf("access", "local_network:demo-lan"))
        assertFalse(route.matchesReadback(mapOf("access" to "reject"), mapOf("access" to emptyMap()),
            mapOf("access" to ""), mapOf("access" to emptyMap())))
        val scopes = route.execution().map { it.selector }
        assertTrue(route.matchesReadback(scopes.associateWith { "reject" }, scopes.associateWith { emptyMap() },
            scopes.associateWith { "" }, scopes.associateWith { emptyMap() }))
    }

    @Test
    fun appliedRejectCannotCompleteStartupForSelectedInternetPolicy() {
        val route = AppliedRoute(mapOf("demo-service" to "demo-policy"), emptyList(), blockedScopes = listOf("access"))
        assertTrue(route.matchesReadback(mapOf("access" to "reject"), mapOf("access" to emptyMap()),
            mapOf("access" to ""), mapOf("access" to emptyMap())))
        assertFalse(route.hasInitialSelection("demo-policy", mapOf("access" to "reject"), mapOf("access" to emptyMap()),
            mapOf("access" to ""), mapOf("access" to emptyMap())))
    }

    @Test
    fun firstDefaultPathNeedsItsFullPolicyReadbackButNoBusinessSamplesOrOtherCandidates() {
        val context = mapOf("entry_node_id" to "demo-entry", "first_resource_id" to "demo-wg", "final_exit" to "demo-exit")
        val choices = mapOf("demo-candidate" to context)
        val route = AppliedRoute(mapOf("demo-service" to "demo-policy"), listOf(
            AppliedSelector("access", "demo-candidate", listOf("demo-entry"), "demo-exit", policyID = "demo-policy", choices = choices),
        ), blockedScopes = listOf("local_network:demo-lan"))
        val candidates = mapOf("access" to "demo-candidate", "local_network:demo-lan" to "reject")
        val targets = candidates.keys.associateWith { emptyMap<String, String>() }
        val policies = mapOf("access" to "demo-policy", "local_network:demo-lan" to "")
        val actualChoices = mapOf("access" to choices, "local_network:demo-lan" to emptyMap())
        assertTrue(route.hasInitialSelection("demo-policy", candidates, targets, policies, actualChoices))
        // A→B→A can restore the same preference while a native write is still
        // unconfirmed. The old matching A readback must not publish CONNECTED.
        assertFalse(route.hasInitialSelection("demo-policy", candidates, targets, policies, actualChoices, selectionInFlight = true))
        // A new network generation or changed retained execution clears the
        // old actual proof. The retained application alone cannot be ready.
        assertFalse(route.hasInitialSelection("demo-policy", emptyMap(), emptyMap(), emptyMap(), emptyMap()))
        assertFalse(route.hasInitialSelection("demo-other-policy", candidates, targets, policies, actualChoices))
        assertFalse(route.hasInitialSelection("demo-policy", candidates, targets,
            policies + ("access" to "demo-old-policy"), actualChoices))
        assertFalse(route.hasInitialSelection("demo-policy", candidates, targets, policies,
            actualChoices + ("access" to emptyMap())))
    }

    @Test
    fun waitingInternetPreferenceAndIndependentLanDoNotRequireAnInternetPath() {
        val route = AppliedRoute(mapOf("demo-lan" to "demo-lan-policy"), emptyList(),
            blockedScopes = listOf("access", "local_network:demo-lan"))
        val scopes = route.execution().map { it.selector }
        assertTrue(route.hasInitialSelection("", scopes.associateWith { "reject" },
            scopes.associateWith { emptyMap() }, scopes.associateWith { "" }, scopes.associateWith { emptyMap() }))
        assertFalse(route.hasInitialSelection("", emptyMap(), emptyMap(), emptyMap(), emptyMap()))
        assertFalse(AppliedRoute(emptyMap(), emptyList()).hasInitialSelection("", emptyMap(), emptyMap(), emptyMap(), emptyMap()))
        assertTrue(AppliedRoute(emptyMap(), emptyList()).hasInitialSelection("", emptyMap(), emptyMap(), emptyMap(), emptyMap(), accessScopeExpected = false))
    }
}
