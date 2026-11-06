package io.github.scisaga.loom.route

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class BlockedSelectionRecoveryTest {
    @Test
    fun completeRejectStillNeedsLocalReevaluationForCurrentlySelectedScopes() {
        val blocked = AppliedRoute(emptyMap(), emptyList(), blockedScopes = listOf("access", "local_network:demo-lan"))
        val actual = mapOf("access" to "reject", "local_network:demo-lan" to "reject")
        assertTrue(blocked.hasCompleteReadback(actual.keys, actual, actual.keys.associateWith { emptyMap() },
            actual.keys.associateWith { "" }, actual.keys.associateWith { emptyMap() }))
        assertEquals(setOf("access"), blocked.blockedSelectedScopes("demo-policy", emptyMap(), actual))
        assertEquals(setOf("local_network:demo-lan"), blocked.blockedSelectedScopes("", mapOf("demo-lan" to "demo-lan-policy"), actual))
        assertTrue(blocked.blockedSelectedScopes("", emptyMap(), actual).isEmpty())
        assertTrue(blocked.blockedSelectedScopes("demo-policy", emptyMap(), actual + ("access" to "demo-current")).isEmpty())
    }
}
