package io.github.scisaga.loom.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class UnderlyingNetworkSelectionTest {
    @Test
    fun stableSelectionRetainsCurrentCandidateAtEqualRank() {
        val candidates = listOf(
            RankedUnderlying("wifi-a", 1_013, "100"),
            RankedUnderlying("wifi-b", 1_013, "200"),
        )

        assertEquals("wifi-b", selectStableUnderlying(candidates, "wifi-b"))
        assertEquals("wifi-a", selectStableUnderlying(candidates, null))
    }

    @Test
    fun validatedNetworkOutranksUnvalidatedTransportPreference() {
        val cellular = underlyingNetworkRank(
            validated = true,
            notSuspended = true,
            unmetered = false,
            transportPriority = 2,
        )
        val wifi = underlyingNetworkRank(
            validated = false,
            notSuspended = true,
            unmetered = true,
            transportPriority = 3,
        )

        assertTrue(checkNotNull(cellular) > checkNotNull(wifi))
    }

    @Test
    fun suspendedNetworkIsNotACandidate() {
        assertNull(
            underlyingNetworkRank(
                validated = true,
                notSuspended = false,
                unmetered = true,
                transportPriority = 4,
            ),
        )
    }

    @Test
    fun builderBindingSuppressesDuplicateRuntimePublishAndTracksRemoval() {
        val tracker = UnderlyingPublicationTracker<String>()
        tracker.builderBound("wifi")

        assertFalse(tracker.needsRuntimePublish("wifi"))
        assertTrue(tracker.needsRuntimePublish(null))
        tracker.runtimePublished(null)
        assertFalse(tracker.needsRuntimePublish(null))
    }
}
