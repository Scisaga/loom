package io.github.scisaga.loom.enrollment

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class V2PendingEnrollmentInstrumentedTest {
    @Test
    fun stableCoordinatesAndAttemptJournalSurviveExactReplay() {
        val descriptor = """{"bootstrap_tunnel_capability":{"capability_id":"capability-1"}}"""
            .encodeToByteArray()
        val initial = V2PendingEnrollment(
            descriptor = descriptor,
            proofBundle = "{}".encodeToByteArray(),
            bootstrapCatalog = "{}".encodeToByteArray(),
        )
        val coordinates = initial.withStableCoordinates()
        val preflight = "{\"schema\":1}".encodeToByteArray()
        val core = "{\"schema\":2}".encodeToByteArray()
        val selection = "{\"transport\":\"hysteria2\"}".encodeToByteArray()
        val persisted = coordinates
            .withSelection("network-1", selection)
            .withPreflight(preflight)
            .withClaimCore(core)
            .advanceAttempt("capability-1", 1)
        val replay = V2PendingEnrollment.decode(persisted.encode())

        assertEquals(coordinates.requestID, replay.requestID)
        assertArrayEquals(coordinates.clientNonce, replay.clientNonce)
        assertArrayEquals(core, replay.claimCore)
        assertEquals("network-1", replay.selectedUnderlay)
        assertArrayEquals(selection, replay.selectedTransport)
        assertEquals(1L, replay.connectionAttempts)
        assertThrows(IllegalStateException::class.java) {
            replay.advanceAttempt("capability-1", 3)
        }
        assertThrows(IllegalStateException::class.java) {
            replay.advanceAttempt("other-capability", 2)
        }
        assertThrows(IllegalStateException::class.java) {
            replay.withClaimCore("{\"schema\":3}".encodeToByteArray())
        }
        assertThrows(IllegalStateException::class.java) {
            replay.withConnectionAttempts(0)
        }
        assertThrows(IllegalStateException::class.java) {
            replay.withSelection("network-1", "{\"transport\":\"trojan_tls\"}".encodeToByteArray())
        }
        assertArrayEquals(
            "{\"transport\":\"trojan_tls\"}".encodeToByteArray(),
            replay.withSelection("network-2", "{\"transport\":\"trojan_tls\"}".encodeToByteArray())
                .selectedTransport,
        )
    }
}
