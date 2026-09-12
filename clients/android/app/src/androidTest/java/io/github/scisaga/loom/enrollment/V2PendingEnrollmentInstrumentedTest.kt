package io.github.scisaga.loom.enrollment

import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assume.assumeTrue
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

    @Test
    fun resumeAttemptJournalIsIndependentAndDurable() {
        val pending = V2PendingEnrollment(
            descriptor = """{"bootstrap_tunnel_capability":{"capability_id":"initial-1"}}"""
                .encodeToByteArray(),
            proofBundle = "{}".encodeToByteArray(),
            bootstrapCatalog = "{}".encodeToByteArray(),
            preflightResponse = "{}".encodeToByteArray(),
            requestID = "request-1",
            clientNonce = ByteArray(32),
            claimCore = "{}".encodeToByteArray(),
            claimResult = """{"status":"reserved"}""".encodeToByteArray(),
            progressStatus = "reserved",
            resumeExpected = "{}".encodeToByteArray(),
            resumeDescriptor = """{"resume_tunnel_capability":{"capability_id":"resume-1"}}"""
                .encodeToByteArray(),
            resumeProofBundle = "{}".encodeToByteArray(),
            resumeBootstrapCatalog = "{}".encodeToByteArray(),
        )
            .advanceAttempt("initial-1", 1)
            .advanceAttempt("resume-1", 1)
            .withResumeSelection("network-1", "{}".encodeToByteArray())
        val replay = V2PendingEnrollment.decode(pending.encode())

        assertEquals(1L, replay.connectionAttempts)
        assertEquals(1L, replay.resumeConnectionAttempts)
        assertEquals("network-1", replay.resumeSelectedUnderlay)
        assertArrayEquals(pending.resumeDescriptor, replay.resumeDescriptor)
        assertThrows(IllegalStateException::class.java) {
            replay.advanceAttempt("resume-1", 3)
        }
        assertThrows(IllegalStateException::class.java) {
            replay.advanceAttempt("unknown", 2)
        }
    }

    @Test
    fun protectedPendingSurvivesStoreRecreationAndRejectsRollback() {
        assumeTrue(Build.HARDWARE == "ranchu" || Build.HARDWARE == "goldfish")
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val store = ManagedProfileStore(context)
        store.clearPending()
        try {
            val pending = V2PendingEnrollment(
                descriptor = """{"bootstrap_tunnel_capability":{"capability_id":"capability-1"}}"""
                    .encodeToByteArray(),
                proofBundle = "{}".encodeToByteArray(),
                bootstrapCatalog = "{}".encodeToByteArray(),
            )
                .withStableCoordinates()
                .withSelection("network-1", "{\"transport\":\"hysteria2\"}".encodeToByteArray())
                .withPreflight("{\"schema\":1}".encodeToByteArray())
                .withClaimCore("{\"schema\":2}".encodeToByteArray())
                .advanceAttempt("capability-1", 1)
            store.putV2Pending(pending)

            val recreated = ManagedProfileStore(context)
            val replay = V2PendingEnrollment.decode(checkNotNull(recreated.pending()))
            assertEquals(pending.requestID, replay.requestID)
            assertArrayEquals(pending.clientNonce, replay.clientNonce)
            assertArrayEquals(pending.claimCore, replay.claimCore)
            assertEquals(1L, replay.connectionAttempts)
            assertThrows(IllegalStateException::class.java) {
                recreated.putV2Pending(replay.copy(connectionAttempts = 0))
            }
            assertThrows(IllegalStateException::class.java) {
                recreated.putV2Pending(replay.copy(claimCore = "{\"schema\":3}".encodeToByteArray()))
            }
            assertArrayEquals(pending.encode(), checkNotNull(recreated.pending()))
        } finally {
            store.clearPending()
        }
    }
}
