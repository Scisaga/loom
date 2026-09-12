package io.github.scisaga.loom.enrollment

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class EnrollmentRecoveryTest {
    @Test
    fun readyRecoveryClearsPendingBeforePull() = runBlocking {
        val events = mutableListOf<String>()

        val resumed = resumeReadyAfterPendingCleanup(
            ready = "validated-ready",
            clearPending = { events += "clear-pending" },
            continuePull = { events += "pull:$it" },
        )

        assertTrue(resumed)
        assertEquals(listOf("clear-pending", "pull:validated-ready"), events)
    }

    @Test
    fun missingReadyLeavesPendingForEnrollmentRetry() = runBlocking {
        val events = mutableListOf<String>()

        val resumed = resumeReadyAfterPendingCleanup<String>(
            ready = null,
            clearPending = { events += "clear-pending" },
            continuePull = { events += "pull:$it" },
        )

        assertFalse(resumed)
        assertTrue(events.isEmpty())
    }

    @Test
    fun activeV2LatchSelectsV2WithoutReadingLegacy() {
        var legacyRead = false

        val selected = selectLatchedRuntime("active", "v2-runtime") {
            legacyRead = true
            "legacy-runtime"
        }

        assertEquals("v2-runtime", selected)
        assertFalse(legacyRead)
    }

    @Test
    fun terminalV2LatchRejectsLegacyFallback() {
        listOf("revoked", "decommissioned").forEach { state ->
            var legacyRead = false

            val error = assertThrows(V2TerminalDeviceException::class.java) {
                selectLatchedRuntime(state, null) {
                    legacyRead = true
                    "legacy-runtime"
                }
            }

            assertEquals(state, error.lifecycleState)
            assertFalse(legacyRead)
        }
    }

    @Test
    fun absentV2LatchCanUseLegacyRuntime() {
        assertEquals("legacy-runtime", selectLatchedRuntime(null, null) { "legacy-runtime" })
    }
}
