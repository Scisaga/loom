package io.github.scisaga.loom.enrollment

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
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
}
