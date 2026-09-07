package io.github.scisaga.loom.enrollment

import java.time.Instant
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class EnrollmentWindowTest {
    private val expiry = Instant.parse("2026-09-07T12:00:00Z")

    @Test
    fun firstUseMustPrecedeInviteExpiry() {
        assertTrue(
            enrollmentAttemptWindow(expiry.toString(), null, expiry.minusMillis(1)).markFirstAttempt,
        )
        assertThrows(IllegalStateException::class.java) {
            enrollmentAttemptWindow(expiry.toString(), null, expiry)
        }
    }

    @Test
    fun persistedAttemptGetsOnlyOneHourRecoveryWindow() {
        val firstAttempt = expiry.minusSeconds(30).toString()
        assertFalse(
            enrollmentAttemptWindow(expiry.toString(), firstAttempt, expiry.plusSeconds(3_599)).markFirstAttempt,
        )
        assertThrows(IllegalStateException::class.java) {
            enrollmentAttemptWindow(expiry.toString(), firstAttempt, expiry.plusSeconds(3_600))
        }
    }

    @Test
    fun persistedFirstAttemptMustItselfPrecedeExpiry() {
        assertThrows(IllegalStateException::class.java) {
            enrollmentAttemptWindow(expiry.toString(), expiry.toString(), expiry.minusSeconds(1))
        }
    }
}
