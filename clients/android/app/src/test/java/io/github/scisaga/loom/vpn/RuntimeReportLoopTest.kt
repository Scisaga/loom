package io.github.scisaga.loom.vpn

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RuntimeReportLoopTest {
    @Test
    fun completedRoundWakesSingleReporterBeforeMinuteAndCoalescesPendingNotifications(): Unit = runBlocking {
        val wakeups = Channel<Unit>(Channel.CONFLATED)
        val firstSending = CompletableDeferred<Unit>()
        val releaseFirst = CompletableDeferred<Unit>()
        val sent = Channel<Pair<Long, Long>?>(Channel.UNLIMITED)
        var sample: Pair<Long, Long>? = null
        var calls = 0
        val starts = mutableListOf<Long>()
        val reporting = async {
            runtimeReportLoop(wakeups, 60_000, 50, elapsedMillis = ::elapsedMillis, current = { true }) {
                starts += elapsedMillis()
                val captured = sample
                calls++
                if (calls == 1) { firstSending.complete(Unit); releaseFirst.await() }
                sent.send(captured)
            }
        }
        firstSending.await()
        val original = 1_893_456_000_123L to 1_893_456_030_123L
        sample = original
        repeat(20) { wakeups.trySend(Unit) }
        releaseFirst.complete(Unit)
        assertNull(withTimeout(1_000) { sent.receive() })
        assertEquals(original, withTimeout(1_000) { sent.receive() })
        assertNull(withTimeoutOrNull(80) { sent.receive() })
        assertEquals(2, calls)
        assertTrue(starts[1] - starts[0] >= 49) // Millisecond clock observation can straddle a boundary.
        assertEquals(original, sample)
        withTimeout(1_000) { reporting.cancelAndJoin() }
    }

    @Test
    fun endedSessionDoesNotSendQueuedNotification(): Unit = runBlocking {
        val wakeups = Channel<Unit>(Channel.CONFLATED)
        val sending = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        var current = true
        var calls = 0
        val reporting = async {
            runtimeReportLoop(wakeups, 60_000, 50, elapsedMillis = ::elapsedMillis, current = { current }) {
                calls++
                sending.complete(Unit)
                release.await()
            }
        }
        sending.await()
        wakeups.trySend(Unit)
        current = false
        release.complete(Unit)
        withTimeout(1_000) { reporting.await() }
        assertEquals(1, calls)
    }

    @Test
    fun acceptedBatchReportsWhileSelectorIsStillWaiting(): Unit = runBlocking {
        val wakeups = Channel<Unit>(Channel.CONFLATED)
        val sent = Channel<Unit>(Channel.UNLIMITED)
        val selectorWaiting = CompletableDeferred<Unit>()
        val releaseSelector = CompletableDeferred<Unit>()
        var calls = 0
        val reporting = async {
            runtimeReportLoop(wakeups, 60_000, 50, elapsedMillis = ::elapsedMillis, current = { true }) {
                calls++
                sent.send(Unit)
            }
        }
        withTimeout(1_000) { sent.receive() }
        val selecting = async {
            wakeups.trySend(Unit)
            selectorWaiting.complete(Unit)
            releaseSelector.await()
        }
        selectorWaiting.await()
        withTimeout(1_000) { sent.receive() }
        assertFalse(selecting.isCompleted)
        assertEquals(2, calls)
        assertNull(withTimeoutOrNull(30) { sent.receive() })
        releaseSelector.complete(Unit)
        selecting.await()
        withTimeout(1_000) { reporting.cancelAndJoin() }
    }

    private fun elapsedMillis(): Long = System.nanoTime() / 1_000_000
}
