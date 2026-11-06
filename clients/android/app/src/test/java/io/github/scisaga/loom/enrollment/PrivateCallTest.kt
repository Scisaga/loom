package io.github.scisaga.loom.enrollment

import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

class PrivateCallTest {
    @Test
    fun cancellationReleasesTheBlockedPrivateRequest() = runBlocking {
        val entered = CountDownLatch(1)
        val released = CountDownLatch(1)
        val call = launch {
            privateCall(
                run = {
                    entered.countDown()
                    check(released.await(30, TimeUnit.SECONDS)) { "private call reached its network timeout" }
                },
                cancel = { released.countDown() },
            )
        }
        withContext(Dispatchers.IO) { assertTrue(entered.await(5, TimeUnit.SECONDS)) }
        withTimeout(5_000) { call.cancelAndJoin() }
        assertTrue(released.count == 0L)
    }

    @Test
    fun cancellationAlsoReleasesAMeasurementCallbackWaitingToCommit() = runBlocking {
        val operation = Mutex(locked = true)
        val entered = CountDownLatch(1)
        val cancelled = AtomicBoolean(false)
        val applied = AtomicBoolean(false)
        val call = launch {
            val owner = currentCoroutineContext()
            privateCall(
                run = {
                    // Same ownership as a synchronous Go completion callback:
                    // cancelling the VPN also cancels its suspended commit.
                    runBlocking(owner) {
                        entered.countDown()
                        operation.withLock { applied.set(true) }
                    }
                },
                cancel = { cancelled.set(true) },
            )
        }
        try {
            withContext(Dispatchers.IO) { assertTrue(entered.await(5, TimeUnit.SECONDS)) }
            withTimeout(5_000) { call.cancelAndJoin() }
            assertTrue(cancelled.get())
            assertTrue(!applied.get())
        } finally {
            operation.unlock()
        }
    }
}
