package io.github.scisaga.loom.route

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class UnderlayProbeRegistryTest {
    @Test
    fun pendingRoundDoesNotBlockModesAndCancelledWaiterCannotRepeatIt() = runBlocking {
        val application = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        try {
            val registry = UnderlayProbeRegistry(application)
            registry.observeDefaultNetwork("network-1", "wlan0")
            val started = CompletableDeferred<Unit>()
            val finish = CompletableDeferred<Unit>()
            var probes = 0
            val inputs = byteArrayOf(1)
            val first = withTimeout(2_000) {
                registry.beginEntries(inputs, "wlan0", { frozen, _ ->
                    probes++
                    started.complete(Unit)
                    finish.await()
                    frozen
                }, { _, frozen, _ -> frozen })
            }
            inputs[0] = 2
            withTimeout(2_000) { started.await() }
            // 模式已经可以继续生效，唯一测量还被人为挂起；取消 profile 的等待不取消它。
            assertFalse(finish.isCompleted)
            val oldProfile = launch { first.await() }
            oldProfile.cancelAndJoin()
            val second = withTimeout(2_000) {
                registry.beginEntries(byteArrayOf(3), "wlan0", { _, _ -> error("不得重复探测") },
                    { _, frozen, _ -> frozen })
            }
            assertEquals(1, probes)
            assertEquals(1, registry.debugState().activeProbeRounds)
            finish.complete(Unit)
            val measured = withTimeout(2_000) { second.await() }
            assertTrue(measured.reused)
            assertEquals(1.toByte(), measured.entries.single())
            assertTrue(registry.isCurrent(measured.generation))
        } finally {
            application.cancel()
        }
    }

    @Test
    fun networkChangeDiscardsAnUnfinishedOldRoundWithoutWaitingForIt() = runBlocking {
        val application = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        try {
            val registry = UnderlayProbeRegistry(application)
            registry.observeDefaultNetwork("network-1", "wlan0")
            val started = CompletableDeferred<Unit>()
            val neverFinished = CompletableDeferred<Unit>()
            val old = registry.beginEntries(byteArrayOf(1), "wlan0", { _, _ ->
                started.complete(Unit)
                neverFinished.await()
                byteArrayOf(1)
            }, { _, frozen, _ -> frozen })
            withTimeout(2_000) { started.await() }
            withTimeout(2_000) { registry.observeDefaultNetwork("network-2", "rmnet0") }
            assertFalse(registry.isCurrent(old.generation))
            val current = withTimeout(2_000) {
                registry.beginEntries(byteArrayOf(2), "rmnet0", { inputs, _ -> inputs }, { _, frozen, _ -> frozen }).await()
            }
            assertEquals(old.generation + 1, current.generation)
            assertEquals(2.toByte(), current.entries.single())
            assertEquals(1, registry.debugState().activeProbeRounds)
            assertTrue(runCatching { old.await() }.isFailure)
        } finally {
            application.cancel()
        }
    }

    @Test
    fun profileConfigAndReconnectReuseOneMeasurement() = runBlocking {
        val registry = UnderlayProbeRegistry()
        assertTrue(registry.observeDefaultNetwork("network-1", "wlan0"))
        var probes = 0
        suspend fun measure(inputs: ByteArray, source: String): ByteArray {
            probes++
            return "measured:${inputs.decodeToString()}:$source".encodeToByteArray()
        }
        fun reuse(inputs: ByteArray, frozen: ByteArray, source: String): ByteArray =
            "reused:${inputs.decodeToString()}:${frozen.decodeToString()}:$source".encodeToByteArray()

        val first = registry.beginEntries("config-a".encodeToByteArray(), "wlan0", ::measure, ::reuse).await()
        assertFalse(first.reused)
        val firstDebug = registry.debugState()
        assertEquals(64, firstDebug.frozenFingerprint.length)
        // 同代 profile/config/reconnect 不得清空，也不得主动测新增 candidate。
        assertFalse(registry.observeDefaultNetwork("network-1", "wlan0"))
        val second = registry.beginEntries("config-b".encodeToByteArray(), "wlan0", ::measure, ::reuse).await()
        assertTrue(second.reused)
        assertEquals(1, probes)
        assertTrue(second.entries.decodeToString().startsWith("reused:config-b:measured:config-a"))
        assertEquals(firstDebug, registry.debugState())
    }

    @Test
    fun confirmedDefaultNetworkChangeCreatesExactlyOneNewGeneration() = runBlocking {
        val registry = UnderlayProbeRegistry()
        var probes = 0
        suspend fun measure(inputs: ByteArray, source: String): ByteArray {
            probes++
            return "$source:${inputs.decodeToString()}".encodeToByteArray()
        }
        val reuse = { _: ByteArray, frozen: ByteArray, _: String -> frozen }

        registry.observeDefaultNetwork("network-1", "wlan0")
        val first = registry.beginEntries(byteArrayOf(1), "wlan0", ::measure, reuse).await()
        registry.observeDefaultNetwork("network-2", "rmnet0")
        assertTrue(registry.debugState().frozenFingerprint.isEmpty())
        val second = registry.beginEntries(byteArrayOf(2), "rmnet0", ::measure, reuse).await()
        assertEquals(2, probes)
        assertEquals(first.generation + 1, second.generation)
        assertEquals(second.generation, registry.debugState().generation)
        assertEquals(1, registry.debugState().activeProbeRounds)
        assertTrue(registry.debugState().frozenFingerprint.isNotEmpty())
    }

    @Test
    fun failedFirstRoundStillConsumesGenerationBudget() = runBlocking {
        val registry = UnderlayProbeRegistry()
        registry.observeDefaultNetwork("network-1", "wlan0")
        var attempts = 0
        val measure = { _: ByteArray, _: String ->
            attempts++
            error("synthetic measurement failure")
        }
        val reuse = { _: ByteArray, frozen: ByteArray, _: String -> frozen }

        assertTrue(runCatching { registry.beginEntries(byteArrayOf(1), "wlan0", measure, reuse).await() }.isFailure)
        assertTrue(runCatching { registry.beginEntries(byteArrayOf(1), "wlan0", measure, reuse).await() }.isFailure)
        assertEquals(1, attempts)
        assertEquals(1, registry.debugState().activeProbeRounds)
        assertTrue(registry.debugState().frozenFingerprint.isEmpty())
    }

    @Test
    fun missingSourceDoesNotConsumeProbeBudget() = runBlocking {
        val registry = UnderlayProbeRegistry()
        registry.observeDefaultNetwork(null, "")
        var probes = 0
        val failed = runCatching {
            registry.beginEntries(byteArrayOf(1), "", { _, _ -> probes++; byteArrayOf() }, { _, old, _ -> old }).await()
        }
        assertTrue(failed.isFailure)
        assertEquals(0, probes)
        assertEquals(0, registry.debugState().activeProbeRounds)
    }
}
