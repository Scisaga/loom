package io.github.scisaga.loom.route

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class UnderlayProbeRegistryTest {
    @Test
    fun directDoesNotFreezeAndFirstProxyModeConsumesBudgetOnce() = runBlocking {
        val registry = UnderlayProbeRegistry()
        registry.observeDefaultNetwork("network-1", "wlan0")
        var probes = 0
        val measure = { _: ByteArray, _: String ->
            probes++
            "measured".encodeToByteArray()
        }
        val reuse = { _: ByteArray, frozen: ByteArray, _: String -> frozen }

        assertEquals(null, registry.entriesIfEnabled(false, byteArrayOf(1), "wlan0", measure, reuse))
        assertEquals(0, probes)
        assertFalse(checkNotNull(registry.entriesIfEnabled(true, byteArrayOf(1), "wlan0", measure, reuse)).reused)
        assertTrue(checkNotNull(registry.entriesIfEnabled(true, byteArrayOf(2), "wlan0", measure, reuse)).reused)
        assertEquals(1, probes)
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

        val first = registry.entries("config-a".encodeToByteArray(), "wlan0", ::measure, ::reuse)
        assertFalse(first.reused)
        // 同代 profile/config/reconnect 不得清空，也不得主动测新增 candidate。
        assertFalse(registry.observeDefaultNetwork("network-1", "wlan0"))
        val second = registry.entries("config-b".encodeToByteArray(), "wlan0", ::measure, ::reuse)
        assertTrue(second.reused)
        assertEquals(1, probes)
        assertTrue(second.entries.decodeToString().startsWith("reused:config-b:measured:config-a"))
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
        val first = registry.entries(byteArrayOf(1), "wlan0", ::measure, reuse)
        registry.observeDefaultNetwork("network-2", "rmnet0")
        val second = registry.entries(byteArrayOf(2), "rmnet0", ::measure, reuse)
        assertEquals(2, probes)
        assertEquals(first.generation + 1, second.generation)
    }

    @Test
    fun missingSourceDoesNotConsumeProbeBudget() = runBlocking {
        val registry = UnderlayProbeRegistry()
        registry.observeDefaultNetwork(null, "")
        var probes = 0
        val failed = runCatching {
            registry.entries(byteArrayOf(1), "", { _, _ -> probes++; byteArrayOf() }, { _, old, _ -> old })
        }
        assertTrue(failed.isFailure)
        assertEquals(0, probes)
    }
}
