package io.github.scisaga.loom.vpn

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CertifiedConfigurationTest {
    @Test
    fun cleanupFailureCannotBlockOrRollBackNewAuthorization() = runBlocking {
        var persisted = "demo-old-floor"
        val events = mutableListOf<String>()
        val (accepted, stopped) = acceptAuthorityAndStopRuntime(
            accept = {
                events += "save"
                persisted = "demo-new-floor"
                persisted
            },
            stop = {
                events += "stop"
                error("runtime cleanup failed")
            },
        )
        assertEquals(listOf("save", "stop"), events)
        assertEquals("demo-new-floor", persisted)
        assertEquals(persisted, accepted.getOrThrow())
        assertTrue(stopped.isFailure)
    }

    @Test
    fun failedWriteStillStopsOldExecutionAndCannotPublishAcceptance() = runBlocking {
        var stopped = false
        val (accepted, cleanup) = acceptAuthorityAndStopRuntime(
            accept = { error("atomic write/readback failed") },
            stop = { stopped = true },
        )
        assertTrue(stopped)
        assertTrue(accepted.isFailure)
        assertTrue(cleanup.isSuccess)
    }
}
