package io.github.scisaga.loom.vpn

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RuntimeResourceApplicationTest {
    @Test
    fun currentPermissionWithPendingResourcesRetainsExecutionWithoutRunningProof() {
        val reply = RuntimeAuthorizationResult(true, true, false, "demo-current-execution")
        assertTrue(reply.retainExecution)
        assertEquals("unknown", runtimeReportState(true, reply.resourcesReady, false))
        assertEquals("demo-view", runtimeReportPermissionViewDigest("demo-view", reply.permissionCurrent))
        assertTrue(shouldRetryRuntimeResources(reply.permissionCurrent, reply.resourcesReady))
        assertFalse(shouldRetryRuntimeResources(true, true))
        assertFalse(shouldRetryRuntimeResources(false, false))
    }

    @Test(expected = IllegalArgumentException::class)
    fun resourceCompletionCannotReplacePermissionConfirmation() {
        RuntimeAuthorizationResult(true, false, true, "demo-execution")
    }

    @Test(expected = IllegalArgumentException::class)
    fun confirmedPermissionRequiresItsActualProjection() {
        RuntimeAuthorizationResult(true, true, false, "")
    }

    @Test
    fun unconfirmedPermissionUsesSafetyPathAndStoppedExecutionHasNoProof() {
        assertFalse(RuntimeAuthorizationResult(true, false, false, "").retainExecution)
        assertFalse(RuntimeAuthorizationResult(false, false, false, "").retainExecution)
        assertEquals("stopped", runtimeReportState(false, true, false))
        assertEquals("error", runtimeReportState(false, true, true))
        assertEquals("", runtimeReportPermissionViewDigest("demo-view", false))
        assertEquals("", runtimeReportPermissionViewDigest(null, true))
    }

    @Test
    fun suspendedReportConsumerDoesNotOwnLifecycleAndRetainsItsCapturedObservation() = runBlocking {
        val lock = Mutex()
        var currentView: String? = "demo-view"
        var permissionCurrent = true
        val sending = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        val report = async {
            withRuntimeReportSnapshot(lock, capture = {
                runtimeReportState(currentView != null, false, false) to
                    runtimeReportPermissionViewDigest(currentView, permissionCurrent)
            }) { captured ->
                sending.complete(Unit)
                release.await()
                captured
            }
        }
        sending.await()
        withTimeout(1_000) { lock.withLock { currentView = null; permissionCurrent = false } }
        release.complete(Unit)
        assertEquals("unknown" to "demo-view", report.await())
        assertEquals("stopped", runtimeReportState(currentView != null, false, false))
        assertEquals("", runtimeReportPermissionViewDigest(currentView, permissionCurrent))
    }

    @Test
    fun pendingInitialReadbackDoesNotBlockReportOrStopAndCannotPublishForStoppedSession() = runBlocking {
        val lock = Mutex()
        val reading = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Boolean>()
        var session = 1
        var phase = ConnectionPhase.STARTING
        val confirmation = async {
            confirmInitialSelection(lock, ready = { reading.complete(Unit); release.await() },
                isCurrent = { session == 1 && phase == ConnectionPhase.STARTING },
                connected = { phase = ConnectionPhase.CONNECTED })
        }
        reading.await()
        assertEquals(ConnectionPhase.STARTING, withTimeout(1_000) {
            withRuntimeReportSnapshot(lock, capture = { phase }) { it }
        })
        withTimeout(1_000) { lock.withLock { session++; phase = ConnectionPhase.DISCONNECTED } }
        release.complete(true)
        confirmation.await()
        assertEquals(ConnectionPhase.DISCONNECTED, phase)
    }

    @Test
    fun onlyFirstConfirmedSelectionPublishesConnectedAndLaterMeasurementsKeepItConnected() = runBlocking {
        val lock = Mutex()
        var phase = ConnectionPhase.STARTING
        var publications = 0
        suspend fun confirm(ready: Boolean) = confirmInitialSelection(lock, ready = { ready },
            isCurrent = { phase == ConnectionPhase.STARTING }, connected = { publications++; phase = ConnectionPhase.CONNECTED })
        confirm(false)
        assertEquals(ConnectionPhase.STARTING, phase)
        confirm(true)
        assertEquals(ConnectionPhase.CONNECTED, phase)
        confirm(false)
        confirm(true)
        assertEquals(ConnectionPhase.CONNECTED, phase)
        assertEquals(1, publications)
    }
}
