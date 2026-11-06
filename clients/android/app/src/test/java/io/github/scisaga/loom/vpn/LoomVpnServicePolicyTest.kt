package io.github.scisaga.loom.vpn

import android.app.Service
import android.content.Intent
import org.junit.Assert.assertEquals
import org.junit.Test

class LoomVpnServicePolicyTest {
    @Test
    fun connectedRequestIsRestartedAfterProcessReclaim() {
        assertEquals(Service.START_STICKY, vpnServiceRestartMode(desiredConnected = true))
    }

    @Test
    fun explicitDisconnectIsNotRestarted() {
        assertEquals(Service.START_NOT_STICKY, vpnServiceRestartMode(desiredConnected = false))
    }

    @Test
    fun disconnectActionFollowsAndroidAlwaysOnPolicy() {
        assertEquals(true, shouldOfferAppDisconnect(alwaysOn = false))
        assertEquals(false, shouldOfferAppDisconnect(alwaysOn = true))
    }

    @Test
    fun bootAndUpgradeRestoreOnlyAnAuthorizedRequestedConnection() {
        assertEquals(true, shouldRestoreVpn(Intent.ACTION_BOOT_COMPLETED, true, true))
        assertEquals(true, shouldRestoreVpn(Intent.ACTION_MY_PACKAGE_REPLACED, true, true))
        assertEquals(false, shouldRestoreVpn(Intent.ACTION_BOOT_COMPLETED, false, true))
        assertEquals(false, shouldRestoreVpn(Intent.ACTION_BOOT_COMPLETED, true, false))
        assertEquals(false, shouldRestoreVpn("unexpected", true, true))
    }

    @Test
    fun reconnectAfterCommittedFailureCannotReuseTheFailedBoxWhenUiProjectsStarting() {
        assertEquals(true, canReuseVpnRuntime(true, true, true, ConnectionPhase.STARTING))
        assertEquals(true, canReuseVpnRuntime(true, true, true, ConnectionPhase.CONNECTED))
        // Fail-closed commit invalidates the managed runtime before releasing
        // the locks. A new CONNECT projecting STARTING must create a new Box.
        assertEquals(false, canReuseVpnRuntime(true, true, false, ConnectionPhase.STARTING))
        assertEquals(false, canReuseVpnRuntime(true, true, true, ConnectionPhase.ERROR))
    }
}
