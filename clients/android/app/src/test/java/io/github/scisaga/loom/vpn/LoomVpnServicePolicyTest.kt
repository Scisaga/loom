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
    fun bootAndUpgradeRestoreOnlyAnAuthorizedRequestedConnection() {
        assertEquals(true, shouldRestoreVpn(Intent.ACTION_BOOT_COMPLETED, true, true))
        assertEquals(true, shouldRestoreVpn(Intent.ACTION_MY_PACKAGE_REPLACED, true, true))
        assertEquals(false, shouldRestoreVpn(Intent.ACTION_BOOT_COMPLETED, false, true))
        assertEquals(false, shouldRestoreVpn(Intent.ACTION_BOOT_COMPLETED, true, false))
        assertEquals(false, shouldRestoreVpn("unexpected", true, true))
    }
}
