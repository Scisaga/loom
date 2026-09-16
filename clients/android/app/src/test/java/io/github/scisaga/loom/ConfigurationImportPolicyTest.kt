package io.github.scisaga.loom

import io.github.scisaga.loom.enrollment.EnrollmentPhase
import io.github.scisaga.loom.enrollment.EnrollmentStatus
import io.github.scisaga.loom.vpn.ConnectionPhase
import io.github.scisaga.loom.vpn.VpnStatus
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ConfigurationImportPolicyTest {
    private val installed = EnrollmentStatus(phase = EnrollmentPhase.READY, protocol = 2, snapshot = "demo-head")

    @Test
    fun recoveryIsAvailableWhileDisconnectedAndAfterAFailedImport() {
        assertTrue(canImportV2Configuration("demo-profile", installed, VpnStatus()))
        assertTrue(canImportV2Configuration("demo-profile", installed.copy(phase = EnrollmentPhase.ERROR),
            VpnStatus(phase = ConnectionPhase.ERROR)))
        assertTrue(canImportV2Configuration("demo-profile", installed,
            VpnStatus(phase = ConnectionPhase.CONNECTED, profileId = "demo-profile")))
    }

    @Test
    fun recoveryCannotInterruptAnotherProfileOrAnOngoingOperation() {
        assertFalse(canImportV2Configuration("demo-profile", installed,
            VpnStatus(phase = ConnectionPhase.CONNECTED, profileId = "demo-other")))
        for (phase in listOf(ConnectionPhase.STARTING, ConnectionPhase.STOPPING)) {
            assertFalse(canImportV2Configuration("demo-profile", installed, VpnStatus(phase = phase)))
        }
        assertFalse(canImportV2Configuration("demo-profile", installed.copy(phase = EnrollmentPhase.PULLING), VpnStatus()))
        assertFalse(canImportV2Configuration("demo-profile", EnrollmentStatus(), VpnStatus()))
    }
}
