package io.github.scisaga.loom.enrollment

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

class EnrollmentRecoveryTest {
    @Test
    fun activeV2LatchUsesV2EvenWhenMigrationSourceIsRetained() {
        assertEquals("v2-runtime", selectLatchedRuntime("active", "v2-runtime", true))
    }

    @Test
    fun terminalV2LatchCannotRestoreLegacyOrDebugRuntime() {
        listOf("revoked", "decommissioned").forEach { state ->
            val error = assertThrows(V2TerminalDeviceException::class.java) {
                selectLatchedRuntime<String>(state, null, true)
            }
            assertEquals(state, error.lifecycleState)
        }
    }

    @Test
    fun legacyIdentityRequiresAuthenticatedMigration() {
        assertThrows(DeviceMigrationRequiredException::class.java) {
            selectLatchedRuntime<String>(null, null, true)
        }
    }

    @Test
    fun newInstallationHasNoManagedRuntime() {
        assertNull(selectLatchedRuntime<String>(null, null, false))
    }

    @Test
    fun incompleteActiveV2StateCannotFallBack() {
        assertThrows(IllegalStateException::class.java) {
            selectLatchedRuntime<String>("active", null, true)
        }
    }
}
