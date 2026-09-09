package io.github.scisaga.loom.enrollment

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class AndroidRuntimeCompatibilityTest {
    @Test
    fun certificateSlotsShareLibboxWorkingDirectory() {
        assertEquals(File("/app/files/libbox"), libboxWorkingDirectory(File("/app/files")))
    }

    @Test
    fun acceptsOnlyTheEmbeddedSingBoxRuntime() {
        validateAndroidRuntimeComponents(
            singBox = "1.11.4",
            wireGuard = "",
            tailscale = "",
            agent = "",
            embeddedSingBox = "1.11.4",
        )
    }

    @Test
    fun rejectsMissingOrDifferentSingBoxRuntime() {
        assertThrows(IllegalStateException::class.java) {
            validateAndroidRuntimeComponents("", "", "", "", "1.11.4")
        }
        assertThrows(IllegalStateException::class.java) {
            validateAndroidRuntimeComponents("1.12.0", "", "", "", "1.11.4")
        }
    }

    @Test
    fun rejectsServerOnlyComponents() {
        listOf(
            arrayOf("wireguard", "", ""),
            arrayOf("", "tailscale", ""),
            arrayOf("", "", "agent"),
        ).forEach { (wireGuard, tailscale, agent) ->
            assertThrows(IllegalStateException::class.java) {
                validateAndroidRuntimeComponents("1.11.4", wireGuard, tailscale, agent, "1.11.4")
            }
        }
    }
}
