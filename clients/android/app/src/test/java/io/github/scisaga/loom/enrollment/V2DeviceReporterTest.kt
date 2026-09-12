package io.github.scisaga.loom.enrollment

import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class V2DeviceReporterTest {
    @Test
    fun onlyExactRuntimeByteChangesRequireLibboxReplacement() {
        val current = profile(config = "config-a", routePlan = "route-a", recordID = "v2:head-a")

        assertFalse(
            requiresV2RuntimeActivation(
                current,
                profile(config = "config-a", routePlan = "route-b", recordID = "v2:head-b"),
            ),
        )
        assertTrue(
            requiresV2RuntimeActivation(
                current,
                profile(config = "config-b", routePlan = "route-a", recordID = "v2:head-b"),
            ),
        )
        assertTrue(
            requiresV2RouteApplication(
                current,
                profile(config = "config-a", routePlan = "route-b", recordID = "v2:head-b"),
            ),
        )
        assertFalse(
            requiresV2RouteApplication(
                current,
                profile(config = "config-b", routePlan = "route-a", recordID = "v2:head-b"),
            ),
        )
    }

    @Test
    fun runtimeCandidateCannotCrossDeviceIdentity() {
        assertThrows(IllegalStateException::class.java) {
            requiresV2RuntimeActivation(
                profile(config = "config-a", routePlan = null, recordID = "v2:head-a"),
                profile(
                    nodeID = "android-other",
                    config = "config-b",
                    routePlan = null,
                    recordID = "v2:head-b",
                ),
            )
        }
    }

    private fun profile(
        nodeID: String = "android-device",
        config: String,
        routePlan: String?,
        recordID: String,
    ) = ManagedProfile(
        nodeID = nodeID,
        snapshot = recordID.removePrefix("v2:"),
        generation = 1,
        config = config,
        routePlan = routePlan,
        certificatePEM = ByteArray(0),
        caPEM = ByteArray(0),
        reportEndpoint = "",
        recordID = recordID,
        protocol = 2,
    )
}
