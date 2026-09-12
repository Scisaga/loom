package io.github.scisaga.loom

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.scisaga.libbox.Libbox
import io.github.scisaga.loomcore.Loomcore
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class V2SingleHostRuntimeInstrumentedTest {
    @Test
    fun sharedGoHydrationProducesOneLibboxTunAndUserspaceWireGuardHost() {
        val assets = InstrumentationRegistry.getInstrumentation().context.assets
        val singBox = assets.open("android/v2-single-host-sing-box.json").use { it.reader().readText() }
        val routePlan = assets.open("android/v2-single-host-route-plan.json").use { it.reader().readText() }
        val bundle = JSONObject()
            .put("owner", "android-v2")
            .put(
                "files",
                JSONObject()
                    .put("agent/config.json", routePlan)
                    .put("sing-box/config.json", singBox),
            )
            .toString()
            .encodeToByteArray()
        val secrets = """
            api/android-v2=synthetic-api-secret
            probe/android-v2=synthetic-probe-secret
            wg/android-v2=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
        """.trimIndent().plus("\n").encodeToByteArray()

        val prepared = JSONObject(Loomcore.prepareAndroidRuntime(bundle, secrets).decodeToString())
        assertTrue(prepared.getString("route_plan").isNotBlank())
        val config = JSONObject(prepared.getString("sing_box_config"))
        val inbounds = config.getJSONArray("inbounds")
        val tunCount = (0 until inbounds.length()).count {
            inbounds.getJSONObject(it).getString("type") == "tun"
        }
        assertEquals(1, tunCount)
        val endpoints = config.getJSONArray("endpoints")
        assertEquals(1, endpoints.length())
        assertEquals("wireguard", endpoints.getJSONObject(0).getString("type"))
        assertFalse(endpoints.getJSONObject(0).getBoolean("system"))
        assertTrue(config.getJSONObject("route").getBoolean("auto_detect_interface"))
        Libbox.checkConfig(config.toString())
    }
}
