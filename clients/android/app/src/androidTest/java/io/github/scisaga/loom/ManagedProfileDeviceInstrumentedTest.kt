package io.github.scisaga.loom

import android.content.Intent
import androidx.activity.ComponentActivity
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.core.content.ContextCompat
import androidx.test.platform.app.InstrumentationRegistry
import io.github.scisaga.loom.enrollment.EnrollmentManager
import io.github.scisaga.loom.profiles.ProfileCatalog
import io.github.scisaga.loom.route.RouteManager
import io.github.scisaga.loom.route.RouteMode
import io.github.scisaga.loom.vpn.ConnectionPhase
import io.github.scisaga.loom.vpn.LoomVpnService
import io.github.scisaga.loom.vpn.VpnRuntime
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test

/** §7.2：仅在操作者显式选择 managedProfile=true 时复用真机已有的正式配置。 */
class ManagedProfileDeviceInstrumentedTest {
    @get:Rule val compose = createEmptyComposeRule()

    @Test
    fun managedConnectionReadsActualRoutesAndReusesTheUnderlayBudget() = runBlocking {
        assumeTrue(InstrumentationRegistry.getArguments().getString("managedProfile") == "true")
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val activity: ComponentActivity = launchDeviceUi()
        val context = instrumentation.targetContext
        val catalog = ProfileCatalog.get(context)
        val selected = catalog.state.value.selectedId
        val scoped = catalog.context(selected)
        val enrollment = EnrollmentManager.get(scoped)
        val manager = RouteManager.get(scoped)
        waitUntil { enrollment.status.value.snapshot.isNotEmpty() && manager.status.value.available }
        val original = manager.status.value
        val registry = (context.applicationContext as LoomApplication).underlayProbeRegistry
        val before = registry.debugState()
        try {
            compose.onNodeWithTag("tab-configuration").performClick()
            compose.onNodeWithTag("route-direct").performScrollTo().performClick()
            waitUntil { manager.status.value.mode == RouteMode.DIRECT && !manager.status.value.busy }
            compose.onNodeWithTag("tab-connection").performClick()
            compose.onNodeWithTag("connection-toggle").performClick()
            waitUntil { VpnRuntime.status.value.phase == ConnectionPhase.CONNECTED && manager.status.value.running }
            assertEquals(before.activeProbeRounds, registry.debugState().activeProbeRounds)
            // §7.3：候选 tag 是不透明标识；Direct 由已读回候选的空服务器链判定。
            assertTrue(manager.status.value.currentPaths.isNotEmpty())
            assertTrue(manager.status.value.currentPaths.all { it.serverChain.isEmpty() })
            compose.onNodeWithTag("route-chain-diagram").performScrollTo().assertIsDisplayed()

            compose.onNodeWithTag("tab-configuration").performClick()
            compose.onNodeWithTag("route-auto").performScrollTo().performClick()
            waitUntil { manager.status.value.mode == RouteMode.AUTO && !manager.status.value.busy &&
                manager.status.value.currentPaths.isNotEmpty() }
            waitUntil { registry.debugState().activeProbeRounds > before.activeProbeRounds }
            val frozen = registry.debugState()
            assertEquals(before.activeProbeRounds + 1, frozen.activeProbeRounds)
            val exit = manager.status.value.exits.firstOrNull()
            if (exit != null) {
                compose.onNodeWithTag("route-fixed-exit").performClick()
                compose.onNodeWithTag("route-exit-$exit").performClick()
                waitUntil { manager.status.value.mode == RouteMode.FIXED_EXIT && !manager.status.value.busy }
                assertEquals(frozen.activeProbeRounds, registry.debugState().activeProbeRounds)
                compose.onNodeWithTag("route-auto").performClick()
                waitUntil { manager.status.value.mode == RouteMode.AUTO && !manager.status.value.busy }
            }
            compose.onNodeWithTag("tab-connection").performClick()
            compose.onNodeWithTag("connection-toggle").performScrollTo().performClick()
            waitUntil { VpnRuntime.status.value.phase == ConnectionPhase.DISCONNECTED }
            assertTrue(manager.status.value.currentPaths.isEmpty())
            compose.onNodeWithTag("connection-toggle").performClick()
            waitUntil { VpnRuntime.status.value.phase == ConnectionPhase.CONNECTED && manager.status.value.currentPaths.isNotEmpty() }
            waitUntil { VpnRuntime.status.value.trustedReport.startsWith("成功") }
            assertEquals(frozen.activeProbeRounds, registry.debugState().activeProbeRounds)
            assertEquals(frozen.frozenFingerprint, registry.debugState().frozenFingerprint)
            compose.onNodeWithTag("route-chain-diagram").performScrollTo().assertIsDisplayed()
            val paths = manager.status.value.currentPaths
            assertTrue(paths.any { it.serverChain.isNotEmpty() })
            val image = instrumentation.uiAutomation.takeScreenshot()
            context.getExternalFilesDir(null)!!.resolve("managed-route-acceptance.png").outputStream().use {
                image.compress(android.graphics.Bitmap.CompressFormat.PNG, 100, it)
            }
            context.getExternalFilesDir(null)!!.resolve("managed-acceptance.txt").writeText(
                "managed=true\nprofile-bound=${VpnRuntime.status.value.profileId == selected}\n" +
                    "trusted-report=${VpnRuntime.status.value.trustedReport}\n" +
                    "paths=${paths.size}\nprobe-rounds=${frozen.activeProbeRounds}\nreconnect-reused=true\n",
            )
        } finally {
            ContextCompat.startForegroundService(context, Intent(context, LoomVpnService::class.java)
                .setAction(LoomVpnService.ACTION_DISCONNECT))
            waitUntil { VpnRuntime.status.value.phase == ConnectionPhase.DISCONNECTED }
            manager.select(original.mode, original.exit)
            waitUntil { !manager.status.value.busy && manager.status.value.mode == original.mode }
            instrumentation.runOnMainSync { activity.finish() }
        }
    }

    private suspend fun waitUntil(condition: () -> Boolean) = withTimeout(45_000) {
        while (!condition()) {
            check(VpnRuntime.status.value.phase != ConnectionPhase.ERROR) { "正式配置本机启动失败" }
            delay(100)
        }
    }
}
