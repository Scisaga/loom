package io.github.scisaga.loom

import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.Until
import io.github.scisaga.loom.enrollment.EnrollmentManager
import io.github.scisaga.loom.enrollment.EnrollmentPhase
import io.github.scisaga.loom.enrollment.ManagedProfileStore
import io.github.scisaga.loom.profiles.ProfileCatalog
import io.github.scisaga.loom.route.RouteManager
import io.github.scisaga.loom.route.RouteMode
import io.github.scisaga.loom.vpn.ConnectionPhase
import io.github.scisaga.loom.vpn.VpnRuntime
import java.io.File
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test

/** Existing demo enrollment, real UI settings and the normal private report sender. */
class ReportedPreferenceInstrumentedTest {
    @get:Rule val compose = createAndroidComposeRule<MainActivity>()

    @Test
    fun signedSettingsRemainSeparateFromRuntimeAndSurviveRestart() {
        val args = InstrumentationRegistry.getArguments()
        assumeTrue(args.getString("demoPreferenceFixture") == "true")
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val device = UiDevice.getInstance(instrumentation)
        assertEquals("1", device.executeShellCommand("getprop ro.kernel.qemu").trim())
        val context = instrumentation.targetContext
        val directory = checkNotNull(context.getExternalFilesDir(null))
        val catalog = ProfileCatalog.get(context)
        val profile = catalog.state.value.profiles.single {
            ManagedProfileStore(context, it.id).loadCurrent()?.nodeID == "demo-android"
        }
        catalog.view(profile.id)
        val enrollment = EnrollmentManager.get(context)
        val routing = RouteManager.get(context)
        enrollment.initialize(profile.id)
        fun await(label: String, ready: () -> Boolean) {
            val until = System.nanoTime() + TimeUnit.SECONDS.toNanos(70)
            while (!ready() && System.nanoTime() < until &&
                enrollment.status(profile.id).value.phase != EnrollmentPhase.ERROR) Thread.sleep(100)
            assertTrue(label + "; enrollment=" + enrollment.status(profile.id).value +
                "; routing=" + routing.status(profile.id).value + "; vpn=" + VpnRuntime.status.value, ready())
        }
        fun click(tag: String) = compose.onNodeWithTag(tag).performScrollTo().performClick()
        fun report(step: String) {
            runBlocking { enrollment.postReport(profile.id) }
            File(directory, "demo-preference-$step").writeText("reported")
            await("control must verify the signed setting and actual runtime separately") {
                File(directory, "demo-preference-ack-$step").exists()
            }
        }
        await("original protected profile must resume") { enrollment.status(profile.id).value.phase == EnrollmentPhase.READY }
        compose.onNodeWithTag("tab-connection").performClick()
        if (args.getString("demoPreferenceResume") == "true") {
            await("existing route settings must become visible") { routing.status(profile.id).value.available }
            assertEquals(RouteMode.FIXED_EXIT, routing.status(profile.id).value.mode)
            assertEquals("demo-exit", routing.status(profile.id).value.exit)
            report("restarted")
            compose.onNodeWithTag("tab-configuration").performClick()
            click("route-auto")
            await("normal Auto restoration must be durable") { routing.status(profile.id).value.mode == RouteMode.AUTO }
            report("restored")
            return
        }
        compose.onNodeWithTag("tab-configuration").performClick()
        click("refresh-config")
        await("current demo permissions must be loaded") {
            enrollment.status(profile.id).value.phase == EnrollmentPhase.READY && routing.status(profile.id).value.directAvailable
        }
        compose.onNodeWithTag("tab-connection").performClick()
        await("retained system VPN must settle before using the connection toggle") {
            VpnRuntime.status.value.phase !in setOf(ConnectionPhase.STARTING, ConnectionPhase.STOPPING)
        }
        if (VpnRuntime.status.value.phase != ConnectionPhase.CONNECTED ||
            VpnRuntime.status.value.activeProfileId != profile.id) {
            click("connection-toggle")
            device.wait(Until.findObject(By.res("android:id/button1")), 3_000)?.click()
        }
        await("real VPN and selector must be running") {
            VpnRuntime.status.value.phase == ConnectionPhase.CONNECTED && routing.status(profile.id).value.running
        }
        compose.onNodeWithTag("tab-configuration").performClick()
        for ((tag, mode) in listOf("route-direct" to RouteMode.DIRECT, "route-auto" to RouteMode.AUTO, "route-fixed-exit" to RouteMode.FIXED_EXIT)) {
            click(tag)
            if (mode == RouteMode.FIXED_EXIT) click("route-exit-demo-exit")
            await("UI setting and selector must finish applying") {
                val status = routing.status(profile.id).value
                status.mode == mode && status.running && status.currentPaths.isNotEmpty() &&
                    (mode != RouteMode.DIRECT || status.currentPaths.all { it.finalExit == "direct" }) &&
                    (mode != RouteMode.FIXED_EXIT || status.currentPaths.all { it.finalExit == "demo-exit" })
            }
            report(mode.wire)
        }
        assertTrue(device.takeScreenshot(File(directory, "demo-preference-fixed.png")))
        compose.onNodeWithTag("tab-connection").performClick()
        click("connection-toggle")
        await("normal stop must complete") { VpnRuntime.status.value.phase == ConnectionPhase.DISCONNECTED }
        report("stopped")
    }
}
