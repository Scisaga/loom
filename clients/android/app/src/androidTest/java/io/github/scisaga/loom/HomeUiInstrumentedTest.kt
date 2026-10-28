package io.github.scisaga.loom

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextReplacement
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.Until
import kotlin.math.abs
import org.junit.Assert.assertTrue
import org.junit.Assert.assertEquals
import org.junit.Assume.assumeTrue
import io.github.scisaga.loom.profiles.ProfileCatalog
import io.github.scisaga.loom.enrollment.ManagedProfileStore
import java.io.File
import org.junit.Rule
import org.junit.Test

class HomeUiInstrumentedTest {
    @get:Rule
    val compose = createAndroidComposeRule<MainActivity>()

    @Test
    fun deleteFinalDisconnectedProfileThenAddAnotherThroughNormalUi() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val device = UiDevice.getInstance(instrumentation)
        assumeTrue("deletion fixture is emulator-only", device.executeShellCommand("getprop ro.kernel.qemu").trim() == "1")
        val catalog = ProfileCatalog.get(compose.activity)
        val removed = catalog.state.value.viewedProfileId
        assumeTrue(catalog.state.value.profiles.size == 1)
        assumeTrue(ManagedProfileStore(compose.activity, removed).state() == null)
        device.wait(Until.findObject(By.res("com.android.permissioncontroller:id/permission_allow_button")), 3_000)?.click()
        compose.onNodeWithTag("tab-configuration").performClick()
        compose.onNodeWithTag("profile-menu-$removed").performClick()
        compose.onNodeWithTag("profile-delete-$removed").assertIsEnabled()
        device.takeScreenshot(File(compose.activity.getExternalFilesDir(null), "demo-profile-actions.png"))
        compose.onNodeWithTag("profile-delete-$removed").performClick()
        compose.onNodeWithText("删除").performClick()
        compose.waitUntil(10_000) { catalog.state.value.profiles.isEmpty() }
        compose.onNodeWithTag("profiles-empty").assertIsDisplayed()
        compose.onNodeWithTag("service-policy-card").assertDoesNotExist()
        compose.activityRule.scenario.recreate()
        compose.onNodeWithTag("profiles-empty").assertIsDisplayed()
        compose.onNodeWithTag("loom-wordmark").assertIsDisplayed()
        device.takeScreenshot(File(compose.activity.getExternalFilesDir(null), "demo-profiles-empty.png"))
        compose.onNodeWithTag("add-profile").performClick()
        compose.onNodeWithTag("profile-name-input").performTextReplacement("Loom A")
        compose.onNodeWithText("保存").performClick()
        compose.waitUntil(10_000) { catalog.state.value.profiles.size == 1 }
        assertEquals("Loom A", catalog.state.value.viewed?.name)
        assertTrue(removed != catalog.state.value.viewedProfileId)
        compose.onNodeWithTag("tab-connection").performClick()
        compose.onNodeWithTag("connection-toggle").assertIsDisplayed().assertIsNotEnabled()
    }

    @Test
    fun retainedUiRequiresCertifiedProfileBeforeConnecting() {
        val device = UiDevice.getInstance(InstrumentationRegistry.getInstrumentation())
        device.wait(Until.findObject(By.res("com.android.permissioncontroller:id/permission_allow_button")), 3_000)?.click()
        assertTrue("normal application UI did not open", device.wait(Until.hasObject(By.desc("Loom")), 10_000))
        compose.onNodeWithContentDescription("Loom").assertIsDisplayed()
        compose.onNodeWithText("LOOM · Loom A").assertIsDisplayed()
        val logoTop = compose.onNodeWithTag("loom-mark").fetchSemanticsNode().boundsInRoot.top
        val wordmarkTop = compose.onNodeWithTag("loom-wordmark").fetchSemanticsNode().boundsInRoot.top
        val density = compose.activity.resources.displayMetrics.density
        assertTrue("LOOM 字标未做光学顶边对齐", abs((logoTop - wordmarkTop) - 4 * density) <= density)
        compose.onNodeWithTag("home-tabs").assertIsDisplayed()
        compose.onNodeWithTag("connection-toggle").assertIsDisplayed().assertIsNotEnabled()
        compose.onNodeWithTag("route-summary-card").performScrollTo().assertIsDisplayed()

        compose.onNodeWithTag("tab-configuration").performClick()
        compose.onNodeWithTag("profiles-card").assertIsDisplayed()
        compose.onNodeWithTag("add-profile").assertIsDisplayed()
        compose.onNodeWithTag("service-policy-card").performScrollTo().assertIsDisplayed()
        compose.onNodeWithText("等待认证配置中的服务与策略").assertIsDisplayed()

        compose.onNodeWithTag("tab-diagnostics").performClick()
        compose.onNodeWithTag("network-evidence-card").assertIsDisplayed()
    }
}
