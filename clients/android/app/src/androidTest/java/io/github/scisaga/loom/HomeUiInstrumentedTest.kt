package io.github.scisaga.loom

import androidx.compose.ui.graphics.toPixelMap
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.activity.ComponentActivity
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Before
import org.junit.After
import io.github.scisaga.loom.profiles.ProfileCatalog
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

class HomeUiInstrumentedTest {
    @get:Rule val compose = createEmptyComposeRule()
    private lateinit var activity: ComponentActivity
    @Before fun launch() { activity = launchDeviceUi() }
    @After fun finish() {
        if (::activity.isInitialized) InstrumentationRegistry.getInstrumentation().runOnMainSync { activity.finish() }
    }

    @Test
    fun nativeTabsKeepPathsProfilesAndDiagnosticsInTheirOwnPages() {
        compose.onNodeWithContentDescription("Loom").assertIsDisplayed()
        compose.onNodeWithTag("home-tabs").assertIsDisplayed()
        val configuration = compose.onNodeWithTag("tab-configuration").fetchSemanticsNode().boundsInRoot
        val diagnostics = compose.onNodeWithTag("tab-diagnostics").fetchSemanticsNode().boundsInRoot
        assertTrue("配置页应在诊断页之前", configuration.left < diagnostics.left)
        compose.onNodeWithTag("route-summary-card").performScrollTo().assertIsDisplayed()
        compose.onNodeWithTag("profiles-card").assertDoesNotExist()
        captureScreen("connection")
        compose.onNodeWithTag("tab-configuration").performClick()
        compose.onNodeWithTag("profiles-card").assertIsDisplayed()
        compose.onNodeWithTag("route-mode-card").performScrollTo().assertIsDisplayed()
        captureScreen("configuration")
        compose.onNodeWithTag("tab-diagnostics").performClick()
        compose.onNodeWithTag("network-evidence-card").assertIsDisplayed()
        compose.onNodeWithTag("device-info-card").performScrollTo().assertIsDisplayed()
        compose.onNodeWithTag("route-mode-card").assertDoesNotExist()
        captureScreen("diagnostics")
    }

    @Test
    fun renameCancelAndSaveUseNativeDialogWithoutChangingConnection() {
        val catalog = ProfileCatalog.get(activity)
        val selected = catalog.state.value.selected
        val original = selected.name
        val runtime = io.github.scisaga.loom.vpn.VpnRuntime.status.value
        try {
            compose.onNodeWithTag("tab-configuration").performClick()
            compose.onNodeWithTag("profile-menu-${selected.id}").performScrollTo().performClick()
            compose.onNodeWithText("重命名").performClick()
            compose.onNodeWithTag("profile-name-input").performTextReplacement("demo-rename")
            compose.onNodeWithText("取消").performClick()
            assertTrue(catalog.state.value.selected.name == original)
            compose.onNodeWithTag("profile-menu-${selected.id}").performClick()
            compose.onNodeWithText("重命名").performClick()
            compose.onNodeWithTag("profile-name-input").performTextReplacement("demo-rename")
            compose.onNodeWithText("保存").performClick()
            compose.waitUntil { catalog.state.value.selected.name == "demo-rename" }
            assertTrue(io.github.scisaga.loom.vpn.VpnRuntime.status.value.profileId == runtime.profileId)
        } finally { catalog.rename(selected.id, original) }
    }

    @Test
    fun backgroundIsLightWithVisibleWhitePanels() {
        compose.onNodeWithTag("tab-configuration").performClick()
        compose.waitForIdle()
        val root = compose.onRoot().captureToImage().toPixelMap()
        var background = 0
        var white = 0
        for (y in 0 until root.height step 8) for (x in 0 until root.width step 8) {
            val pixel = root[x, y]
            if (pixel.red in 0.92f..0.96f && pixel.green in 0.94f..0.98f && pixel.blue in 0.93f..0.97f) background++
            if (pixel.red > 0.99f && pixel.green > 0.99f && pixel.blue > 0.99f) white++
        }
        assertTrue("页面缺少浅色背景", background > 100)
        assertTrue("白色面板未清楚呈现", white > 100)
    }

    private fun captureScreen(name: String) {
        if (InstrumentationRegistry.getArguments().getString("screenshots") != "true") return
        compose.waitForIdle()
        val image = InstrumentationRegistry.getInstrumentation().uiAutomation.takeScreenshot()
        activity.getExternalFilesDir(null)!!.resolve("ui-$name.png").outputStream().use {
            image.compress(android.graphics.Bitmap.CompressFormat.PNG, 100, it)
        }
    }
}
