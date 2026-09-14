package io.github.scisaga.loom

import android.Manifest
import androidx.compose.ui.graphics.toPixelMap
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.captureToImage
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.test.rule.GrantPermissionRule
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import kotlin.math.abs

class HomeUiInstrumentedTest {
    @get:Rule(order = 0)
    val notificationPermission: GrantPermissionRule =
        GrantPermissionRule.grant(Manifest.permission.POST_NOTIFICATIONS)

    @get:Rule(order = 1)
    val compose = createAndroidComposeRule<MainActivity>()

    @Test
    fun bottomTabsSeparateConnectionConfigurationAndDiagnostics() {
        compose.onNodeWithContentDescription("Loom").assertIsDisplayed()
        val logoTop = compose.onNodeWithContentDescription("Loom").fetchSemanticsNode().boundsInRoot.top
        val wordmarkTop = compose.onNodeWithText("LOOM").fetchSemanticsNode().boundsInRoot.top
        val alignmentTolerance = compose.activity.resources.displayMetrics.density
        assertTrue("LOOM 字标未与图标顶端对齐", abs(logoTop - wordmarkTop) <= alignmentTolerance)
        compose.onNodeWithTag("home-tabs").assertIsDisplayed()
        compose.onNodeWithTag("connection-toggle").assertIsDisplayed().assertIsNotEnabled()

        compose.onNodeWithTag("tab-configuration").performClick()
        compose.onNodeWithTag("enrollment-card").assertIsDisplayed()
        compose.onNodeWithTag("route-mode-card").performScrollTo().assertIsDisplayed()
        compose.onNodeWithTag("route-direct").assertIsDisplayed().assertIsNotEnabled()
        compose.onNodeWithTag("route-auto").assertIsDisplayed().assertIsNotEnabled()
        compose.onNodeWithTag("route-fixed-exit").assertIsDisplayed().assertIsNotEnabled()

        compose.onNodeWithTag("tab-diagnostics").performClick()
        compose.onNodeWithTag("advanced-info-card").assertIsDisplayed()
        compose.onNodeWithTag("debug-direct-card").assertIsDisplayed()
        compose.onNodeWithTag("debug-direct-toggle").assertIsDisplayed().assertIsEnabled()
    }

    @Test
    fun renderedHomeScreenshotRemainsLightAndCardsDoNotCollapseIntoStrips() {
        compose.waitForIdle()
        val image = compose.onRoot().captureToImage()
        val pixels = image.toPixelMap()
        val stepX = maxOf(1, image.width / 120)
        val stepY = maxOf(1, image.height / 120)
        var samples = 0
        var light = 0
        var nearBlack = 0
        for (y in 0 until image.height step stepY) {
            for (x in 0 until image.width step stepX) {
                val color = pixels[x, y]
                samples++
                if (color.red >= 0.85f && color.green >= 0.85f && color.blue >= 0.85f) light++
                if (color.red <= 0.08f && color.green <= 0.08f && color.blue <= 0.08f) nearBlack++
            }
        }
        assertTrue("首页截图不再是浅色主题", light * 100 >= samples * 70)
        assertTrue("首页截图出现大面积黑色窗口", nearBlack * 100 <= samples * 5)

        val minimumCardHeight = 96f * compose.activity.resources.displayMetrics.density

        compose.onNodeWithTag("tab-configuration").performClick()
        val enrollment = compose.onNodeWithTag("enrollment-card").fetchSemanticsNode().boundsInRoot
        assertTrue(
            "加入卡退化为横向长条：${enrollment.width}x${enrollment.height}",
            enrollment.height >= minimumCardHeight,
        )

        compose.onNodeWithTag("tab-diagnostics").performClick()
        val diagnostics = compose.onNodeWithTag("debug-direct-card").fetchSemanticsNode().boundsInRoot
        assertTrue(
            "诊断卡退化为横向长条：${diagnostics.width}x${diagnostics.height}",
            diagnostics.height >= minimumCardHeight,
        )
    }

    @Test
    fun diagnosticsStayOffConnectionPageAndRenderOnTheirOwnTab() {
        assertTrue(compose.onAllNodesWithText("网络诊断").fetchSemanticsNodes().isEmpty())

        compose.onNodeWithTag("tab-diagnostics").performClick()

        compose.onNodeWithText("网络诊断").assertIsDisplayed()
    }
}
