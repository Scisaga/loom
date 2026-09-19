package io.github.scisaga.loom

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import kotlin.math.abs
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

class HomeUiInstrumentedTest {
    @get:Rule
    val compose = createAndroidComposeRule<MainActivity>()

    @Test
    fun retainedUiRequiresCertifiedProfileBeforeConnecting() {
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
        compose.onNodeWithTag("route-mode-card").performScrollTo().assertIsDisplayed()
        compose.onNodeWithTag("route-direct").assertIsDisplayed().assertIsNotEnabled()
        compose.onNodeWithTag("route-auto").assertIsDisplayed().assertIsNotEnabled()
        compose.onNodeWithTag("route-fixed-exit").assertIsDisplayed().assertIsNotEnabled()

        compose.onNodeWithTag("tab-diagnostics").performClick()
        compose.onNodeWithTag("network-evidence-card").assertIsDisplayed()
    }
}
