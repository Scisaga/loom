package io.github.scisaga.loom

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performScrollTo
import org.junit.Rule
import org.junit.Test

class HomeUiInstrumentedTest {
    @get:Rule
    val compose = createAndroidComposeRule<MainActivity>()

    @Test
    fun retainedUiRequiresCertifiedProfileBeforeConnecting() {
        compose.onNodeWithContentDescription("Loom").assertIsDisplayed()
        compose.onNodeWithTag("connection-toggle").assertIsDisplayed().assertIsNotEnabled()
        compose.onNodeWithTag("route-mode-card").performScrollTo().assertIsDisplayed()
        compose.onNodeWithTag("route-direct").assertIsDisplayed().assertIsNotEnabled()
        compose.onNodeWithTag("route-auto").assertIsDisplayed().assertIsNotEnabled()
        compose.onNodeWithTag("route-fixed-exit").assertIsDisplayed().assertIsNotEnabled()
    }
}
