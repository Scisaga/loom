package io.github.scisaga.loom

import androidx.compose.material3.MaterialTheme
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Before
import org.junit.After
import androidx.compose.ui.test.onAllNodesWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import io.github.scisaga.loom.route.RouteLinkStatus
import io.github.scisaga.loom.route.RoutePathStatus
import org.junit.Rule
import org.junit.Test

class RouteDiagramInstrumentedTest {
    @get:Rule val compose = createEmptyComposeRule()
    private lateinit var activity: ComponentActivity
    @Before fun launch() { activity = launchDeviceUi() }
    @After fun finish() {
        if (::activity.isInitialized) InstrumentationRegistry.getInstrumentation().runOnMainSync { activity.finish() }
    }

    @Test
    fun opaqueDirectCandidateShowsLocalLinkWithoutServer() {
        InstrumentationRegistry.getInstrumentation().runOnMainSync { activity.setContent {
            MaterialTheme {
                RouteChainDiagram(RoutePathStatus(
                    service = "demo-web", candidate = "demo-opaque-route", chain = "", reason = "", updatedAt = "",
                    links = emptyList(), serverChain = emptyList(),
                ))
            }
        } }
        compose.onAllNodesWithContentDescription("服务器图标").assertCountEquals(0)
        compose.onAllNodesWithContentDescription("链路方向向下").assertCountEquals(1)
        compose.onNodeWithText("Direct · 本机直连").assertIsDisplayed()
        compose.onNodeWithText("不执行路径测量").assertIsDisplayed()
    }

    @Test
    fun unknownEvidenceRetainsEveryActualNodeAndDirectionalLink() {
        InstrumentationRegistry.getInstrumentation().runOnMainSync { activity.setContent {
            MaterialTheme {
                RouteChainDiagram(RoutePathStatus(
                    service = "demo-web", candidate = "demo-route", chain = "", reason = "", updatedAt = "",
                    serverChain = listOf("demo-entry", "demo-exit"), protocols = listOf("Hysteria2", "WireGuard"),
                    links = listOf(
                        RouteLinkStatus("demo-device", "demo-entry", "12 ms", "本机测量", 0, "entry", "Hysteria2"),
                        RouteLinkStatus("demo-entry", "demo-exit", "—", "暂无观测", 1, "neighbor", "WireGuard"),
                        RouteLinkStatus("demo-exit", "https://demo.example/", "—", "暂无观测", 2, "target", "HTTPS"),
                    ),
                ))
            }
        }
        }
        compose.onAllNodesWithContentDescription("本机图标").assertCountEquals(1)
        compose.onAllNodesWithContentDescription("服务器图标").assertCountEquals(2)
        compose.onAllNodesWithContentDescription("目标地址图标").assertCountEquals(1)
        compose.onAllNodesWithContentDescription("链路方向向下").assertCountEquals(3)
        compose.onNodeWithText("WireGuard").assertIsDisplayed()
        compose.onNodeWithText("https://demo.example/").assertIsDisplayed()
    }
}
