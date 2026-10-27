package io.github.scisaga.loom

import android.Manifest
import android.content.Context
import android.hardware.camera2.CameraCharacteristics
import android.hardware.camera2.CameraManager
import android.view.View
import android.view.ViewGroup
import android.view.WindowInsets
import android.view.inspector.WindowInspector
import androidx.camera.view.PreviewView
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.click
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTouchInput
import androidx.core.content.ContextCompat
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.filters.SdkSuppress
import androidx.test.rule.GrantPermissionRule
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.By
import java.io.File
import java.util.concurrent.ConcurrentHashMap
import kotlin.math.abs
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

@SdkSuppress(minSdkVersion = 35)
class InviteScannerInstrumentedTest {
    @get:Rule(order = 0)
    val permissions: GrantPermissionRule = GrantPermissionRule.grant(
        Manifest.permission.CAMERA,
        Manifest.permission.POST_NOTIFICATIONS,
    )

    @get:Rule(order = 1)
    val compose = createAndroidComposeRule<MainActivity>()

    @Test
    fun cameraFloatsOverThePageAndEveryDismissalReleasesIt() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val device = UiDevice.getInstance(instrumentation)
        assertEquals("1", device.executeShellCommand("getprop ro.kernel.qemu").trim())
        val context = instrumentation.targetContext
        val cameraManager = context.getSystemService(Context.CAMERA_SERVICE) as CameraManager
        val cameraID = cameraManager.cameraIdList.first {
            cameraManager.getCameraCharacteristics(it).get(CameraCharacteristics.LENS_FACING) ==
                CameraCharacteristics.LENS_FACING_BACK
        }
        val available = ConcurrentHashMap<String, Boolean>()
        val callback = object : CameraManager.AvailabilityCallback() {
            override fun onCameraAvailable(cameraId: String) { available[cameraId] = true }
            override fun onCameraUnavailable(cameraId: String) { available[cameraId] = false }
        }
        cameraManager.registerAvailabilityCallback(ContextCompat.getMainExecutor(context), callback)
        val directory = checkNotNull(context.getExternalFilesDir(null))
        try {
            compose.onNodeWithTag("tab-configuration").performClick()
            for (dismissal in listOf("close", "backdrop", "back")) {
                val scan = compose.onNodeWithTag("scan-invite").performScrollTo()
                val originalPosition = scan.fetchSemanticsNode().boundsInRoot
                scan.performClick()
                assertCenteredSquare()
                compose.waitUntil(15_000) { available[cameraID] == false }
                compose.waitUntil(15_000) { cameraStreaming() }
                assertVisibleScreenCenter(device)
                compose.onNodeWithTag("invite-scanner-preview").assertIsDisplayed()
                compose.onNodeWithTag("invite-scanner").performTouchInput { click(center) }
                compose.onNodeWithTag("invite-scanner").assertIsDisplayed()
                if (dismissal == "close") {
                    assertTrue(device.takeScreenshot(File(directory, "demo-scanner-portrait.png")))
                    compose.onNodeWithTag("close-invite-scanner").performClick()
                } else if (dismissal == "backdrop") {
                    compose.onNodeWithTag("invite-scanner-backdrop").performTouchInput { click(Offset(2f, 2f)) }
                } else {
                    device.pressBack()
                }
                compose.waitForIdle()
                compose.onNodeWithTag("invite-scanner").assertDoesNotExist()
                compose.waitUntil(15_000) { available[cameraID] == true }
                assertEquals(originalPosition, compose.onNodeWithTag("scan-invite").fetchSemanticsNode().boundsInRoot)
            }
            device.setOrientationLeft()
            device.waitForIdle()
            compose.onNodeWithTag("scan-invite").performScrollTo().performClick()
            assertCenteredSquare()
            compose.waitUntil(15_000) { available[cameraID] == false }
            compose.waitUntil(15_000) { cameraStreaming() }
            assertVisibleScreenCenter(device)
            assertTrue(device.takeScreenshot(File(directory, "demo-scanner-landscape.png")))
            compose.onNodeWithTag("close-invite-scanner").performClick()
            compose.waitUntil(15_000) { available[cameraID] == true }
            File(directory, "demo-scanner-result.json").writeText(
                JSONObject().put("centered_square_in_portrait_and_landscape", true)
                    .put("page_position_preserved", true)
                    .put("center_matches_visible_screen", true)
                    .put("real_preview_streaming", true)
                    .put("camera_released_after_close_outside_and_back", true)
                    .put("camera_reopens", true).toString(),
            )
        } finally {
            cameraManager.unregisterAvailabilityCallback(callback)
            device.setOrientationNatural()
        }
    }

    private fun assertCenteredSquare() {
        compose.onNodeWithTag("invite-scanner").assertIsDisplayed()
        val viewport = compose.onNodeWithTag("invite-scanner").fetchSemanticsNode().boundsInRoot
        val backdrop = compose.onNodeWithTag("invite-scanner-backdrop").fetchSemanticsNode().boundsInRoot
        assertTrue("camera viewport is distorted", abs(viewport.width - viewport.height) <= 1f)
        assertTrue("camera viewport is not horizontally centered", abs(viewport.center.x - backdrop.center.x) <= 1f)
        assertTrue("camera viewport is not vertically centered", abs(viewport.center.y - backdrop.center.y) <= 1f)
        assertTrue("camera viewport exceeds the available page", viewport.width <= backdrop.width && viewport.height <= backdrop.height)
    }

    private fun assertVisibleScreenCenter(device: UiDevice) {
        val camera = checkNotNull(device.findObject(By.desc("扫描加入二维码"))).visibleBounds
        val metrics = compose.activity.windowManager.currentWindowMetrics
        val insets = metrics.windowInsets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.displayCutout())
        val expectedX = (metrics.bounds.left + insets.left + metrics.bounds.right - insets.right) / 2f
        val expectedY = (metrics.bounds.top + insets.top + metrics.bounds.bottom - insets.bottom) / 2f
        assertTrue("camera is clipped on the actual screen", abs(camera.width() - camera.height()) <= 2)
        assertTrue("camera is offset horizontally: $camera, expected $expectedX", abs(camera.exactCenterX() - expectedX) <= 2f)
        assertTrue("camera is offset vertically: $camera, expected $expectedY", abs(camera.exactCenterY() - expectedY) <= 2f)
    }

    private fun cameraStreaming(): Boolean {
        fun streaming(view: View): Boolean = when (view) {
            is PreviewView -> view.previewStreamState.value == PreviewView.StreamState.STREAMING
            is ViewGroup -> (0 until view.childCount).any { streaming(view.getChildAt(it)) }
            else -> false
        }
        var result = false
        compose.runOnUiThread { result = WindowInspector.getGlobalWindowViews().any(::streaming) }
        return result
    }
}
