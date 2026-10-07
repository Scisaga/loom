package io.github.scisaga.loom

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertTextContains
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.UiDevice
import io.github.scisaga.loom.enrollment.EnrollmentManager
import io.github.scisaga.loom.enrollment.ManagedProfileStore
import io.github.scisaga.loom.profiles.ProfileCatalog
import io.github.scisaga.loomcore.Loomcore
import java.io.File
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test

/** Signed demo states exercise the native bridge, encrypted storage and real UI.
 * This does not claim to exercise enrollment or a live membership decision. */
class MemberWarningInstrumentedTest {
    @get:Rule
    val compose = createAndroidComposeRule<MainActivity>()

    @Test
    fun certifiedSealWarningSurvivesProtectedReload() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val args = InstrumentationRegistry.getArguments()
        assumeTrue(args.getString("demoMemberFixture") == "true")
        assertEquals("1", UiDevice.getInstance(instrumentation).executeShellCommand("getprop ro.kernel.qemu").trim())
        val context = instrumentation.targetContext
        val directory = checkNotNull(context.getExternalFilesDir(null))
        val catalog = ProfileCatalog.get(context)
        val profileName = args.getString("demoMemberName") ?: "Demo member review"
        val resume = args.getString("demoMemberResume") == "true"
        val profile = if (resume) catalog.state.value.profiles.single { it.name == profileName }
            else catalog.create(profileName)
        if (!resume) {
            val before = File(directory, "demo-member-before.json").readBytes()
            val after = File(directory, "demo-member-after.json").readBytes()
            try {
                val store = ManagedProfileStore(context, profile.id)
                assertEquals(null, store.state())
                store.saveState(before)
                assertFalse(store.possiblePermissionRestoration())
                val review = JSONObject(Loomcore.androidMemberReview(after, before).decodeToString())
                assertTrue(review.getBoolean("possible_permission_restoration"))
                assertTrue(review.getJSONArray("changes").length() > 0)
                store.acceptCertified(after)
            } finally {
                before.fill(0)
                after.fill(0)
            }
        }
        val reopened = ManagedProfileStore(context, profile.id)
        assertTrue(reopened.possiblePermissionRestoration())
        assertTrue(checkNotNull(reopened.loadCurrent()).possiblePermissionRestoration)
        catalog.view(profile.id)
        val enrollment = EnrollmentManager.get(context)
        enrollment.initialize(profile.id)
        compose.waitUntil(15_000) { enrollment.status(profile.id).value.possiblePermissionRestoration }
        compose.onNodeWithTag("member-permission-warning").assertIsDisplayed().assertTextContains(profileName, substring = true)
        compose.activityRule.scenario.recreate()
        compose.waitForIdle()
        compose.onNodeWithTag("member-permission-warning").assertIsDisplayed().assertTextContains(profileName, substring = true)
        val other = catalog.state.value.profiles.first { it.id != profile.id }
        catalog.view(other.id)
        compose.waitUntil(15_000) { catalog.state.value.viewedProfileId == other.id }
        compose.waitForIdle()
        compose.onNodeWithTag("member-permission-warning").assertDoesNotExist()
        catalog.view(profile.id)
        compose.waitForIdle()
        compose.onNodeWithTag("member-permission-warning").assertIsDisplayed().assertTextContains(profileName, substring = true)
        assertTrue(UiDevice.getInstance(instrumentation).takeScreenshot(File(directory, "demo-member-visible.png")))
        File(directory, if (resume) "demo-member-restarted.json" else "demo-member-accepted.json").writeText(
            JSONObject().put("protected_reload_warning", true).put("actual_ui_warning", true)
                .put("profile_isolation", true).put("live_member_change", false).toString(),
        )
    }
}
