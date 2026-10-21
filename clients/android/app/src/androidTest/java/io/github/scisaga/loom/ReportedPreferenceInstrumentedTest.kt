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
import io.github.scisaga.loom.vpn.ConnectionPhase
import io.github.scisaga.loom.vpn.VpnRuntime
import java.io.File
import java.io.DataInputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory
import org.json.JSONObject
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
    fun servicePolicySettingsRemainSeparateFromRuntimeAndSurviveRestart() {
        val args = InstrumentationRegistry.getArguments()
        assumeTrue(args.getString("demoPolicyFixture") == "true")
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
        compose.onNodeWithTag("tab-configuration").performClick()
        click("refresh-config")
        val serviceID = "demo-service"
        val firstPolicy = "demo-policy"
        val secondPolicy = "demo-policy-fixed"
        await("per-Service policy choices must become visible") {
            routing.status(profile.id).value.services.singleOrNull { it.serviceID == serviceID }?.options?.size == 2
        }
        if (args.getString("demoPolicyResume") == "true") {
            assertEquals(secondPolicy, routing.status(profile.id).value.services.single { it.serviceID == serviceID }.policyID)
            report("restarted")
            return
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
        val fixture = JSONObject(File(directory, "demo-runtime.json").readText())
        val trusted = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null)
            File(directory, "demo-ca.pem").inputStream().use {
                setCertificateEntry("demo-ca", CertificateFactory.getInstance("X.509").generateCertificate(it))
            }
        }
        val managers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(trusted) }
        val tls = SSLContext.getInstance("TLS").apply { init(null, managers.trustManagers, null) }
        fun business() {
            val port = fixture.getInt("target_port")
            val transport = Socket().apply {
                soTimeout = 5_000
                connect(InetSocketAddress(fixture.getString("target_ip"), port), 5_000)
            }
            (tls.socketFactory.createSocket(transport, "demo.example", port, true) as SSLSocket).use {
                it.sslParameters = it.sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
                it.startHandshake()
                it.outputStream.write("GET /demo-policy-business HTTP/1.1\r\nHost: demo.example\r\nConnection: close\r\n\r\n".encodeToByteArray())
                assertTrue("selected Policy did not deliver actual HTTPS", it.inputStream.readBytes().decodeToString().contains("demo-android-business"))
            }
        }
        val domestic = Socket().apply {
            soTimeout = 3_000
            connect(InetSocketAddress(fixture.getString("domestic_ip"), fixture.getInt("domestic_port")), 5_000)
        }
        fun domesticStillConnected() {
            domestic.outputStream.write("demo".encodeToByteArray())
            val body = ByteArray(4)
            DataInputStream(domestic.inputStream).readFully(body)
            assertEquals("demo", body.decodeToString())
        }
        domesticStillConnected()
        compose.onNodeWithTag("tab-configuration").performClick()
        val otherChoices = routing.status(profile.id).value.services.filter { it.serviceID != serviceID }
        val otherPaths = routing.status(profile.id).value.currentPaths.filter { it.service != "service:$serviceID" }
        for (policy in listOf(firstPolicy, secondPolicy)) {
            click("service-policy-$serviceID-$policy")
            await("UI choice and affected selector must finish applying") {
                val status = routing.status(profile.id).value
                status.services.single { it.serviceID == serviceID }.policyID == policy && status.running &&
                    status.currentPaths.any { it.service == "service:$serviceID" }
            }
            assertEquals(otherChoices, routing.status(profile.id).value.services.filter { it.serviceID != serviceID })
            assertEquals(otherPaths.map { it.candidate }, routing.status(profile.id).value.currentPaths.filter { it.service != "service:$serviceID" }.map { it.candidate })
            domesticStillConnected()
            business()
            report(policy)
        }
        domestic.close()
        assertTrue(device.takeScreenshot(File(directory, "demo-preference-fixed.png")))
        compose.onNodeWithTag("tab-connection").performClick()
        click("connection-toggle")
        await("normal stop must complete") { VpnRuntime.status.value.phase == ConnectionPhase.DISCONNECTED }
        report("stopped")
    }
}
